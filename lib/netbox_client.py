"""Safely scoped, standard-library client for the NetBox 4.x REST API."""

from __future__ import annotations

import json
import re
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, unquote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


DEFAULT_CREDENTIAL_KEY = "pack.netbox.credentials"
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_PAGE_SIZE = 1000
MAX_TOTAL_RESULTS = 10000
_SENSITIVE = re.compile(r"(?:password|secret|token|credential|private.?key|api.?key)", re.IGNORECASE)
_READ_ONLY_FIELDS = {"id", "url", "display_url", "display", "created", "last_updated"}

# Public action keys deliberately distinguish DCIM interfaces from VM interfaces.
RESOURCES = {
    "regions": ("dcim", "regions"),
    "sites": ("dcim", "sites"),
    "tenants": ("tenancy", "tenants"),
    "racks": ("dcim", "racks"),
    "manufacturers": ("dcim", "manufacturers"),
    "device_types": ("dcim", "device-types"),
    "platforms": ("dcim", "platforms"),
    "device_roles": ("dcim", "device-roles"),
    "devices": ("dcim", "devices"),
    "device_interfaces": ("dcim", "interfaces"),
    "cables": ("dcim", "cables"),
    "prefixes": ("ipam", "prefixes"),
    "ip_addresses": ("ipam", "ip-addresses"),
    "vlans": ("ipam", "vlans"),
    "vrfs": ("ipam", "vrfs"),
    "providers": ("circuits", "providers"),
    "circuits": ("circuits", "circuits"),
    "circuit_terminations": ("circuits", "circuit-terminations"),
    "clusters": ("virtualization", "clusters"),
    "virtual_machines": ("virtualization", "virtual-machines"),
    "vm_interfaces": ("virtualization", "interfaces"),
    "tags": ("extras", "tags"),
    "custom_fields": ("extras", "custom-fields"),
    "journal_entries": ("extras", "journal-entries"),
}
_API_ROOTS = {"status", "schema", *(root for root, _ in RESOURCES.values())}


class NetBoxPackError(Exception):
    """An action-safe error that excludes credentials, URLs, and response bodies."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _fetch_key(key_ref: str) -> Any:
    if not isinstance(key_ref, str) or not key_ref.startswith("pack.netbox.") or len(key_ref) > 255:
        raise NetBoxPackError("credential_key must be a pack-owned canonical pack.netbox.* Attune Key ref")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(key_ref, client=attune.context.client)
    except Exception as exc:
        raise NetBoxPackError(f"could not read Attune Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise NetBoxPackError("Attune Key was not found")
        raise NetBoxPackError(f"could not read Attune Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _credential(key_ref: str) -> dict[str, Any]:
    value = _fetch_key(key_ref)
    if not isinstance(value, dict):
        raise NetBoxPackError("NetBox credential Key must contain a JSON object")
    return value


def _nonempty(value: Any, name: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise NetBoxPackError(f"{name} must be a non-empty string of at most {maximum} characters")
    if any(ord(character) < 32 for character in value):
        raise NetBoxPackError(f"{name} contains a control character")
    return value


def _integer(params: dict[str, Any], name: str, default: int, minimum: int, maximum: int) -> int:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise NetBoxPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(params: dict[str, Any], name: str, default: bool = False) -> bool:
    value = params.get(name, default)
    if not isinstance(value, bool):
        raise NetBoxPackError(f"{name} must be a boolean")
    return value


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            # Preserve schema/container shape while redacting actual scalar or list values.
            key: "[REDACTED]" if _SENSITIVE.search(str(key)) and not isinstance(item, dict) else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _resource_path(resource: Any, object_id: Any | None = None) -> str:
    if resource not in RESOURCES:
        raise NetBoxPackError("resource is not in the curated NetBox resource allowlist")
    root, endpoint = RESOURCES[resource]
    path = f"/{root}/{endpoint}/"
    if object_id is not None:
        if isinstance(object_id, bool) or not isinstance(object_id, int) or object_id <= 0:
            raise NetBoxPackError("object_id must be a positive integer NetBox ID")
        path += f"{object_id}/"
    return path


def _body(params: dict[str, Any], name: str, *, allow_empty: bool = False) -> dict[str, Any]:
    value = params.get(name)
    if not isinstance(value, dict) or (not value and not allow_empty):
        qualifier = "an object" if allow_empty else "a non-empty object"
        raise NetBoxPackError(f"{name} must be {qualifier}")
    read_only = _READ_ONLY_FIELDS.intersection(value)
    if read_only:
        raise NetBoxPackError(f"{name} contains read-only fields: {', '.join(sorted(read_only))}")
    if "custom_fields" in value and not isinstance(value["custom_fields"], dict):
        raise NetBoxPackError(f"{name}.custom_fields must be an object")
    return dict(value)


def _filters(params: dict[str, Any], name: str = "filters") -> dict[str, Any]:
    value = params.get(name, {})
    if not isinstance(value, dict):
        raise NetBoxPackError(f"{name} must be an object")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key or len(key) > 100 or not re.fullmatch(r"[A-Za-z0-9_]+", key):
            raise NetBoxPackError(f"{name} contains an invalid filter name")
        if key in {"limit", "offset", "start"}:
            raise NetBoxPackError(f"{name} must not override pagination parameters")
        items = item if isinstance(item, list) else [item]
        if not items or len(items) > 100 or any(
            child is not None and (isinstance(child, (dict, list)) or not isinstance(child, (str, int, float, bool)))
            for child in items
        ):
            raise NetBoxPackError(f"{name}.{key} must be a scalar or a non-empty scalar array")
        result[key] = [str(child).lower() if isinstance(child, bool) else child for child in items] if isinstance(item, list) else (
            str(item).lower() if isinstance(item, bool) else item
        )
    return result


class NetBoxClient:
    """Direct HTTPS client with no redirects and no automatic retries."""

    def __init__(self, credential: dict[str, Any], timeout_seconds: int):
        base_url = credential.get("base_url")
        if not isinstance(base_url, str):
            raise NetBoxPackError("credential base_url must be a string")
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment
        ):
            raise NetBoxPackError("credential base_url must be HTTPS without credentials, query, or fragment")
        try:
            parsed.port
        except ValueError:
            raise NetBoxPackError("credential base_url has an invalid port") from None
        raw_parts = parsed.path.split("/")
        decoded_parts = [unquote(part) for part in raw_parts]
        if (
            any(part in {".", ".."} or "/" in part or "\\" in part for part in decoded_parts if part)
            or any(not part for part in raw_parts[1:-1])
            or (decoded_parts and decoded_parts[-1].lower() == "api")
        ):
            raise NetBoxPackError("credential base_url path is unsafe or already includes /api")

        token = _nonempty(credential.get("token"), "credential token", 8192)
        auth_scheme = credential.get("auth_scheme", "auto")
        if auth_scheme not in {"auto", "bearer", "token"}:
            raise NetBoxPackError("credential auth_scheme must be auto, bearer, or token")
        if auth_scheme == "auto":
            auth_scheme = "bearer" if token.startswith("nbt_") else "token"
        if credential.get("verify_tls", True) is not True:
            raise NetBoxPackError("credential verify_tls must be true")
        ca_cert = credential.get("ca_cert")
        if ca_cert is not None and (not isinstance(ca_cert, str) or not ca_cert.strip()):
            raise NetBoxPackError("credential ca_cert must be a non-empty PEM string")
        try:
            context = ssl.create_default_context(cadata=ca_cert) if ca_cert else ssl.create_default_context()
        except (ssl.SSLError, ValueError):
            raise NetBoxPackError("credential ca_cert is not a valid CA certificate") from None

        self.api_url = base_url.rstrip("/") + "/api"
        self.authorization = ("Bearer " if auth_scheme == "bearer" else "Token ") + token
        self.timeout_seconds = timeout_seconds
        self._opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))

    def _open(self, request: Request):
        return self._opener.open(request, timeout=self.timeout_seconds)

    @staticmethod
    def _validate_path(path: str) -> None:
        if not isinstance(path, str) or not path.startswith("/") or "?" in path or "#" in path or "\\" in path:
            raise NetBoxPackError("internal API path is invalid")
        parts = path.split("/")
        decoded = [unquote(part) for part in parts]
        if len(parts) < 2 or parts[1] not in _API_ROOTS or any(
            part in {".", ".."} or "/" in part or "\\" in part for part in decoded if part
        ):
            raise NetBoxPackError("internal API path is outside the fixed root allowlist")

    def _send(self, request: Request) -> tuple[int, dict[str, str], bytes]:
        try:
            with self._open(request) as response:
                content = response.read(MAX_RESPONSE_BYTES + 1)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise NetBoxPackError("NetBox response exceeded the 32 MiB action limit")
                return response.status, dict(response.headers.items()), content
        except HTTPError as exc:
            messages = {
                400: "NetBox rejected the request (HTTP 400)",
                401: "NetBox authentication failed (HTTP 401)",
                403: "NetBox authorization failed (HTTP 403)",
                404: "NetBox resource was not found (HTTP 404)",
                409: "NetBox resource conflict (HTTP 409)",
                412: "NetBox optimistic concurrency check failed (HTTP 412)",
                413: "NetBox rejected an oversized request (HTTP 413)",
                429: "NetBox rate limit was reached (HTTP 429)",
            }
            exc.close()
            raise NetBoxPackError(messages.get(exc.code, f"NetBox returned HTTP {exc.code}")) from None
        except (URLError, TimeoutError, OSError) as exc:
            raise NetBoxPackError(f"NetBox request failed ({type(exc).__name__})") from None

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: Any = None,
        if_match: str | None = None,
        expected: set[int] | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        if method not in {"GET", "POST", "PATCH", "DELETE"}:
            raise NetBoxPackError("internal HTTP method is not allowed")
        self._validate_path(path)
        url = self.api_url + path
        if query:
            url += "?" + urlencode(query, doseq=True)
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers = {"Accept": "application/json", "Authorization": self.authorization}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if if_match is not None:
            headers["If-Match"] = _nonempty(if_match, "if_match", 512)
        status, response_headers, content = self._send(Request(url, data=data, headers=headers, method=method))
        if status not in (expected or {200}):
            raise NetBoxPackError(f"NetBox returned unexpected HTTP {status}")
        lowered = {key.lower(): value for key, value in response_headers.items()}
        meta: dict[str, Any] = {"http_status": status}
        for source, target in (("etag", "etag"), ("x-request-id", "request_id"), ("api-version", "api_version")):
            if source in lowered:
                meta[target] = lowered[source]
        if not content:
            return {"success": True}, meta
        try:
            return _redact(json.loads(content)), meta
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise NetBoxPackError("NetBox returned invalid JSON") from None


def _list(
    client: NetBoxClient,
    resource: str,
    params: dict[str, Any],
    filters: dict[str, Any] | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    offset = _integer(params, "offset", 0, 0, 2**31 - 1)
    limit = _integer(params, "limit", 100, 1, MAX_PAGE_SIZE)
    all_pages = _boolean(params, "all_pages")
    max_total = _integer(params, "max_total", 1000, 1, MAX_TOTAL_RESULTS)
    items: list[Any] = []
    pages = 0
    server_count: int | None = None
    has_next = False
    meta: dict[str, Any] = {"http_status": 200}
    while True:
        remaining = max_total - len(items)
        page_limit = min(limit, remaining)
        query = dict(filters if filters is not None else _filters(params))
        query.update({"limit": page_limit, "offset": offset + len(items)})
        page, request_meta = client.request("GET", _resource_path(resource), query=query)
        if not isinstance(page, dict) or not isinstance(page.get("results"), list):
            raise NetBoxPackError("NetBox returned an unexpected paginated response")
        results = page["results"]
        if len(results) > page_limit:
            raise NetBoxPackError("NetBox returned more results than the requested limit")
        count = page.get("count")
        if count is not None and (isinstance(count, bool) or not isinstance(count, int) or count < 0):
            raise NetBoxPackError("NetBox returned an invalid pagination count")
        server_count = count if server_count is None else server_count
        has_next = page.get("next") is not None
        items.extend(results)
        pages += 1
        meta = request_meta
        if not all_pages or not has_next or len(items) >= max_total:
            break
        if not results:
            raise NetBoxPackError("NetBox pagination did not advance")
    return items, {
        **meta,
        "offset": offset,
        "count": len(items),
        "total": server_count,
        "pages": pages,
        "truncated": has_next and (not all_pages or len(items) >= max_total),
    }


def _detail_with_etag(client: NetBoxClient, resource: str, object_id: int) -> tuple[Any, dict[str, Any]]:
    return client.request("GET", _resource_path(resource, object_id))


def _update(
    client: NetBoxClient,
    resource: str,
    object_id: int,
    body: dict[str, Any],
    if_match: Any = None,
) -> tuple[Any, dict[str, Any]]:
    etag = if_match
    fetched = False
    if etag is None:
        _, detail_meta = _detail_with_etag(client, resource, object_id)
        etag = detail_meta.get("etag")
        fetched = True
    elif etag == "*":
        raise NetBoxPackError("if_match must be an exact ETag, not '*'")
    if etag is not None:
        etag = _nonempty(etag, "if_match", 512)
    data, meta = client.request(
        "PATCH", _resource_path(resource, object_id), body=body, if_match=etag, expected={200}
    )
    return data, {
        **meta,
        "object_id": object_id,
        "concurrency": "if-match" if etag else "server-does-not-advertise-etag",
        "etag_fetched": fetched,
    }


def _execute(client: NetBoxClient, operation: str, params: dict[str, Any]) -> tuple[Any, dict[str, Any], str | None]:
    if operation == "status":
        data, meta = client.request("GET", "/status/")
        return data, meta, None
    if operation == "schema":
        data, meta = client.request("GET", "/schema/")
        return data, meta, None
    if operation == "allocate_available":
        kind = params.get("kind")
        parent_id = params.get("parent_prefix_id")
        _resource_path("prefixes", parent_id)
        allocation = _body(params, "allocation", allow_empty=True)
        if kind == "ip":
            allocation_path = f"/ipam/prefixes/{parent_id}/available-ips/"
        elif kind == "prefix":
            prefix_length = allocation.get("prefix_length")
            if isinstance(prefix_length, bool) or not isinstance(prefix_length, int) or not 0 <= prefix_length <= 128:
                raise NetBoxPackError("prefix allocation requires integer allocation.prefix_length from 0 to 128")
            allocation_path = f"/ipam/prefixes/{parent_id}/available-prefixes/"
        else:
            raise NetBoxPackError("kind must be ip or prefix")
        data, meta = client.request("POST", allocation_path, body=allocation, expected={201})
        return data, {**meta, "parent_prefix_id": parent_id, "atomic_server_allocation": True}, "prefixes"

    resource = params.get("resource")
    path = _resource_path(resource)
    if operation == "resource_list":
        data, meta = _list(client, resource, params)
        return data, meta, resource
    if operation == "resource_get":
        object_id = params.get("object_id")
        data, meta = _detail_with_etag(client, resource, object_id)
        return data, {**meta, "object_id": object_id}, resource
    if operation == "resource_create":
        data, meta = client.request("POST", path, body=_body(params, "body"), expected={201})
        return data, meta, resource
    if operation == "resource_update":
        object_id = params.get("object_id")
        data, meta = _update(client, resource, object_id, _body(params, "body"), params.get("if_match"))
        return data, meta, resource
    if operation == "resource_delete":
        object_id = params.get("object_id")
        current, get_meta = _detail_with_etag(client, resource, object_id)
        if not isinstance(current, dict) or not isinstance(current.get("display"), str):
            raise NetBoxPackError("NetBox detail response lacks the display identity required for deletion")
        expected_display = _nonempty(params.get("expected_display"), "expected_display")
        if current["display"] != expected_display:
            raise NetBoxPackError("expected_display does not match the current NetBox object")
        expected = f"delete:{resource}:{object_id}:{expected_display}"
        if params.get("confirm") != expected:
            raise NetBoxPackError("destructive operation confirmation does not match the verified object")
        _, delete_meta = client.request("DELETE", _resource_path(resource, object_id), expected={204})
        return {
            "deleted": True,
            "object_id": object_id,
            "display": expected_display,
        }, {**delete_meta, "verified_etag": get_meta.get("etag")}, resource
    if operation == "resource_upsert":
        selector = _filters(params, "selector")
        if not selector:
            raise NetBoxPackError("selector must contain at least one explicit NetBox filter")
        selected, select_meta = _list(client, resource, {
            "offset": 0, "limit": 2, "all_pages": False, "max_total": 2
        }, selector)
        total = select_meta.get("total")
        if len(selected) > 1 or (isinstance(total, int) and total > 1):
            raise NetBoxPackError("upsert selector is ambiguous; it matched more than one object")
        if not selected:
            data, meta = client.request("POST", path, body=_body(params, "create_body"), expected={201})
            return data, {**meta, "created": True, "selector": selector}, resource
        object_id = selected[0].get("id") if isinstance(selected[0], dict) else None
        _resource_path(resource, object_id)
        data, meta = _update(client, resource, object_id, _body(params, "update_body"))
        return data, {**meta, "created": False, "selector": selector}, resource
    raise NetBoxPackError("unsupported NetBox action")


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    timeout = _integer(params, "timeout_seconds", 30, 1, 120)
    credential_key = params.get("credential_key", DEFAULT_CREDENTIAL_KEY)
    client = NetBoxClient(_credential(credential_key), timeout)
    data, meta, resource = _execute(client, operation, params)
    return {"operation": operation, "resource": resource, "data": _redact(data), "meta": meta}
