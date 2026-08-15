from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import netbox_client as client  # noqa: E402


class Response:
    def __init__(self, value=None, status=200, headers=None):
        self.status = status
        self.headers = headers or {}
        self.content = b"" if value is None else json.dumps(value).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        return self.content[:limit]


def credential(**changes):
    value = {
        "base_url": "https://netbox.example.invalid/nb",
        "token": "nbt_KEY.TOP-SECRET-TOKEN",
        "auth_scheme": "auto",
        "verify_tls": True,
    }
    value.update(changes)
    return value


def netbox(**changes):
    return client.NetBoxClient(credential(**changes), 15)


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_curated_action_inventory(self):
        self.assertEqual(
            {
                "status", "schema", "resource_list", "resource_get", "resource_create",
                "resource_update", "resource_delete", "resource_upsert", "allocate_available",
            },
            set(self.actions),
        )

    def test_actions_are_flat_stdin_json_with_structured_output(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                for field, value in {
                    "ref": f"netbox.{name}",
                    "runner_type": "python",
                    "runtime_version": '\">=3.10\"',
                    "entry_point": "netbox_action.py",
                    "parameter_delivery": "stdin",
                    "parameter_format": "json",
                    "output_format": "json",
                }.items():
                    self.assertRegex(text, rf"(?m)^{field}: {value}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(text, r"credential_key: \{[^\n]*default: netbox\.credentials")
                for field in ("operation", "resource", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {field}: \{{type:")
                self.assertNotRegex(text, r"(?m)^  (?:token|api_token|url|endpoint|method):")

    def test_resource_surface_is_fixed_and_interfaces_are_unambiguous(self):
        expected = {
            "regions", "sites", "tenants", "racks", "manufacturers", "device_types",
            "platforms", "device_roles", "devices", "device_interfaces", "cables",
            "prefixes", "ip_addresses", "vlans", "vrfs", "providers", "circuits",
            "circuit_terminations", "clusters", "virtual_machines", "vm_interfaces",
            "tags", "custom_fields", "journal_entries",
        }
        self.assertEqual(expected, set(client.RESOURCES))
        self.assertEqual(("dcim", "interfaces"), client.RESOURCES["device_interfaces"])
        self.assertEqual(("virtualization", "interfaces"), client.RESOURCES["vm_interfaces"])
        for name in (
            "resource_list", "resource_get", "resource_create", "resource_update",
            "resource_delete", "resource_upsert",
        ):
            for resource in expected:
                self.assertIn(resource, self.actions[name])
        self.assertNotIn("generic", self.actions)

    def test_destructive_contract_and_allocation_contract_are_explicit(self):
        delete = self.actions["resource_delete"]
        self.assertRegex(delete, r"(?m)^  expected_display: \{type: string, required: true")
        self.assertRegex(delete, r"(?m)^  confirm: \{type: string, required: true")
        allocation = self.actions["allocate_available"]
        self.assertIn("enum: [ip, prefix]", allocation)
        self.assertIn("parent_prefix_id", allocation)

    def test_source_license_notice_and_api_metadata(self):
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        source = (ROOT / "SOURCE.md").read_text(encoding="utf-8")
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn('source_revision: "69cb91a8b55c791ebec189cd976170ce44206358"', pack)
        self.assertIn('api_revision: "3db98de783c02038775b78f9804a95681f78eb7b"', pack)
        self.assertIn('api_baseline: "NetBox 4.6.8"', pack)
        self.assertIn('license: "MIT"', pack)
        self.assertIn("v4.6.8", source)
        self.assertIn("69cb91a8b55c791ebec189cd976170ce44206358", notice)
        self.assertIn("MIT License", (ROOT / "LICENSE").read_text(encoding="utf-8"))

    def test_no_undeclared_runtime_dependency_or_webhook_listener(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        implementation = (ROOT / "lib" / "netbox_client.py").read_text(encoding="utf-8")
        self.assertNotIn("requests", requirements)
        self.assertNotIn("pynetbox", requirements)
        self.assertNotIn("flask", requirements)
        self.assertFalse((ROOT / "sensors").exists())
        self.assertNotIn("requests", implementation)


class ValidationTests(unittest.TestCase):
    def test_credentials_require_https_verification_and_safe_root(self):
        bad = [
            credential(base_url="http://netbox.invalid"),
            credential(base_url="https://user:secret@netbox.invalid"),
            credential(base_url="https://netbox.invalid/base/%2e%2e/escape"),
            credential(base_url="https://netbox.invalid/base//escape"),
            credential(base_url="https://netbox.invalid/api"),
            credential(base_url="https://netbox.invalid?next=https://evil.invalid"),
            credential(verify_tls=False),
            credential(token=""),
            credential(auth_scheme="basic"),
        ]
        for settings in bad:
            with self.subTest(settings=settings), self.assertRaises(client.NetBoxPackError):
                client.NetBoxClient(settings, 15)

    def test_pack_owned_key_refs_are_required_before_sdk_access(self):
        for key_ref in ("credentials", "other.netbox", "", 4):
            with self.subTest(key_ref=key_ref), mock.patch.dict(sys.modules, {"attune": mock.Mock()}):
                with self.assertRaisesRegex(client.NetBoxPackError, "pack-owned"):
                    client._fetch_key(key_ref)

    def test_custom_ca_is_loaded_without_disabling_verification(self):
        context = object()
        with mock.patch("ssl.create_default_context", return_value=context) as create, mock.patch(
            "lib.netbox_client.HTTPSHandler"
        ) as handler:
            netbox(ca_cert="CA PEM")
        create.assert_called_once_with(cadata="CA PEM")
        handler.assert_called_once_with(context=context)

    def test_internal_request_rejects_arbitrary_urls_and_non_allowlisted_roots(self):
        nb = netbox()
        nb.authorization = "Bearer REDACTED"
        for path in (
            "https://evil.invalid/api/dcim/sites/", "//evil.invalid/path", "/users/tokens/",
            "/plugins/example/", "/dcim/../users/", "/dcim/sites/?next=x",
        ):
            with self.subTest(path=path), self.assertRaises(client.NetBoxPackError):
                nb.request("GET", path)
        with self.assertRaises(client.NetBoxPackError):
            nb.request("PUT", "/dcim/sites/1/")

    def test_resource_paths_use_numeric_ids_and_never_names(self):
        self.assertEqual("/dcim/devices/42/", client._resource_path("devices", 42))
        self.assertEqual("/circuits/circuit-terminations/7/", client._resource_path("circuit_terminations", 7))
        for value in ("router-1", 0, -1, True):
            with self.subTest(value=value), self.assertRaises(client.NetBoxPackError):
                client._resource_path("devices", value)
        with self.assertRaises(client.NetBoxPackError):
            client._resource_path("users", 1)

    def test_write_body_preserves_custom_field_shape_and_rejects_response_fields(self):
        body = {
            "name": "edge-01",
            "custom_fields": {
                "number": 7,
                "flags": ["a", "b"],
                "nested": {"enabled": True},
                "nullable": None,
            },
        }
        result = client._body({"body": body}, "body")
        self.assertEqual(body, result)
        self.assertIsNot(body, result)
        with self.assertRaisesRegex(client.NetBoxPackError, "custom_fields"):
            client._body({"body": {"custom_fields": "flattened"}}, "body")
        with self.assertRaisesRegex(client.NetBoxPackError, "read-only"):
            client._body({"body": {"id": 4, "name": "x"}}, "body")

    def test_filters_are_encoded_scalars_and_cannot_override_pagination(self):
        parsed = client._filters({"filters": {"name": "edge / one", "site_id": [1, 2], "enabled": True}})
        self.assertEqual({"name": "edge / one", "site_id": [1, 2], "enabled": "true"}, parsed)
        for filters in ({"limit": 0}, {"name__x;drop": "x"}, {"name": {"nested": 1}}, {"name": []}):
            with self.subTest(filters=filters), self.assertRaises(client.NetBoxPackError):
                client._filters({"filters": filters})


class ClientTests(unittest.TestCase):
    def test_v2_token_uses_bearer_url_encoding_and_structured_headers(self):
        nb = netbox()
        page = {"count": 1, "next": None, "previous": None, "results": [{"id": 1}]}
        with mock.patch.object(nb, "_open", return_value=Response(
            page,
            headers={"API-Version": "4.6", "X-Request-ID": "request-1"},
        )) as opened:
            data, meta = nb.request(
                "GET", "/dcim/sites/", query={"name": "edge / one", "tag": ["a", "b"]}
            )
        request = opened.call_args.args[0]
        query = parse_qs(urlsplit(request.full_url).query)
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(["edge / one"], query["name"])
        self.assertEqual(["a", "b"], query["tag"])
        self.assertEqual("Bearer nbt_KEY.TOP-SECRET-TOKEN", headers["authorization"])
        self.assertEqual(page, data)
        self.assertEqual("4.6", meta["api_version"])
        self.assertEqual("request-1", meta["request_id"])

    def test_legacy_token_scheme_is_explicit_and_no_retry_occurs(self):
        nb = netbox(token="legacy-secret")
        error = HTTPError("https://redacted.invalid", 429, "TOP-SECRET", {}, io.BytesIO(b"TOKEN-BODY"))
        with mock.patch.object(nb, "_open", side_effect=error) as opened:
            with self.assertRaisesRegex(client.NetBoxPackError, "rate limit") as caught:
                nb.request("POST", "/dcim/sites/", body={"name": "site"}, expected={201})
        error.close()
        self.assertEqual(1, opened.call_count)
        self.assertNotIn("TOP-SECRET", str(caught.exception))
        self.assertNotIn("TOKEN-BODY", str(caught.exception))

    def test_response_keys_are_redacted_without_flattening_custom_fields(self):
        nb = netbox()
        value = {"custom_fields": {"api_token": "SECRET", "nested": {"number": 4}}, "name": "site"}
        with mock.patch.object(nb, "_open", return_value=Response(value)):
            data, _ = nb.request("GET", "/dcim/sites/1/")
        self.assertEqual("[REDACTED]", data["custom_fields"]["api_token"])
        self.assertEqual({"number": 4}, data["custom_fields"]["nested"])

    def test_redaction_preserves_sensitive_named_openapi_schema_objects(self):
        schema = {
            "properties": {
                "token": {"type": "string", "description": "API token input"},
                "password": {"type": "string", "writeOnly": True},
            }
        }
        self.assertEqual(schema, client._redact(schema))
        self.assertEqual("[REDACTED]", client._redact({"token": "actual-secret"})["token"])

    def test_list_pagination_is_bounded_and_advances_offsets_without_following_next_url(self):
        nb = netbox()
        pages = [
            ({"count": 3, "next": "https://evil.invalid/steal", "previous": None, "results": [{"id": 1}, {"id": 2}]}, {"http_status": 200}),
            ({"count": 3, "next": None, "previous": "ignored", "results": [{"id": 3}]}, {"http_status": 200}),
        ]
        with mock.patch.object(nb, "request", side_effect=pages) as request:
            data, meta = client._list(nb, "devices", {
                "filters": {"site_id": 9}, "limit": 2, "offset": 5,
                "all_pages": True, "max_total": 10,
            })
        self.assertEqual([1, 2, 3], [item["id"] for item in data])
        self.assertEqual([5, 7], [call.kwargs["query"]["offset"] for call in request.call_args_list])
        self.assertTrue(all(call.args[1] == "/dcim/devices/" for call in request.call_args_list))
        self.assertEqual(2, meta["pages"])
        self.assertFalse(meta["truncated"])

    def test_one_page_and_max_total_report_truncation(self):
        nb = netbox()
        page = ({"count": 50, "next": "ignored", "previous": None, "results": [{"id": 1}]}, {"http_status": 200})
        with mock.patch.object(nb, "request", return_value=page):
            _, one = client._list(nb, "sites", {"limit": 1, "all_pages": False})
            _, capped = client._list(nb, "sites", {"limit": 1, "all_pages": True, "max_total": 1})
        self.assertTrue(one["truncated"])
        self.assertTrue(capped["truncated"])

    def test_update_fetches_etag_and_sends_if_match_without_retry(self):
        nb = netbox()
        responses = [
            ({"id": 4, "display": "edge-01"}, {"http_status": 200, "etag": 'W/"old"'}),
            ({"id": 4, "display": "edge-01"}, {"http_status": 200, "etag": 'W/"new"'}),
        ]
        with mock.patch.object(nb, "request", side_effect=responses) as request:
            data, meta = client._update(nb, "devices", 4, {"status": "offline"})
        self.assertEqual(4, data["id"])
        self.assertEqual(["GET", "PATCH"], [call.args[0] for call in request.call_args_list])
        self.assertEqual('W/"old"', request.call_args_list[1].kwargs["if_match"])
        self.assertEqual("if-match", meta["concurrency"])
        self.assertTrue(meta["etag_fetched"])
        with self.assertRaisesRegex(client.NetBoxPackError, r"not '\*'"):
            client._update(nb, "devices", 4, {"status": "active"}, "*")

    def test_update_reports_older_server_without_etag(self):
        nb = netbox()
        responses = [
            ({"id": 4}, {"http_status": 200}),
            ({"id": 4}, {"http_status": 200}),
        ]
        with mock.patch.object(nb, "request", side_effect=responses) as request:
            _, meta = client._update(nb, "devices", 4, {"status": "offline"})
        self.assertIsNone(request.call_args_list[1].kwargs["if_match"])
        self.assertEqual("server-does-not-advertise-etag", meta["concurrency"])

    def test_delete_binds_resource_id_display_and_checks_before_delete(self):
        nb = netbox()
        params = {
            "resource": "devices", "object_id": 42, "expected_display": "edge-01",
            "confirm": "delete:devices:42:edge-01",
        }
        with mock.patch.object(nb, "request", side_effect=[
            ({"id": 42, "display": "edge-01"}, {"http_status": 200, "etag": 'W/"x"'}),
            ({"success": True}, {"http_status": 204}),
        ]) as request:
            data, meta, resource = client._execute(nb, "resource_delete", params)
        self.assertEqual({"deleted": True, "object_id": 42, "display": "edge-01"}, data)
        self.assertEqual("devices", resource)
        self.assertEqual('W/"x"', meta["verified_etag"])
        self.assertEqual("/dcim/devices/42/", request.call_args_list[1].args[1])
        self.assertEqual("DELETE", request.call_args_list[1].args[0])

    def test_wrong_object_or_confirmation_never_reaches_delete(self):
        nb = netbox()
        base = {"resource": "devices", "object_id": 42, "expected_display": "edge-01"}
        cases = [
            ({**base, "confirm": "delete:devices:42:edge-01"}, "different-device"),
            ({**base, "confirm": "delete:sites:42:edge-01"}, "edge-01"),
        ]
        for params, actual in cases:
            with self.subTest(params=params), mock.patch.object(
                nb, "request", return_value=({"id": 42, "display": actual}, {"http_status": 200})
            ) as request, self.assertRaises(client.NetBoxPackError):
                client._execute(nb, "resource_delete", params)
            self.assertEqual(1, request.call_count)

    def test_delete_confirmation_error_does_not_echo_server_display(self):
        nb = netbox()
        display = "SERVER-DERIVED-DO-NOT-ECHO"
        with mock.patch.object(
            nb, "request", return_value=({"id": 42, "display": display}, {"http_status": 200})
        ) as request:
            with self.assertRaises(client.NetBoxPackError) as caught:
                client._execute(nb, "resource_delete", {
                    "resource": "devices", "object_id": 42, "expected_display": display,
                    "confirm": "wrong",
                })
        self.assertNotIn(display, str(caught.exception))
        self.assertEqual(1, request.call_count)

    def test_upsert_rejects_ambiguous_selectors_before_mutation(self):
        nb = netbox()
        page = ({
            "count": 2, "next": None, "previous": None,
            "results": [{"id": 1}, {"id": 2}],
        }, {"http_status": 200})
        with mock.patch.object(nb, "request", return_value=page) as request:
            with self.assertRaisesRegex(client.NetBoxPackError, "ambiguous"):
                client._execute(nb, "resource_upsert", {
                    "resource": "devices", "selector": {"name": "edge"},
                    "create_body": {"name": "edge"}, "update_body": {"status": "active"},
                })
        self.assertEqual(1, request.call_count)

    def test_upsert_create_conflict_is_not_retried_as_update(self):
        nb = netbox()
        empty = ({"count": 0, "next": None, "previous": None, "results": []}, {"http_status": 200})
        with mock.patch.object(nb, "request", side_effect=[empty, client.NetBoxPackError("conflict")]) as request:
            with self.assertRaisesRegex(client.NetBoxPackError, "conflict"):
                client._execute(nb, "resource_upsert", {
                    "resource": "sites", "selector": {"slug": "nyc"},
                    "create_body": {"name": "NYC", "slug": "nyc"},
                    "update_body": {"status": "active"},
                })
        self.assertEqual(2, request.call_count)
        self.assertEqual("POST", request.call_args_list[1].args[0])

    def test_upsert_existing_uses_returned_numeric_id_and_etag(self):
        nb = netbox()
        responses = [
            ({"count": 1, "next": None, "previous": None, "results": [{"id": 8}]}, {"http_status": 200}),
            ({"id": 8}, {"http_status": 200, "etag": 'W/"current"'}),
            ({"id": 8, "status": {"value": "active"}}, {"http_status": 200}),
        ]
        with mock.patch.object(nb, "request", side_effect=responses) as request:
            data, meta, _ = client._execute(nb, "resource_upsert", {
                "resource": "sites", "selector": {"slug": "nyc"},
                "create_body": {"name": "NYC", "slug": "nyc"},
                "update_body": {"status": "active"},
            })
        self.assertEqual(8, data["id"])
        self.assertFalse(meta["created"])
        self.assertEqual("/dcim/sites/8/", request.call_args_list[2].args[1])
        self.assertEqual('W/"current"', request.call_args_list[2].kwargs["if_match"])

    def test_available_allocation_posts_directly_to_server_atomic_route(self):
        nb = netbox()
        with mock.patch.object(
            nb, "request", return_value=({"id": 90, "prefix": "192.0.2.0/28"}, {"http_status": 201})
        ) as request:
            data, meta, resource = client._execute(nb, "allocate_available", {
                "kind": "prefix", "parent_prefix_id": 12,
                "allocation": {"prefix_length": 28, "description": "edge"},
            })
        self.assertEqual(90, data["id"])
        self.assertTrue(meta["atomic_server_allocation"])
        self.assertEqual("prefixes", resource)
        self.assertEqual("POST", request.call_args.args[0])
        self.assertEqual("/ipam/prefixes/12/available-prefixes/", request.call_args.args[1])
        self.assertEqual(1, request.call_count)
        with self.assertRaisesRegex(client.NetBoxPackError, "prefix_length"):
            client._execute(nb, "allocate_available", {
                "kind": "prefix", "parent_prefix_id": 12, "allocation": {},
            })

    def test_create_serializes_custom_fields_without_shape_loss(self):
        nb = netbox()
        body = {"name": "edge", "custom_fields": {"nested": {"x": [1, 2]}, "flag": False}}
        with mock.patch.object(nb, "_open", return_value=Response({"id": 1}, 201)) as opened:
            nb.request("POST", "/dcim/devices/", body=body, expected={201})
        self.assertEqual(body, json.loads(opened.call_args.args[0].data))


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("netbox_action_test", ROOT / "actions" / "netbox_action.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_invalid_input_and_unknown_errors_do_not_echo_secrets(self):
        cases = [
            ("[]", None),
            ('{"body":{"token":"DO-NOT-ECHO"}}', RuntimeError("DO-NOT-ECHO")),
        ]
        for raw, error in cases:
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = mock.patch.object(self.module, "execute_action", side_effect=error) if error else mock.patch.object(
                self.module, "execute_action"
            )
            with patch_execute, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "netbox.resource_get"}), mock.patch(
                "sys.stdin", io.StringIO(raw)
            ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                self.assertEqual(1, self.module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
