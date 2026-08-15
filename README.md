# NetBox REST Attune Pack

This pack translates the MIT-licensed StackStorm Exchange NetBox pack at exact
revision `69cb91a8b55c791ebec189cd976170ce44206358` into nine curated Attune
actions backed by one shared HTTP client. It targets NetBox 4.x with a verified
NetBox 4.6.8 baseline. See [SOURCE.md](SOURCE.md) for source, release, license,
REST, and OpenAPI verification.

## Requirements

- Python 3.10 or newer on the selected Attune worker.
- HTTPS reachability from the worker to NetBox.
- A least-privilege NetBox v2 API token. Legacy v1 tokens remain usable for
  NetBox versions that still accept them.
- An encrypted pack-owned Attune Key, normally `netbox.credentials`.

There are no third-party Python dependencies and tests make no live requests.

## Credential Key

```json
{
  "base_url": "https://netbox.example.com",
  "token": "nbt_KEY.PLAINTEXT",
  "auth_scheme": "auto",
  "verify_tls": true
}
```

`base_url` is the NetBox deployment root, not `/api`. A deployment subpath is
valid, for example `https://example.com/netbox`. The client appends `/api`,
requires HTTPS, rejects URL credentials, query strings, fragments, redirects,
unsafe path segments, and `verify_tls: false`, and never accepts a target URL
from an action. For private PKI, add a PEM bundle as `ca_cert`; verification
remains enabled.

`auth_scheme: auto` uses `Bearer` for current `nbt_` v2 token plaintext and
`Token` for legacy v1 values. `bearer` or `token` can be selected explicitly.
Credential Key refs must begin `netbox.`. Tokens are never action parameters,
outputs, or errors.

Each request has a 1-120 second timeout, a 32 MiB response cap, and no automatic
retry. In particular, POST, PATCH, and DELETE are never blindly replayed.
Server error bodies, URLs, headers, and request bodies are omitted from errors;
sensitive-looking keys are recursively redacted from outputs.

## Actions

| Action | Purpose |
|---|---|
| `status` | Read `/api/status/` |
| `schema` | Read the target instance's `/api/schema/` OpenAPI JSON |
| `resource_list` | Filtered, bounded `limit`/`offset` list |
| `resource_get` | Detail GET by numeric ID, including ETag metadata |
| `resource_create` | Create one object |
| `resource_update` | PATCH one numeric ID with `If-Match` when available |
| `resource_delete` | Delete one verified ID/display pair after exact confirmation |
| `resource_upsert` | Explicit selector with zero-or-one enforcement |
| `allocate_available` | Atomic available-IP or available-prefix POST |

Every action receives a flat JSON object on stdin and returns:

```json
{
  "operation": "resource_get",
  "resource": "devices",
  "data": {"id": 42, "display": "edge-01"},
  "meta": {"http_status": 200, "etag": "W/\"...\"", "request_id": "..."}
}
```

## Curated Resources

The six resource operations use a fixed map, not caller-supplied paths:

| Area | Resource keys |
|---|---|
| Sites and tenancy | `regions`, `sites`, `tenants` |
| Racks | `racks` |
| Hardware and devices | `manufacturers`, `device_types`, `platforms`, `device_roles`, `devices` |
| Connectivity | `device_interfaces`, `cables` |
| IPAM | `prefixes`, `ip_addresses`, `vlans`, `vrfs` |
| Circuits | `providers`, `circuits`, `circuit_terminations` |
| Virtualization | `clusters`, `virtual_machines`, `vm_interfaces` |
| Extensibility and records | `tags`, `custom_fields`, `journal_entries` |

DCIM and virtual-machine interfaces have distinct keys to prevent wrong-model
operations. Get, update, and delete always use positive numeric NetBox IDs.
Related fields in bodies should also use numeric IDs rather than ambiguous name
objects. Journal entry bodies use NetBox's `assigned_object_type` plus numeric
`assigned_object_id` contract.

No generic endpoint action is included. This deliberately excludes arbitrary
URLs and broad roots such as users, plugins, scripts, event rules, and webhooks.
Adding a model requires a reviewed resource-map change and tests.

## Bodies and Custom Fields

Create and update accept one JSON object, never bulk arrays. Response-only
fields (`id`, URLs, display fields, and timestamps) are rejected from writes.
NetBox model fields otherwise pass through unchanged so installed minor-version
schemas remain authoritative. A supplied `custom_fields` value must remain an
object; the client does not flatten, merge, stringify, or reconstruct it.

Use `schema` or the instance Swagger UI to verify required and writable fields.
This matters for cables, generic terminations, custom field definitions, and
scope/assignment fields whose exact shape evolves across NetBox 4.x.

## Pagination and Selectors

`resource_list` URL-encodes filter names and scalar values. `limit` is 1-1,000,
`offset` is non-negative, and one page is returned by default. With
`all_pages: true`, the client advances offsets itself and ignores server-provided
next URLs, eliminating cross-host pagination redirects. It stops at
`max_total`, at most 10,000, and reports `count`, `total`, `pages`, and
`truncated`.

`resource_upsert.selector` must contain explicit NetBox filters. The action
requests at most two results and fails if the server count or returned results
show ambiguity. Zero matches causes POST with `create_body`; one match causes
PATCH by its returned numeric ID with `update_body`. Prefer unique slug, CIDR,
circuit ID, or properly scoped compound filters over a bare display name.

Upsert cannot make the list-then-create decision atomic. A competing creator
can win after selection; NetBox's conflict is returned as failure and the action
does not retry or switch to update. Callers should reconcile explicitly.

## Concurrency and Deletion

For update, pass the exact ETag returned by `resource_get` as `if_match`, or omit
it and the action performs a detail GET immediately before PATCH. On NetBox 4.6+
the PATCH includes `If-Match`; HTTP 412 is a failure and is never retried. On an
older 4.x server that does not advertise ETags, metadata reports
`server-does-not-advertise-etag` and PATCH follows that server's last-write-wins
behavior.

Deletion first reads the numeric ID and requires `expected_display` to match the
current object exactly. `confirm` must then be case-sensitive and exact:

```text
delete:<resource>:<object_id>:<expected_display>
```

Only then is the same resource path and ID deleted. NetBox 4.6 does not document
`If-Match` for DELETE, so the preflight ETag is reported but not sent. IDs and
displays protect against wrong-resource and mistyped-ID deletion; grant delete
permissions only where needed.

## IP Allocation Races

Do not list available addresses and then create one. `allocate_available` posts
directly to one of these server-side allocation routes:

```text
/api/ipam/prefixes/<parent_prefix_id>/available-ips/
/api/ipam/prefixes/<parent_prefix_id>/available-prefixes/
```

For `kind: ip`, `allocation` may be `{}` or contain writable IP address fields.
For `kind: prefix`, it must contain integer `prefix_length` and may contain other
writable prefix fields. NetBox 4.6.8 serializes competing allocations using an
advisory lock and database transaction. HTTP 409 means capacity/conflict and is
not retried. A network timeout after POST is outcome-ambiguous; reconcile by
querying NetBox before any new allocation attempt.

## Webhooks and Events

The upstream Flask sensor exposed an in-process listener and mapped incoming
event strings directly to StackStorm triggers. It is intentionally deferred.
This translation does not yet have a reviewed durable Attune event-rule mapping,
replay/deduplication store, authenticated ingress ownership model, or lifecycle
management for a secure listener. Configure neither NetBox webhooks nor event
rules through this pack. Poll explicit resources or journal entries until a
separate durable receiver design is implemented and threat-modeled.

## Validation

```bash
/usr/bin/python3 -m unittest discover -s /home/david/Codebase/attune-packs/netbox/tests -v
/home/david/.cargo/bin/attune --output json pack check /home/david/Codebase/attune-packs/netbox
/home/david/.cargo/bin/attune pack test /home/david/Codebase/attune-packs/netbox --detailed
```

Tests mock every HTTP and Attune Key interaction and use only the Python
standard library. Live verification remains deployment-specific because NetBox
plugins, permissions, custom fields, token restrictions, and private PKI alter
the effective contract.

## License

The verified upstream MIT text is included in [LICENSE](LICENSE). Attribution
and modification details are in [NOTICE](NOTICE).
