# Source and API Baseline

## Upstream Pack

- Repository: https://github.com/StackStorm-Exchange/stackstorm-netbox
- Verified revision: `69cb91a8b55c791ebec189cd976170ce44206358`
- Revision date: 2025-06-23
- Exact tag and pack version at revision: `v3.4.4` / `3.4.4`
- License: MIT, verified from the upstream `LICENSE` file
- Upstream API generation baseline: NetBox 4.3

The upstream revision contains hundreds of generated per-route actions, one
shared permissive request runner, StackStorm KV support, and an in-process Flask
webhook sensor. This pack preserves attribution and operational intent, not the
generated implementation.

## Current NetBox Baseline

- Release verified 2026-08-15: NetBox `v4.6.8`, published 2026-08-11
- Release: https://github.com/netbox-community/netbox/releases/tag/v4.6.8
- Verified source revision: `3db98de783c02038775b78f9804a95681f78eb7b`
- REST documentation:
  https://netboxlabs.com/docs/netbox/en/stable/integrations/rest-api/
- Per-instance OpenAPI JSON: `https://<netbox>/api/schema/`
- Interactive schema: `https://<netbox>/api/schema/swagger-ui/`

Endpoint registration and behavior were checked against the tagged 4.6.8
source. The selected model routes are registered under `/api/dcim/`,
`/api/tenancy/`, `/api/ipam/`, `/api/circuits/`, `/api/virtualization/`, and
`/api/extras/`. List views return `count`, `next`, `previous`, and `results` and
accept `limit`/`offset`. Detail objects use numeric primary keys and require a
trailing slash.

NetBox 4.6 adds weak ETags to individual detail GET/POST/PATCH/PUT responses.
`If-Match` on PATCH/PUT is checked again under a row lock and stale values return
HTTP 412. NetBox 4.6.8's available-IP and available-prefix POST views acquire a
server advisory lock, calculate availability under that lock, and save in a
database transaction; insufficient capacity returns HTTP 409. The allocation
action uses those POST routes directly and never performs a preview-then-create
sequence.

The `schema` action reads each target instance's own OpenAPI document because
plugins and installed NetBox minor releases can alter that document. This pack
does not cache or claim that one static schema represents every deployment.
