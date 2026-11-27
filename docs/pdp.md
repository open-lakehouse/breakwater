# The policy decision point (`olai-pdp`)

`crates/pdp` is a Cedar policy decision point (PDP) that services call over
olai-auth's wire API (`olai_auth::wire`). A service holds an
`olai_auth::HttpAuthorizer` pointed at the PDP. The PDP evaluates
`olai_auth::CedarAuthorizer` over its policies and entities loaded from Postgres,
and answers.

This is request-level authorization ("may this principal call this API on this
securable"). It is separate from the DataFusion session policies of
`datafusion-policy*`, which rewrite queries.

## Running it

The binary (`cargo run -p olai-pdp --features bin -- <command>`) and the image
(`ghcr.io/open-lakehouse/pdp`) have four commands:

| Command | |
|---|---|
| `pdp serve` | Serve on `PDP_HOST:PDP_PORT` (default `0.0.0.0:8080`). It never migrates. |
| `pdp migrate` | Apply olai-auth's `authz` migrations. Use a direct connection, because the migrator holds an advisory lock. |
| `pdp check` | Validate the policies without a database, and print the schema's actions. |
| `pdp healthcheck` | Exit 0 if the local server answers `GET /health` (the image's `HEALTHCHECK`). |

```bash
docker build -f crates/pdp/Dockerfile -t pdp .
docker run --rm -e DATABASE_URL=postgres://… pdp migrate
docker run -p 8080:8080 \
  -e DATABASE_URL=postgres://… \
  -e PDP_CALLERS=UNITYCATALOG=UnityCatalog \
  -e AUTHZ_TOKEN_UNITYCATALOG=… \
  -e PDP_POLICY_DIRS=/etc/pdp/policies -v ./policies:/etc/pdp/policies:ro \
  pdp
```

## Configuration

Everything comes from the environment (`Config::from_env`). An embedding host
can also build a `Config` itself. An empty variable counts as unset.

| Variable | Default | |
|---|---|---|
| `PDP_DATABASE_URL`, else `DATABASE_URL` | required | The Postgres holding `authz` (and `neon_auth`) |
| `PDP_POLICY_DIRS` | none | `:`-separated directories of `*.cedarschema` and `*.cedar` files, read in file name order |
| `PDP_BUILTIN_POLICIES` | `true` | Include the built-in `Lakehouse` schema and baseline |
| `PDP_CALLERS` | none | `NAME=Namespace,…`: who may call, and about which namespace |
| `PDP_TRUSTED_CALLER` | none | `NAME`: the caller of the trusted listener, which takes no credential (see [Caller auth](#caller-auth)) |
| `PDP_TRUSTED_HOST`, `PDP_TRUSTED_PORT` | `127.0.0.1`, none | The trusted listener's address. The port is required with `PDP_TRUSTED_CALLER` |
| `PDP_TOKEN_PREFIX` | `AUTHZ_TOKEN_` | Caller `NAME`'s secret is `<prefix><NAME>` |
| `AUTHZ_ENTITY_TTL_MS` | `2000` | How long groups and grants are reused (`0`: never) |
| `PDP_NEON_AUTH` | `false` | Load users from Neon Auth's `neon_auth."user"` |
| `PDP_HOST`, `PDP_PORT` | `0.0.0.0`, `8080` | `pdp serve`'s address |
| `RUST_LOG` | `olai_pdp=info,olai_auth=info` | Decisions are logged at target `olai_pdp::decision` |

Callers are compared by the SHA-256 of their secret, in constant time. A
configured caller without a secret can't call. A variable carrying the prefix
that names no caller is logged and ignored.

## Policies

The schema is every fragment composed namespace by namespace
(`olai_auth::compose_schema`), so a namespace can span several files. The
policies are every `*.cedar` file. Both are validated in strict mode at start,
so a policy that doesn't validate never serves.

The built-in sources (`crates/pdp/policies/`) come first:

- `Lakehouse.cedarschema`: the principals the loader builds. These are
  `Lakehouse::User` (`neon_role`, `banned`, `email_verified`, in `Group`s and a
  `Role`), `Lakehouse::ServiceAccount` (`name`, `disabled`, in `Group`s),
  `Lakehouse::Group` and `Lakehouse::Role`.
- `baseline.cedar`: `banned` forbids a banned user, and `disabled` forbids a
  disabled service account, in every namespace.

Each service contributes its own namespace's fragment (its resources and
actions) and the deployment's policies over it. For example, mangrove's
`UnityCatalog` fragments and luminescent-lakehouse's `unitycatalog.cedar`.

## Entities

`loader::PgEntityLoader` builds each request's entities from Postgres, under a
1.5 s deadline. That is well under a caller's 2 s timeout. Any error is a deny.

- **The principal** is never cached, so a ban or a disabled account counts from
  the next request.
  - A `Lakehouse::ServiceAccount` comes from `authz.service_accounts`.
  - A `Lakehouse::User` comes from `neon_auth."user"` with `PDP_NEON_AUTH`. Its
    role is a `Lakehouse::Role` parent, and an expired ban isn't a ban. Without
    `PDP_NEON_AUTH`, a user is a deny. Another user source plugs in at olai-auth's
    `PrincipalAttrs`.
- **Its groups** come from `authz.memberships`, transitively, as
  `Lakehouse::Group` parents.
- **Its grants** are set as `privileges` (held on the entity) and
  `inherited_privileges` (held on it or an ancestor) on the resource and on each
  ancestor the caller sends in `entities`. A caller can't set those two
  attributes itself, so it can't forge grants. Groups and grants are cached for
  `AUTHZ_ENTITY_TTL_MS`.

The PDP reads only what olai-auth's `authz_reader` role may read.

## The OPA route

Unity Catalog's OPA authorizers can use the PDP as their OPA server. That is UC
Java 0.8 (`server.authorization.provider=opa`) and unitycatalog-rs
(`auth.engine=opa`). Both send one leaf privilege check per request, and both
read only `result.allow`:

```json
{"input": {
  "principal": {"id": "…", "email": "alice@example.com", "external_id": "…"},
  "privilege": "SELECT",
  "resource": {"id": "…", "type": "TABLE", "name": "orders", "parents": [
    {"id": "…", "type": "SCHEMA", "name": "reports"},
    {"id": "…", "type": "CATALOG", "name": "analytics"}
  ]},
  "context": {"source_ip": "10.1.2.3"}
}}
```

The answer is `{"result":{"allow":true}}`. Always a 200, even a deny. A body
without an `input` is a 400, which UC turns into a 503.

`POST /v1/data/{package}` takes the caller's bearer secret, as unitycatalog-rs
sends it from `opa_token_file`. The package (`uc/authz`) is logged and nothing
else. The caller's namespace decides, as on `/v1/authorize`, so a client can't
pick the namespace it asks about.

### Caller auth

UC Java 0.8 sends no credential to OPA: no `Authorization` header, no client
certificate, and its URL validator refuses userinfo. The PDP therefore trusts
the network path instead. A **trusted listener** serves only `GET /health` and
`POST /v1/data/{package}`, takes no credential, and decides every request as
one caller:

```bash
PDP_CALLERS=UCJAVA=UnityCatalogOpa,UCRS=UnityCatalogOpa
PDP_TRUSTED_CALLER=UCJAVA          # needs no secret
PDP_TRUSTED_PORT=8181              # PDP_TRUSTED_HOST defaults to 127.0.0.1
AUTHZ_TOKEN_UCRS=…                 # bearer callers stay on PDP_PORT
```

```properties
server.authorization.provider=opa
server.authorization.opa.decision-url=http://pdp:8181/v1/data/uc/authz
```

On this listener the network is the authentication. Serve it only where
nothing but UC can reach it:

- a sidecar on localhost (the default host);
- a compose network shared only with UC; or
- a k8s `NetworkPolicy` that admits only UC's pods.

For the last two, set `PDP_TRUSTED_HOST` to the private address (in a
container, `0.0.0.0`, and the network decides who reaches it). The listener
never serves `/v1/authorize`, and the main listener never decides without a
bearer. A host that embeds the PDP gets the same router from
`Service::trusted_router()`, to serve on a listener of its own.

Where UC can't reach the PDP over a trusted network, for example the hosted
Neon Function, the credential belongs in UC's egress path instead. A gateway
or sidecar in front of UC adds `Authorization: Bearer …` to its OPA calls, and
UC calls the bearer route. UC itself stays unchanged. A UC Java that sends a
bearer from a token file, as unitycatalog-rs does, would remove the need for
either.

### The `UnityCatalogOpa` namespace

`policies/unitycatalog-opa/` holds the reference schema and policies of a
privilege-level namespace. They aren't built in. Copy them into a policy
directory, or use the image's copy:
`PDP_POLICY_DIRS=/usr/share/pdp/unitycatalog-opa`. The route maps an input into
its caller's namespace:

- The action is the privilege as sent, `UnityCatalogOpa::Action::"USE_CATALOG"`.
- The resource type is `type` in PascalCase: `UnityCatalogOpa::RegisteredModel`.
- Each of `parents` (nearest first) is the Cedar parent of the one before.
- Ids are full names built from the leaf names: `analytics`, `analytics.reports`,
  `analytics.reports.orders`, an external location's or credential's name. The
  metastore, which has no name, is its UC id.
- Each entity carries `name`, `uc_id` (UC's id) and, when the client sends it,
  `owner`.
- A type or privilege the schema doesn't know, or a securable without a name, is
  a deny.

Mangrove's `UnityCatalog` namespace is operation-level: one action per API
operation, and the policies hold the table of which privileges each operation
needs. Here UC has already reduced an operation to privilege checks, so a policy
only answers whether a privilege holds on a securable.

### Context

The route keeps only the attributes of `input.context` that the action's
`context` type declares. The schema is the allowlist. Values the schema types as
`ipaddr` or `datetime` are built from their strings. The route also sets
`principal_email` to the input's `principal.email`, overwriting anything the
client sent under that name. The reference `Context` declares what
unitycatalog-rs sends (`source_ip`, `auth_method`, `provider`, `groups`,
`request_time`) and a `headers` record. To decide on a header a trusted proxy
adds, declare it there, for example `"x-tenant"?: String`, and have the gateway
strip that header on ingress. Then a policy can read `context.headers["x-tenant"]`.

`context.groups` is whatever the client asserts. The principal's memberships are
its `Lakehouse::Group` parents.

### Principals

The input's principal becomes a `Lakehouse::User`, by its Neon Auth id
(`PDP_NEON_AUTH`):

1. If `external_id` is a `neon_auth."user"` id, that user.
2. Otherwise, the user with that `email`, case-insensitive, and only if the email
   is verified. Otherwise signing up with someone's address would get their grants.
3. Otherwise, a deny.

UC's own `principal.id` (its random UUID) isn't used. Groups come from
`authz.memberships`. The resolution isn't cached.

### Grants

Privileges come from `authz.grants`, keyed by `(UnityCatalogOpa::<Type>, <full
name>)`. Grant `SELECT` on `UnityCatalogOpa::Catalog` `analytics`, and it holds on
every table in that catalog (`inherited_privileges`). The reference policies:

- allow a privilege that is granted on the securable or one of its parents;
- allow `ALL_PRIVILEGES` for everything except `OWNER` and `MANAGE`;
- allow `OWNER` for an `OWNER` grant on the securable itself, or when the client
  sends an `owner` equal to the principal's email.

UC Java keeps writing grants to its own store. The PDP never sees those grants.

## Testing

`cargo nextest run -p olai-pdp` runs the HTTP surface over an in-memory loader.
The OPA route's tests replay recorded UC Java and unitycatalog-rs inputs
(`crates/pdp/tests/fixtures/opa`, with their provenance) over the reference
policies.
`tests/postgres.rs` runs the loader against a real database when
`PDP_TEST_DATABASE_URL` points at a server where it can create databases, for
example `postgres://postgres@localhost:5432/postgres` on a local server
with trust auth. Without it, those
tests skip.
