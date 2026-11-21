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

## Testing

`cargo nextest run -p olai-pdp` runs the HTTP surface over an in-memory loader.
`tests/postgres.rs` runs the loader against a real database when
`PDP_TEST_DATABASE_URL` points at a server where it can create databases, for
example `postgres://postgres@localhost:5432/postgres` on a local server
with trust auth. Without it, those
tests skip.
