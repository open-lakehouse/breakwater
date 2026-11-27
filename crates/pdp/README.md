# olai-pdp

A Cedar policy decision point (PDP). Services ask it whether a principal may
perform an action on a resource, over [olai-auth]'s PDP wire API. A service's
`olai_auth::HttpAuthorizer` is the client.

| Route | Auth | |
|---|---|---|
| `GET /health` | open | `OK` |
| `POST /v1/authorize` | caller secret | one `AuthorizeRequest` → `AuthorizeResponse` |
| `POST /v1/authorize/batch` | caller secret | up to 1000 requests, answered in order |
| `POST /v1/data/{package}` | caller secret | OPA-compatible: `{input}` → `{result:{allow}}`, for Unity Catalog's OPA authorizers |

With `PDP_TRUSTED_CALLER`, `pdp serve` also opens a trusted listener
(`PDP_TRUSTED_HOST:PDP_TRUSTED_PORT`, `127.0.0.1` by default). It serves only
`GET /health` and `POST /v1/data/{package}`, with no credential, and decides
every request as that one caller. It is for clients that send no credential,
such as UC Java 0.8, so expose it only where nothing else can reach it.

A decision is always a 200, even a deny (with the reason in `errors`). A missing
or unknown secret is a 401, a malformed body a 400, and an oversized batch a 413.
Each caller may ask only about its own Cedar namespace's actions: the caller
`UNITYCATALOG=UnityCatalog` asks about `UnityCatalog::Action`s, and anything else
is a 403, which refuses a whole batch.

Run it as the `pdp` binary (feature `bin`) or the `ghcr.io/open-lakehouse/pdp`
image. You can also embed it in another host (`embed::start`), as the
luminescent-lakehouse Neon Function does. See [docs/pdp.md](../../docs/pdp.md)
for configuration, the entity model and running the container.

```rust,no_run
# async fn run() -> Result<(), olai_pdp::Error> {
let mut config = olai_pdp::Config::from_env()?;
config.callers.push(olai_pdp::Caller::new("UNITYCATALOG", "UnityCatalog"));
let service = olai_pdp::embed::start(&config).await?;
let router = service.router();
# let _ = router; Ok(()) }
```

[olai-auth]: https://crates.io/crates/olai-auth
