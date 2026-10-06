# Narjar v0.1 protocol contract

Status: current HTTP contract. Historical Nix 2.31.5 and 2.35.2 captures
are retained under [protocol evidence](evidence/nix-http-protocol.md).
The locked real-Nix app and repository tests check the implemented behavior.

## Compatibility target

| Axis | Contract and evidence |
| --- | --- |
| Nix 2.31.5 | Historical protocol capture |
| Nix 2.35.2 | Historical redirect/negative-cache comparison capture |
| aarch64-darwin client | Historical protocol captures; native flat-storage package/test CI |
| x86_64-linux client | Locked real-Nix end-to-end CI for flat and chunked storage |
| Input-addressed store paths | Required |
| Content-addressed store paths | Required and captured |
| Basic/netrc | Required and captured |
| Bearer auth | Optional, not required |
| TLS | Required in deployment; terminated before Narjar |
| Server-emitted redirects | Non-goal |
| Client following HTTP 307 | Captured compatibility fact |
| Proxy request buffering | Must be disabled; deployment configuration, outside the loopback CI gate |
| Persistent connections | Optional optimization |
| Connection close between requests | Required to work |
| Negative-cache refresh | Required operator behavior; captured |
| compression=none, zstd, and xz writes | Required |
| Other precompressed writes | Explicit non-goal |
| Chunked request bodies | Explicit non-goal; Content-Length required |
| Realisations | Unsupported; no requests in the recorded corpus |
| NAR listings, logs, mass query | Explicit non-goal |

## Read routes

| Method and route | Success | Missing | Other contract |
| --- | ---: | ---: | --- |
| GET/HEAD /nix-cache-info | 200 text/x-nix-cache-info | 500 if installation is invalid | fixed Content-Length |
| GET/HEAD /<32-nix32>.narinfo | 200 text/x-nix-narinfo | 404 | immutable after publication |
| GET/HEAD /nar/<52-nix32>.nar[.zst|.xz] | 200 application/x-nix-nar | 404 | Accept-Ranges: bytes; bytes are served as stored |
| GET/HEAD /realisations/<id>.doi | none in v0.1 | 404 | route grammar reserved |
| GET /healthz | 200 text/plain | n/a | public liveness only; no-store |
| GET /readyz | 200 or 503 text/plain | n/a | read auth when private; no-store |
| GET /metrics | 200 text/plain; version=0.0.4 | n/a | read auth when private; no-store |

Invalid names or ambiguous paths return 400. Unsupported methods return 405
with Allow. Private-read auth failures return 401 with a fixed
WWW-Authenticate challenge. Authorization and path existence are not disclosed
before auth.

HEAD returns the status and headers of a full GET, including Content-Length,
without a body. It ignores Range.

One satisfiable byte range returns 206 and Content-Range. An unsatisfiable
range returns 416 and Content-Range: bytes */<full-length>. Multiple or malformed
ranges return 400. Only GET requests for NAR objects support ranges.

nix-cache-info body is fixed at initialization:

~~~text
StoreDir: /nix/store
WantMassQuery: 0
Priority: 30
~~~

Priority is configurable only at initialization. There is no in-place priority
change or backend migration command; create a new cache root for a different
priority. Clients can retain the previous cache metadata for days.

## Write routes

| Method and route | New | Identical retry | Invalid/conflict |
| --- | ---: | ---: | --- |
| PUT /nix-cache-info | 201 | 200 | 409 if bytes differ |
| PUT /nar/<52-nix32>.nar[.zst|.xz] | 201 | 200 | 409 immutable-name conflict |
| PUT /<32-nix32>.narinfo | 201 | 200 | 409 immutable-name conflict |
| PUT /realisations/<id>.doi | unsupported | unsupported | 405/404 in v0.1 |

All writes require a write token. Content-Length is required. The server rejects
Transfer-Encoding request bodies, HTTP Content-Encoding, unexpected route
suffixes, and bodies larger than configured route-specific limits. For HTTP/1.1
`Expect: 100-continue`, the publication worker sends 100 before reading an
incompletely buffered body. Authentication, header, declared-size, storage
capacity, and queue-admission failures receive a final response without granting
continuation. A fully buffered or empty body needs no interim response.
Unsupported expectations receive 417. HTTP/1.0 expectations are ignored.

XZ and Zstd uploads verify their encoded identity and measure the decoded NAR
hash and size. Later narinfo publication binds those measurements to the signed
logical claims. The server stores the canonical raw NAR in the selected flat or
chunked backend and may materialize a compressed egress representation from it.

Error classes:

| Status | Meaning |
| ---: | --- |
| 400 | malformed route/header/narinfo or unsupported compression declaration |
| 401 | missing or invalid credential |
| 409 | immutable name already contains different bytes/identity |
| 411 | Content-Length missing |
| 413 | declared or streamed body exceeds limit |
| 415 | HTTP Content-Encoding or unsupported NAR encoding |
| 417 | unsupported HTTP/1.1 request expectation |
| 422 | hash, size, path, URL, or signature validation failed |
| 429 | configured concurrency admission limit reached |
| 500 | internal invariant or unexpected I/O failure |
| 507 | destination filesystem has insufficient space |

Errors generally have empty bodies; diagnostic endpoints use bounded plain
text. There is no request-identifier or structured-error-body contract. HTTP
responses do not expose credentials or filesystem paths. Retry classification belongs to the Nix client;
[recorded source evidence](evidence/nix-http-protocol.md#retries-and-interrupted-transfers)
describes it. Idempotency makes retried PUT safe.

## Publication order

A fresh cache copy is expected to perform:

~~~text
GET  /nix-cache-info                  -> 200 for an initialized Narjar root
GET  /<store-hash>.narinfo            -> 404
HEAD /<store-hash>.narinfo            -> 404, possibly repeated
HEAD /nar/<file-hash>.nar             -> 404
PUT  /nar/<file-hash>.nar             -> 201
PUT  /<store-hash>.narinfo            -> 201
~~~

Narjar does not depend on the exact number or order of existence probes. It
does depend on NAR-before-narinfo for native v0.1 ingestion. A narinfo PUT whose
NAR is absent fails with 422 and never creates a visible path.

The historical nginx fixture returned 404 and accepted an initial
`PUT /nix-cache-info`; Narjar initializes that file before serving. A matching
PUT is idempotent and a conflicting PUT is rejected.

The NAR object may be durable but unreachable. The store path becomes visible
only when its validated narinfo no-replace hard link and directory sync
complete.

## Narinfo requirements

Accepted metadata must:

- Be bounded UTF-8 in the line-oriented Nix narinfo format.
- Contain one StorePath under /nix/store whose hash equals the route.
- Contain URL nar/<FileHash-nix32>.nar, nar/<FileHash-nix32>.nar.zst, or
  nar/<FileHash-nix32>.nar.xz.
- Declare Compression matching the URL suffix (`none`, `zstd`, or `xz`).
- Include FileHash, FileSize, NarHash, NarSize, References, and at least one Sig.
- Have FileHash equal NarHash and FileSize equal NarSize for compression=none;
  for uploaded zstd and xz, FileHash/FileSize describe the received compressed
  representation, which is decoded into canonical storage. Published narinfo
  transport fields describe the server-selected served representation.
- Match the durable NAR's computed hash and size.
- Use only canonical store-path/reference grammar.
- Verify at least one signature against configured trusted public keys.
- Reject duplicate singleton fields and conflicting values.
- Verify the canonical Nix store-path fingerprint and preserve its signed
  logical claims and accepted signatures when projecting transport fields.

Deriver and CA are accepted only with Nix-compatible field grammar; they never
substitute for the required trusted signature. Other field names are rejected
in v0.1. This matches the current Nix parser's semantic fields
without making unsigned future extensions part of Narjar's trust boundary.

## Caching

Public immutable NAR and narinfo responses may use a long max-age plus
immutable. nix-cache-info uses a shorter explicit policy. Its initialized
priority remains fixed for that cache root. Private/authenticated responses
default to private, no-store.

The `serve --egress-compression` policy selects the representation named by
newly published narinfo files: `none` serves the canonical raw byte stream, while
`zstd` and `xz` materialize an immutable compressed derivative from that raw
file. The URL, Compression, FileHash, and FileSize fields always describe the
same published derivative. A single cache URL is used for both uploads and
substitution; the policy is server configuration, not an alternate endpoint.

404 narinfo responses do not advertise long cache headers. Nix maintains its
own negative cache, so operators use --refresh after a recent publication that
followed a miss.

## Proxy and transport contract

The reverse proxy:

- Terminates TLS and validates the public certificate chain.
- Forwards Authorization without logging it.
- Disables request-body buffering for PUT.
- Applies a body limit no smaller than Narjar's configured limit.
- Preserves Content-Length and does not decompress request bodies.
- Uses timeouts larger than the documented slow-upload allowance.
- Does not rewrite 2xx/4xx/5xx responses or redirect PUT.
- Restricts direct Narjar access to loopback/private network.

Narjar itself speaks HTTP/1.1. HTTP/2 and HTTP/3 belong to the proxy.

## Compatibility checks

The [real-Nix app](../tests/nix-e2e.sh) runs in Linux CI for both canonical
backends using the Nix version pinned by the flake. It checks native push and
stock `nix copy`, duplicate refresh, content-addressed paths, range reads,
independent-store substitution and Nix verification, wrong-key refusal,
negative-cache refresh, concurrent and interrupted uploads, restart recovery,
corrupt input rejection, all raw/XZ/Zstd input and output combinations, and
offline GC with a protected closure. It records the Nix version and commands.

Repository Rust tests cover route, header, authentication, size, hash,
signature, and range edge cases. The static ELF and closure checks establish
packaging properties separately; the end-to-end app uses the normal package.
Historical captures are evidence for their recorded versions, not a separate
multi-version release matrix. TLS proxy configuration and filesystem
power-loss behavior require deployment-specific validation beyond these CI
checks. See the [release procedure](release.md#validate-the-candidate).
