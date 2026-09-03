# Narjar v0.1 protocol contract

Status: NARJ-4 draft. Authority is the pinned Nix source plus the raw captures
under docs/evidence. Third-party implementations are comparison material only.

## Compatibility target

| Axis | v0.1 classification |
| --- | --- |
| Nix 2.31.5 | Required and captured |
| Nix 2.35.2 | Required for tested routes; redirect/negative-cache comparison captured |
| aarch64-darwin client | Required and captured |
| x86_64-linux client | Required before release; unresolved |
| Input-addressed store paths | Required |
| Content-addressed store paths | Required and captured |
| Basic/netrc | Required and captured |
| Bearer auth | Optional, not required |
| TLS | Required in deployment; terminated before Narjar |
| Server-emitted redirects | Non-goal |
| Client following HTTP 307 | Captured compatibility fact |
| Proxy request buffering | Must be disabled; deployment proof unresolved |
| Persistent connections | Optional optimization |
| Connection close between requests | Required to work |
| Negative-cache refresh | Required operator behavior; captured |
| compression=none and xz writes | Required |
| Other precompressed writes | Explicit non-goal |
| Chunked request bodies | Explicit non-goal; Content-Length required |
| Realisations | Explicit v0.1 non-goal unless Linux E2E proves required |
| NAR listings, logs, mass query | Explicit non-goal |

## Read routes

| Method and route | Success | Missing | Other contract |
| --- | ---: | ---: | --- |
| GET/HEAD /nix-cache-info | 200 text/x-nix-cache-info | 500 if installation is invalid | fixed Content-Length |
| GET/HEAD /<32-nix32>.narinfo | 200 text/x-nix-narinfo | 404 | immutable after publication |
| GET/HEAD /nar/<52-nix32>.nar[.xz] | 200 application/x-nix-nar | 404 | Accept-Ranges: bytes; bytes are served as stored |
| GET/HEAD /realisations/<id>.doi | none in v0.1 | 404 | route grammar reserved |
| GET /healthz | 200 text/plain | n/a | public liveness only; no-store |
| GET /readyz | 200 or 503 text/plain | n/a | read auth when private; no-store |
| GET /metrics | 200 text/plain; version=0.0.4 | n/a | read auth when private; no-store |

Invalid names or ambiguous paths return 400. Unsupported methods return 405
with Allow. Private-read auth failures return 401 with a fixed
WWW-Authenticate challenge. Authorization and path existence are not disclosed
before auth.

HEAD returns the GET status and headers, including Content-Length, without a
body.

One satisfiable byte range returns 206 and Content-Range. An unsatisfiable
range returns 416 and Content-Range: bytes */<full-length>. Multiple or malformed
ranges return 400. Only NAR objects support ranges.

nix-cache-info body is fixed at initialization:

~~~text
StoreDir: /nix/store
WantMassQuery: 0
Priority: 30
~~~

Priority is configurable only at initialization; changing it requires an
explicit migration because clients cache this file for days.

## Write routes

| Method and route | New | Identical retry | Invalid/conflict |
| --- | ---: | ---: | --- |
| PUT /nix-cache-info | 201 | 200 | 409 if bytes differ |
| PUT /nar/<52-nix32>.nar[.xz] | 201 | 200 | 409 immutable-name conflict |
| PUT /<32-nix32>.narinfo | 201 | 200 | 409 immutable-name conflict |
| PUT /realisations/<id>.doi | unsupported | unsupported | 405/404 in v0.1 |

All writes require a write token. Content-Length is required. The server rejects
Transfer-Encoding request bodies, HTTP Content-Encoding, unexpected route
suffixes, and bodies larger than configured route-specific limits. XZ uploads
are validated against the decompressed NAR hash and size before publication.

Error classes:

| Status | Meaning |
| ---: | --- |
| 400 | malformed route/header/narinfo or unsupported compression declaration |
| 401 | missing or invalid credential |
| 409 | immutable name already contains different bytes/identity |
| 411 | Content-Length missing |
| 413 | declared or streamed body exceeds limit |
| 415 | HTTP Content-Encoding or unsupported NAR encoding |
| 422 | hash, size, path, URL, or signature validation failed |
| 429 | configured concurrency admission limit reached |
| 500 | internal invariant or unexpected I/O failure |
| 507 | destination filesystem has insufficient space |

Error bodies are bounded plain text with a stable class and request identifier.
They never include secrets, raw Authorization, complete narinfo signatures, or
filesystem paths. Whether Nix retries each status is a client concern still
covered by NARJ-2 fault capture; idempotency makes retried PUT safe.

## Publication order

A fresh cache copy is expected to perform:

~~~text
GET  /nix-cache-info                  -> 404
PUT  /nix-cache-info                  -> 201
GET  /<store-hash>.narinfo            -> 404
HEAD /<store-hash>.narinfo            -> 404, possibly repeated
HEAD /nar/<file-hash>.nar             -> 404
PUT  /nar/<file-hash>.nar             -> 201
PUT  /<store-hash>.narinfo            -> 201
~~~

Narjar does not depend on the exact number or order of existence probes. It
does depend on NAR-before-narinfo for native v0.1 ingestion. A narinfo PUT whose
NAR is absent fails with 422 and never creates a visible path.

The NAR object may be durable but unreachable. The store path becomes visible
only when its validated narinfo rename and directory sync complete.

## Narinfo requirements

Accepted metadata must:

- Be bounded UTF-8 in the line-oriented Nix narinfo format.
- Contain one StorePath under /nix/store whose hash equals the route.
- Contain URL nar/<FileHash-nix32>.nar or nar/<NarHash-nix32>.nar.xz.
- Declare Compression matching the URL suffix (`none` or `xz`).
- Include FileHash, FileSize, NarHash, NarSize, References, and at least one Sig.
- Have FileHash equal NarHash and FileSize equal NarSize for compression=none;
  for xz, FileHash/FileSize describe the stored compressed object.
- Match the durable NAR's computed hash and size.
- Use only canonical store-path/reference grammar.
- Verify at least one signature against configured trusted public keys.
- Reject duplicate singleton fields and conflicting values.
- Preserve accepted original bytes for signature stability; parsing must not
  normalize and then verify a different representation.

Deriver and CA are accepted only with Nix-compatible field grammar; they never
substitute for the required trusted signature. Other field names are rejected
in v0.1. This deliberately matches the current Nix parser's semantic fields
without making unsigned future extensions part of Narjar's trust boundary.

## Caching

Public immutable NAR and narinfo responses may use a long max-age plus
immutable. nix-cache-info uses a shorter explicit policy because deployment
priority may change only by migration. Private/authenticated responses default
to private, no-store.

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

## Compatibility vectors

Release tests must include:

1. Fresh Nix 2.31.5 compression=none push to an empty cache.
2. Duplicate push with no second object mutation.
3. Nix 2.35.2 push through regular-file netrc.
4. Content-addressed nix store add-file path.
5. Pull into an independent real Nix store with the trusted public key.
6. Pull refusal when the producer signature key is not trusted.
7. HEAD parity and full/suffix/open-ended range reads.
8. Interrupted PUT leaves no final file; exact retry succeeds.
9. Interrupted GET resumes or a fresh full GET succeeds without corruption.
10. Out-of-band publication after 404 remains hidden until --refresh.
11. Connection closure between every request.
12. Reverse-proxy TLS path with buffering disabled.
13. Malformed/traversal/oversize/hash/size/signature negative corpus.
14. Linux static binary serving the real client sequence.

Any behavior change requires a versioned decision record and an updated vector.
