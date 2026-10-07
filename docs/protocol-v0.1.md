# HTTP binary-cache protocol

## Routes

| Method and route | Response |
| --- | --- |
| GET/HEAD /nix-cache-info | 200, `text/x-nix-cache-info`; 500 for invalid cache state |
| GET/HEAD /<32-nix32>.narinfo | 200, `text/x-nix-narinfo`; 404 if absent |
| GET/HEAD /nar/<52-nix32>.nar[.zst\|.xz] | 200, `application/x-nix-nar`; 404 if absent |
| PUT /nix-cache-info | 200 for matching initialized bytes; 409 if different |
| PUT /nar/<52-nix32>.nar[.zst\|.xz] | 201 for new durable content; 200 for identical content |
| PUT /<32-nix32>.narinfo | 201 for new durable metadata; 200 for identical metadata |
| GET/HEAD /healthz | 200, public liveness |
| GET/HEAD /readyz | 200 or 503, staging capacity probe |
| GET/HEAD /metrics | 200, Prometheus text |

Realisations, NAR listings, build logs, and mass queries are unsupported.
Realisation reads and authenticated writes return 404.
Unsupported methods on recognized routes return 405 with Allow.

Writes require HTTP Basic credentials backed by a write token. Private-read
mode also requires a read or write token for reads, readiness, and metrics.
Health is always public. Invalid credentials return 401 with a fixed
WWW-Authenticate challenge.

Cache routes require literal canonical ASCII identifiers. They are not
percent-decoded. Invalid NAR GET/HEAD paths return 404, while invalid NAR PUT
paths return 400. Other malformed routes return 400 or 404 according to their
route classification.

HEAD returns full-GET status and headers without a body and ignores Range.
NAR GET supports one byte range: 206 with Content-Range for a satisfiable
range, 416 with `Content-Range: bytes */<length>` for an unsatisfiable range,
and 400 for multiple or malformed ranges. NAR responses advertise
`Accept-Ranges: bytes`.

## Upload framing and publication

PUT requires Content-Length. Transfer-Encoding and HTTP Content-Encoding
are not supported. Raw, Zstd, and XZ are NAR representations selected by the
URL suffix and narinfo Compression, not HTTP content encodings.

HTTP/1.1 `Expect: 100-continue` is granted by the publication worker before
reading an incompletely buffered body, after authentication, size, capacity,
and queue admission checks. A fully buffered or empty body needs no interim
response. Unsupported expectations return 417; HTTP/1.0 expectations are
ignored.

Upload the NAR before narinfo. A narinfo PUT without its required canonical
content or matching compressed-ingress receipt returns 422.
Canonical content is hashed, counted, and made durable before metadata can
be published. The server verifies byte identity, not NAR grammar.

Immutable destinations accept identical retries and reject differing bytes
with 409. Cache-info is created during initialization, not through HTTP;
its PUT route compares against the initialized file. An unreadable or invalid
existing cache-info file returns 500.

## Narinfo

Accepted metadata must:

- Be bounded UTF-8 in Nix's line-oriented format.
- Name a canonical /nix/store path whose hash matches the route.
- Use `nar/<FileHash>.nar[.zst|.xz]` with matching Compression.
- Include FileHash, FileSize, NarHash, NarSize, References, and a trusted Sig.
- For raw input, have FileHash equal NarHash and FileSize equal NarSize.
- For compressed input, match the receipt's encoded and decoded identities.
- Use canonical references, valid Deriver/CA fields, and no unknown fields or
  duplicate singleton fields.
- Verify at least one signature against configured public keys.

The signature covers the store path, uncompressed NAR hash and size, and
references. `--egress-compression none|zstd|xz` selects transport fields for
new publications without changing those signed claims. URL, Compression,
FileHash, and FileSize describe the actual served bytes. Existing metadata is
not rewritten when the server's egress setting changes.

Uploads and substitution use one cache URL. Compressed downloads are
materialized from canonical content and retained for reuse.

## Errors and caching

| Status | Meaning |
| ---: | --- |
| 400 | malformed HTTP headers, request target, or range |
| 401 | missing or invalid credentials |
| 409 | conflicting immutable destination |
| 411 | Content-Length missing |
| 413 | encoded/body size exceeds its limit |
| 415 | unsupported HTTP Content-Encoding |
| 417 | unsupported HTTP/1.1 expectation |
| 422 | invalid narinfo, identity/signature mismatch, decoded-size or decoder-memory excess |
| 429 | admission full |
| 500 | unexpected I/O or internal failure |
| 503 | read-only storage, failed readiness, or draining admission |
| 507 | space, quota, or inode exhaustion |

Errors generally have empty bodies; diagnostic endpoints use bounded plain
text. A transfer failure after headers aborts the connection.

Public-read NAR and narinfo responses use
`public, max-age=31536000, immutable`; cache-info uses
`public, max-age=3600`. This policy remains public when credentials are
supplied in public-read mode. Private-read responses use
`private, no-store`. Diagnostic endpoints use `no-store`.
Missing narinfo does not advertise long cache headers. Nix has its own
negative cache; use `--refresh` after a recently published miss.

Narjar speaks HTTP/1.1. A deployment proxy handles TLS and HTTP/2 or HTTP/3.
Preserve Authorization and Content-Length, disable PUT buffering, and align
body limits and timeouts. Restrict the direct listener to a trusted network.

Recorded client behavior is in [protocol captures](evidence/nix-http-protocol.md).
The [real-Nix tests](../tests/nix-e2e.sh) exercise both storage backends.
