# Nix HTTP binary-cache protocol evidence

Status: NARJ-2 evidence snapshot. This freezes what was observed, separates it
from source-derived behavior, and lists the remaining acceptance gaps.

## Capture boundary

The canonical capture ran Nix 2.31.5 with curl 8.20.0 on aarch64-darwin against
a real loopback TCP connection to nginx at 127.0.0.1:18080. The comparison
capture ran Nix 2.35.2 with curl 8.21.0. There was no DNS lookup and no TLS
terminator. Those are deployment concerns, not evidence supplied by these
traces.

The nginx fixture is [nix-http-trace-nginx.conf](./nix-http-trace-nginx.conf).
Trace columns are, in order:

    epoch method request-uri status request-length response-body-bytes
    content-length transfer-encoding expect content-type user-agent remote-user
    range response-content-range if-none-match accept accept-encoding

It never logs Authorization. Blank fields mean the header was absent.

## Reproduction

Start the fixture from the repository root:

~~~sh
mkdir -p /tmp/narjar-nix-http-trace/{body,root,nginx}
nix shell nixpkgs#nginx -c nginx \
  -c "$PWD/docs/evidence/nix-http-trace-nginx.conf" \
  -p /tmp/narjar-nix-http-trace/nginx/ -g 'daemon off;'
~~~

In another shell, copy a local store path and read it back:

~~~sh
nix --version
nix copy --refresh \
  --to 'http://127.0.0.1:18080/fresh?compression=none' STORE_PATH
nix copy --refresh \
  --from 'http://127.0.0.1:18080/fresh?compression=none' \
  --to 'file:///tmp/narjar-copy-dest?compression=none' STORE_PATH
~~~

Use a regular netrc file for the authenticated variant. A one-shot /dev/fd
netrc is not a valid fixture because libcurl may reopen it for later requests.

## First write, compression=none

The fresh Nix 2.31.5 sequence was:

| Order | Request | Result | Meaning |
| ---: | --- | ---: | --- |
| 1 | GET /nix-cache-info | 404 | Probe cache metadata |
| 2 | PUT /nix-cache-info | 201 | Initialize writable cache |
| 3 | GET /<store-hash>.narinfo | 404 | Initial path-info probe |
| 4-6 | HEAD /<store-hash>.narinfo | 404 | Existence/reference probes |
| 7 | HEAD /nar/<file-hash>.nar | 404 | Avoid duplicate object upload |
| 8 | PUT /nar/<file-hash>.nar | 201 | Publish fixed-length raw NAR |
| 9 | PUT /<store-hash>.narinfo | 201 | Publish path metadata last |

Both PUTs used a fixed Content-Length; neither used chunked transfer nor
Expect: 100-continue. The NAR MIME type was application/x-nix-nar; narinfo was
text/x-nix-narinfo.

The upstream Nix 2.31.5 implementation computes and optionally compresses the
NAR locally, derives nar/<file-hash>.nar[.<codec>], uploads the NAR, signs the
metadata, and writes narinfo last:
[binary-cache-store.cc lines 1599-1818](https://github.com/NixOS/nix/blob/2.31.5/src/libstore/binary-cache-store.cc#L1599-L1818).
That source order agrees with the wire capture.

## Compression, addressing, duplicate writes, and reads

With default compression, Nix 2.31.5 used the same request order but uploaded
nar/<file-hash>.nar.xz. compression=none removed the suffix and sent the raw
NAR. A content-addressed path created by nix store add-file used the same
endpoint grammar and publication order.

Repeating nix copy --refresh --to for an already published path reported zero
copied paths and issued only a successful narinfo lookup; it did not repeat
either PUT.

A stock nix copy --from readback succeeded. The ordinary read path probed
narinfo and then issued GET /nar/<file-hash>.nar; it did not send Range.
Range/resume support is therefore not required for a normal read, but
interrupted-transfer behavior remains a separate acceptance test.

Nix treats narinfo existence as path validity:
[binary-cache-store.cc lines 1992-2003](https://github.com/NixOS/nix/blob/2.31.5/src/libstore/binary-cache-store.cc#L1992-L2003).
Realisation metadata, when used, is stored separately at
realisations/<drv-output-id>.doi:
[binary-cache-store.cc lines 2184-2228](https://github.com/NixOS/nix/blob/2.31.5/src/libstore/binary-cache-store.cc#L2184-L2228).

## Authentication and redirects

A regular netrc authenticated every GET, HEAD, NAR PUT, and narinfo PUT as
narjar. The native copy completed. Authentication is an HTTP-layer Basic
credential supplied by libcurl; the server must authorize each request and
must never assume one authenticated connection covers later requests.

Nix 2.35.2 followed HTTP 307 redirects for all methods, preserving PUT bodies
and content lengths for nix-cache-info, the NAR, and narinfo. This proves 307
behavior for the current client tested here; it does not authorize a server to
emit redirects unless the destination is equally trusted.

## Negative caching and refresh

For Nix 2.35.2, a missing narinfo was cached. After the same object was
published out-of-band, a normal nix path-info still failed without making the
object visible. nix path-info --refresh re-fetched narinfo and succeeded.
Servers must therefore make publication atomic at narinfo and operators must
understand that a prior 404 may remain client-visible until refresh or cache
expiry.

Nix documents a seven-day cache for nix-cache-info; this experiment only
characterizes negative narinfo behavior and does not infer its TTL:
[nix-cache-info format](https://nix.dev/manual/nix/2.35/protocols/binary-cache/nix-cache-info.html).

## Contract consequences for Narjar

- A path is visible only after its final narinfo is durably published.
- A NAR may exist without a narinfo after a crash; that state is unreachable
  garbage, not a readable cache entry.
- Incoming bodies must stream to a same-filesystem temporary file. Never buffer
  a NAR in memory.
- Verify length/hash and durability before rename; then publish narinfo by
  temporary-file write, sync, and atomic rename.
- Existing identical objects are idempotent success. Conflicting attempts must
  not overwrite published content.
- GET and HEAD share metadata and status behavior; HEAD sends no body.
- TLS is expected at a reverse proxy for v0.1; Narjar itself has no evidence
  basis for owning TLS.

## Remaining NARJ-2 gaps

- Deliberately interrupted download/upload, retry, and resume captures.
- A real derivation-output realisation capture, not only the source path.
- TLS/CA and proxy-buffering behavior at the chosen deployment boundary.
- Retry classification for connection reset, 408, 429, and 5xx.
- Exact negative narinfo cache TTL and process-versus-disk-cache behavior.
- A Linux capture to accompany the Darwin client captures.
