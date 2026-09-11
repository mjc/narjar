# NARJ-87: gix dependency and binary cost

Measurement commit: `eb3adc0d22d8267324db614edf927d03f17750fe`.

## Scope

Four protocol-neutral probes were compared with the current Narjar graph:

- `loose`: `gix-hash`, `gix-object`, `gix-odb`, and `tempfile`; loose-object write/read.
- `packed-read`: the loose probe plus the `gix-pack` index-read API.
- `pack-write`: the loose probe plus the `gix-pack` bundle-write API.
- `high-level`: the minimal `gix` facade with `basic`, `sha1`, and `sha256` features.

The high-level probe deliberately disables facade default features. The available index could not resolve the facade's optional `gix-archive ^0.36.1` default dependency. A no-hash-feature variant also correctly failed compilation; the probe was then fixed by selecting both hash features.

## Results

All sizes are bytes unless noted. Candidate binaries are one-binary probes; the Narjar package contains five binaries, so package-level comparisons are directional rather than functionality-equivalent.

| graph | resolved packages | static binary | clean build s | warm build s | max RSS native 1/32 readers KiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| current Narjar package | 47 | 2,332,560 | 3.536 | 0.038 | n/a |
| loose | 96 | 990,168 | 7.897 | 0.064 | 2,556 / 2,252 |
| packed-read | 96 | 1,000,760 | 1.765 | 0.711 | 2,180 / 2,180 |
| pack-write | 102 | 1,420,296 | 4.891 | 0.053 | 2,796 / 2,796 |
| high-level | 146 | 2,135,064 | 11.544 | 0.082 | 3,012 / 3,012 |

The full machine-readable tables are next to this report. Static-musl builds succeeded for every candidate and produced single-path closures. `cargo audit` returned zero vulnerabilities, warnings, or informational findings for the baseline and all candidates. Release binaries contained zero debug bytes.

Every candidate passed `cargo check --locked` under Rust 1.85.1 on Linux and for the `x86_64-apple-darwin` target. The build-time figures were collected sequentially on the measurement host with its configured compiler cache; they are comparative observations for this run, not clean-machine forecasts.

The loose candidate is the smallest gix graph tested, but still resolves 96 packages versus the current graph's 47. Adding packed reads did not enlarge the resolved graph in this feature configuration and added about 10 KiB to the static binary. Pack writing added about 420 KiB over loose. The high-level facade added about 1.15 MiB over loose, 50 more resolved packages, and the highest lexical unsafe-token inventory.

The RSS figures are probe RSS, not full Narjar service RSS. They are useful for graph comparison only; they do not establish production service memory behavior.

## Recommendation

Do not replace Narjar's current storage implementation with gix based on this evidence. The narrow loose graph is the only candidate worth preserving for a future prototype, but it is not a production recommendation: it increases dependency breadth and was not tested against Narjar's publication, validation, locking, or HTTP contracts. The high-level facade and pack-writing graph should be rejected for the current cost envelope.
