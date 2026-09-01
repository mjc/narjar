# Native Linux static package evidence

Date: 2026-09-01  
Source commit: `188f1a54f3d852c2807baafa95a015c8ac534892`  
Target: `x86_64-unknown-linux-musl`  
Package output: `/nix/store/7nli8p259qhclb4vpaxc4yxwn37ypiiz-narjar-0.1.0`

## Build and runtime

The locked package was built through the repository direnv environment against
Tina's Linux store:

```console
$ direnv exec . nix build --store ssh-ng://mjc@tina \
    .#packages.x86_64-linux.narjar-static \
    --accept-flake-config --print-out-paths --no-link
/nix/store/7nli8p259qhclb4vpaxc4yxwn37ypiiz-narjar-0.1.0
```

Tina ran Linux 6.18.44 on x86_64 with Nix 2.35.2. Executing the package there
printed `Hello, world!` and exited successfully.

The same flake output was realized in Tali's separate Nix store. Tali was also
running Linux 6.18.44 on x86_64 with Nix 2.35.2. Because its daemon normally
offloads to Tina, the package derivation was then deliberately rebuilt on Tali
with builders disabled:

```console
$ nix-store --realise --check --option builders '' \
    /nix/store/3p0fn04iq5nc51bgmf4pxmkilf13ac0h-narjar-0.1.0.drv
checking outputs of '...narjar-0.1.0.drv'...
...
Compiling narjar v0.1.0 (/build/source)
Finished `release` profile [optimized] target(s) in 6.87s
/nix/store/7nli8p259qhclb4vpaxc4yxwn37ypiiz-narjar-0.1.0
```

The successful Nix check proves the independently rebuilt package output was
byte-for-byte identical to the registered output. Both stores report:

```text
narHash = sha256-VLwwZyAF+Fb8aMdI/BsYm58AKUqsA2K04Q2alfBmqSk=
narSize = 536520
references = []
```

## ELF and closure

On both Linux hosts, `readelf -lW` reports no `INTERP` program header.
`readelf -dW` reports a PIE dynamic section containing relocations but no
`DT_NEEDED` entries. This is a fully static PIE rather than a dynamically
linked executable.

`nix-store --query --references` returns no paths. The complete requisites
query returns only the package output itself. The binary therefore carries no
runtime Nix-store, compiler, analyzer, test-tool, libc, or dynamic-loader
closure.

The package executed successfully on both Tina and Tali. The current scaffold
does not read certificates, DNS, timezone, locale, or other runtime data.

## Dependency-layer reproducibility observation

A forced local `nix-store --realise --check` of
`narjar-deps-0.1.0.drv` on Tali rebuilt Cargo checks, the release binary, and
the no-run test binary successfully, but Nix reported that the compressed
`target.tar.zst` output differed from Tina's copy.

This does not alter the independently reproduced final package NAR above. The
Crane dependency artifact is an internal build cache, not a shipped runtime
artifact. Its derivation identity still provides the intended source-change
reuse and invalidation boundary. Byte-reproducibility of Crane's compressed
intermediate archive is not treated as package reproducibility evidence.
