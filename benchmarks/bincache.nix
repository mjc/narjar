let
  source = builtins.getFlake "github:wyattgill9/bincache/556a9c8f97a3c994a9de85f567a2ef16ce6513ab";
in
source.packages.${builtins.currentSystem}.bincache.overrideAttrs (old: {
  patches = (old.patches or []) ++ [ ./bincache-no-compression.patch ];
})
