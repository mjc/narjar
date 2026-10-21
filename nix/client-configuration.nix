{
  lib,
  url,
  keys,
  client,
  mode,
  leaseSeconds,
}: {
  services.narjar =
    {
      client = {
        enable = true;
        inherit url mode;
        trustedPublicKeys = keys;
        inherit (client) priority positiveTtlSeconds negativeTtlSeconds;
        substituterPolicy = "append";
        fallback = false;
      };
    }
    // lib.optionalAttrs (mode == "local-edge") {
      edge.leaseSeconds = lib.max leaseSeconds (2 * client.positiveTtlSeconds + 300);
    };
}
