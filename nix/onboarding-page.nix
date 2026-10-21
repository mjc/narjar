{
  lib,
  pkgs,
  url,
  keys,
  client,
  diagnostics,
  privateRead,
  role,
  leaseSeconds,
  clientLeaseSeconds,
}: let
  escape = lib.escapeXML;
  nixos = mode:
    lib.generators.toPretty {} (import ./client-configuration.nix {
      inherit lib url keys client mode;
      leaseSeconds = clientLeaseSeconds;
    });
  nixConf = ''
    extra-substituters = ${url}?priority=${toString client.priority}
    extra-trusted-public-keys = ${lib.concatStringsSep " " keys}
    narinfo-cache-positive-ttl = ${toString client.positiveTtlSeconds}
    narinfo-cache-negative-ttl = ${toString client.negativeTtlSeconds}
  '';
in
  pkgs.writeText "narjar-setup.html" ''
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Use ${escape url}</title>
      <style>
        :root { color-scheme: light dark; }
        body { max-width: 56rem; margin: 3rem auto; padding: 0 1rem; font: 1rem/1.6 system-ui, sans-serif; }
        pre { overflow-x: auto; padding: 1rem; border: 1px solid GrayText; border-radius: .25rem; }
        code { overflow-wrap: anywhere; }
        h2 { margin-top: 2rem; }
        a { color: LinkText; }
      </style>
    </head>
    <body>
      <main>
        <h1>Use this Nix cache</h1>
        <p><a href="${escape url}">${escape url}</a> — ${escape role}.</p>
        <h2>Verify the signing keys first</h2>
        <p>These keys come from this server's configuration. Confirm them with its operator through a trusted channel before using them. Finding this page through LAN discovery does not establish trust.</p>
        ${lib.concatMapStringsSep "\n" (key: ''
        <pre><code>${escape key}</code></pre>
        <p>SHA-256 of the exact public-key line, without a newline: <code>${builtins.hashString "sha256" key}</code></p>
      '')
      keys}
        ${lib.optionalString (!privateRead) ''
      <h2>NixOS: local fail-open edge</h2>
      <p>Import Narjar's NixOS module, then add this configuration. It runs a local verifying cache and turns remote failures into misses. Other substituters remain configured and can still fail independently; choose <code>substituterPolicy = "only"</code> explicitly to use only the edge.</p>
      <pre><code>${escape (nixos "local-edge")}</code></pre>
    ''}
        ${lib.optionalString privateRead ''
      <p>This cache requires read credentials. Ask its operator for a Nix netrc configuration. A local read-through edge cannot supply upstream read credentials; use direct substitution.</p>
    ''}
        <h2>NixOS: direct substitution</h2>
        <p>This uses the remote endpoint without a local cache. It does not provide the local edge's outage behavior.</p>
        <pre><code>${escape (nixos "direct")}</code></pre>
        <h2>nix.conf: direct substitution</h2>
        <p>Add these lines to the configuration used by your Nix daemon. On macOS, use the Nix configuration managed by your installation. No producer signing key or upload token is needed for public reads. Private reads require credentials supplied separately by the operator.</p>
        <pre><code>${escape nixConf}</code></pre>
        <h2>Retention and removal</h2>
      <p>${
      if leaseSeconds == null
      then "Follow the operator's GC retention policy for this uploaded cache."
      else "The minimum advertisement lease is ${toString leaseSeconds} seconds. Client positive metadata TTLs must fit twice within the lease, with another 300 seconds for delayed requests."
    }</p>
        <p>To stop using this cache, remove its client configuration or the added nix.conf lines and apply your normal Nix configuration update.</p>
        ${lib.optionalString diagnostics ''
      <h2>Diagnostics</h2>
      <p><a href="/readyz">Readiness</a> · <a href="/metrics">Prometheus metrics</a>. Private caches require read credentials; these links do not grant access.</p>
    ''}
      </main>
    </body>
    </html>
  ''
