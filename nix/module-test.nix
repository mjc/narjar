{ self }:
{
  name = "narjar-module";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ self.nixosModules.default ];

      services.narjar = {
        enable = true;
        listen = "127.0.0.1:5000";
        minFreeBytes = 0;
        auth.trustedPublicKeys = "/etc/narjar/trusted-public-keys";
      };

      environment.etc."narjar/trusted-public-keys".text =
        "narjar-test:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n";
      environment.systemPackages = [ pkgs.curl ];

      services.nginx = {
        enable = true;
        virtualHosts.localhost.extraConfig = "client_header_timeout 10s;";
        virtualHosts.localhost.locations."/" = {
          proxyPass = "http://127.0.0.1:5000";
          extraConfig = ''
            proxy_request_buffering off;
            proxy_buffering off;
            client_max_body_size 16g;
            client_body_timeout 300s;
            proxy_read_timeout 300s;
            proxy_send_timeout 300s;
          '';
        };
      };
    };

  testScript = ''
    machine.wait_for_unit("narjar.service")
    machine.wait_for_unit("nginx.service")
    machine.wait_for_open_port(5000)
    machine.succeed("curl --fail http://127.0.0.1:5000/healthz")
    machine.succeed("curl --fail http://127.0.0.1/readyz")
    machine.succeed("test \"$(stat -Lc %a /var/lib/narjar)\" = 700")
    machine.succeed("test \"$(stat -c %a /var/lib/narjar/trusted-public-keys)\" = 644")
    machine.succeed("test -f /var/lib/narjar/nix-cache-info")
    machine.succeed("test \"$(systemctl show narjar.service -p DynamicUser --value)\" = yes")
    machine.succeed("test \"$(systemctl show narjar.service -p NoNewPrivileges --value)\" = yes")
    machine.succeed("test \"$(systemctl show narjar.service -p ProtectSystem --value)\" = strict")
    machine.succeed("install -m 0600 /dev/null /var/lib/narjar/auth/read.tokens")
    machine.succeed("systemctl restart narjar.service")
    machine.wait_for_open_port(5000)
    machine.succeed("test ! -e /var/lib/narjar/auth/read.tokens")
    machine.succeed("curl --fail http://127.0.0.1:5000/nix-cache-info")
    machine.succeed("curl --fail http://127.0.0.1/readyz")
    machine.succeed("curl --fail http://127.0.0.1/healthz")
  '';
}
