{self}: {
  name = "narjar-module";

  nodes.machine = {pkgs, ...}: {
    imports = [self.nixosModules.default];

    services.narjar = {
      enable = true;
      listen = "127.0.0.1:5000";
      minFreeBytes = 0;
      auth = {
        writeTokens = "/run/narjar-test/write.tokens";
        trustedPublicKeys = "/run/narjar-test/trusted-public-keys";
      };
      gc = {
        enable = true;
        schedule = "*-*-* 03:00:00";
        targetBytes = 0;
        minAgeSeconds = 3600;
      };
    };

    environment.systemPackages = [pkgs.curl];

    systemd.services.narjar-test-credentials = {
      before = ["narjar.service"];
      wantedBy = ["multi-user.target"];
      serviceConfig.Type = "oneshot";
      serviceConfig.RemainAfterExit = true;
      script = ''
        install -d -m 0700 /run/narjar-test
        printf '%s\n' 'write 0000000000000000000000000000000000000000000000000000000000000000' > /run/narjar-test/write.tokens
        printf '%s\n' 'narjar-test:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=' > /run/narjar-test/trusted-public-keys
        chmod 0600 /run/narjar-test/write.tokens
        chmod 0600 /run/narjar-test/trusted-public-keys
      '';
    };
    systemd.services.narjar.requires = ["narjar-test-credentials.service"];
    systemd.services.narjar.after = ["narjar-test-credentials.service"];

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
    machine.succeed("test \"$(stat -c %a /var/lib/narjar/trusted-public-keys)\" = 600")
    machine.succeed("test \"$(stat -c %a /var/lib/narjar/auth/write.tokens)\" = 600")
    machine.succeed("cmp /run/narjar-test/write.tokens /var/lib/narjar/auth/write.tokens")
    machine.succeed("test -f /var/lib/narjar/nix-cache-info")
    machine.succeed("systemctl show narjar.service -p RequiresMountsFor --value | grep -Fx /var/lib/narjar")
    machine.succeed("test \"$(systemctl show narjar.service -p DynamicUser --value)\" = yes")
    machine.succeed("test \"$(systemctl show narjar.service -p NoNewPrivileges --value)\" = yes")
    machine.succeed("test \"$(systemctl show narjar.service -p ProtectSystem --value)\" = strict")
    machine.succeed("systemctl show narjar-gc.service -p Type --value | grep -Fx oneshot")
    machine.succeed("systemctl show narjar-gc.timer -p TimersCalendar --value | grep -F '*-*-* 03:00:00'")
    machine.succeed("systemctl show narjar-gc.service -p ExecStart --value | grep -F -- '--target-bytes 0'")
    machine.succeed("systemctl show narjar-gc.service -p ExecStart --value | grep -F -- '--min-age-seconds 3600'")
    machine.succeed("install -m 0600 /dev/null /var/lib/narjar/auth/read.tokens")
    machine.succeed("systemctl restart narjar.service")
    machine.wait_for_open_port(5000)
    machine.succeed("test ! -e /var/lib/narjar/auth/read.tokens")
    machine.succeed("curl --fail http://127.0.0.1:5000/nix-cache-info")
    machine.succeed("curl --fail http://127.0.0.1/readyz")
    machine.succeed("curl --fail http://127.0.0.1/healthz")
    machine.succeed("printf '%s\\n' 'write 1111111111111111111111111111111111111111111111111111111111111111' > /run/narjar-test/write.tokens")
    machine.succeed("systemctl restart narjar.service")
    machine.wait_for_open_port(5000)
    machine.succeed("cmp /run/narjar-test/write.tokens /var/lib/narjar/auth/write.tokens")
    machine.succeed("test \"$(stat -c %a /var/lib/narjar/auth/write.tokens)\" = 600")
    machine.succeed("systemctl start narjar-gc.service")
    machine.wait_for_unit("narjar.service")
    machine.wait_for_open_port(5000)
    machine.succeed("curl --fail http://127.0.0.1:5000/healthz")

  '';
}
