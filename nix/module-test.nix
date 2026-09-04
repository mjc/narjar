{self}: {
  name = "narjar-module";

  nodes.machine = {pkgs, ...}: {
    imports = [self.nixosModules.default];

    services.narjar = {
      enable = true;
      listen = "127.0.0.1:5000";
      minFreeBytes = 0;
      auth.trustedPublicKeys = "/etc/narjar/trusted-public-keys";
      gc = {
        enable = true;
        schedule = "*-*-* 03:00:00";
        targetBytes = 0;
        minAgeSeconds = 3600;
      };
    };

    environment.etc."narjar/trusted-public-keys".text = "narjar-test:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n";
    environment.systemPackages = [pkgs.curl];

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

  nodes.static = {pkgs, ...}: {
    imports = [self.nixosModules.default];

    services.narjar = {
      enable = true;
      dataDir = "/var/lib/narjar-static";
      dynamicUser = false;
      minFreeBytes = 0;
    };

    environment.systemPackages = [pkgs.coreutils];
    virtualisation.diskSize = 2048;
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
    machine.succeed("systemctl start narjar-gc.service")
    machine.wait_for_unit("narjar.service")
    machine.succeed("curl --fail http://127.0.0.1:5000/healthz")

    static.wait_for_unit("narjar.service")
    static.succeed("systemctl is-active --quiet narjar.service")
    static.succeed("test \"$(systemctl show narjar.service -p DynamicUser --value)\" = no")
    static.succeed("systemctl stop narjar.service")
    static.succeed("rm -f /var/lib/narjar-static/nix-cache-info && touch /var/lib/narjar-static/incompatible")
    static.succeed("! systemctl start narjar.service")
    static.succeed("journalctl -u narjar.service -b --no-pager | grep -F 'data directory is not empty'")
    static.succeed("systemctl stop narjar.service || true")
    static.succeed("systemctl reset-failed narjar.service")
    static.succeed("rm -rf /var/lib/narjar-static && install -d -m 0700 -o narjar -g narjar /var/lib/narjar-static")
    static.succeed("systemctl start narjar.service")
    static.wait_for_unit("narjar.service")
    static.succeed("mkdir -p /var/lib/narjar-static/realisations/sentinel")
    static.succeed("seq 1 100000 | xargs -P 8 -n 1000 sh -c 'for i; do : > /var/lib/narjar-static/realisations/sentinel/$i; done' sh", timeout=300)
    before = static.succeed("stat -c '%u:%g:%Y:%Z' /var/lib/narjar-static/realisations/sentinel/1")
    static.succeed("systemctl restart narjar.service")
    static.wait_for_unit("narjar.service")
    static.succeed("systemctl is-active --quiet narjar.service")
    after = static.succeed("stat -c '%u:%g:%Y:%Z' /var/lib/narjar-static/realisations/sentinel/1")
    assert before == after, (before, after)
  '';
}
