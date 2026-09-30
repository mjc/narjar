{self}: {
  name = "narjar-static-user-module";

  nodes.machine = {pkgs, ...}: {
    imports = [self.nixosModules.default];

    services.narjar = {
      enable = true;
      dynamicUser = false;
      storageBackend = "flat";
      listen = "127.0.0.1:5000";
      minFreeBytes = 0;
      auth = {
        readTokens = "/run/narjar-static-test/read.tokens";
        writeTokens = "/run/narjar-static-test/write.tokens";
        trustedPublicKeys = "/run/narjar-static-test/trusted-public-keys";
      };
    };

    environment.systemPackages = [pkgs.curl];

    systemd.services.narjar-static-test-credentials = {
      before = ["narjar.service"];
      wantedBy = ["multi-user.target"];
      serviceConfig.Type = "oneshot";
      serviceConfig.RemainAfterExit = true;
      script = ''
        install -d -m 0700 /run/narjar-static-test
        printf '%s\n' 'read 3722571bbb8e89727856c5f44769f2ea2250f74d3aa5ad860760896836e630a4' > /run/narjar-static-test/read.tokens
        printf '%s\n' 'write 0000000000000000000000000000000000000000000000000000000000000000' > /run/narjar-static-test/write.tokens
        chmod 0600 /run/narjar-static-test/read.tokens
        printf '%s\n' 'narjar-test:11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=' > /run/narjar-static-test/trusted-public-keys
        chmod 0600 /run/narjar-static-test/write.tokens
        chmod 0600 /run/narjar-static-test/trusted-public-keys
      '';
    };
    systemd.services.narjar.requires = ["narjar-static-test-credentials.service"];
    systemd.services.narjar.after = ["narjar-static-test-credentials.service"];
  };

  testScript = ''
    def assert_owner_and_mode(path, expected):
        machine.succeed(f'test "$(stat -c \'%U:%G:%a\' {path})" = {expected}')

    def assert_read_requires_credentials():
        machine.fail("curl --fail http://127.0.0.1:5000/readyz")
        machine.succeed("curl --fail --user narjar-test:narjar-static-read-secret http://127.0.0.1:5000/readyz")

    def assert_start_fails_with(message):
        machine.fail("systemctl start narjar.service")
        machine.succeed(f"journalctl -u narjar.service -b --no-pager | grep -F '{message}'")

    def start_service():
        machine.succeed("systemctl reset-failed narjar.service")
        machine.succeed("systemctl start narjar.service")
        machine.wait_for_open_port(5000)
        machine.succeed("curl --fail --user narjar-test:narjar-static-read-secret http://127.0.0.1:5000/healthz")
        assert_read_requires_credentials()
        machine.succeed("cmp /run/narjar-static-test/read.tokens /var/lib/narjar/auth/read.tokens")
        machine.succeed("cmp /run/narjar-static-test/write.tokens /var/lib/narjar/auth/write.tokens")
        machine.succeed("cmp /run/narjar-static-test/trusted-public-keys /var/lib/narjar/trusted-public-keys")

    machine.wait_for_unit("narjar.service")
    machine.wait_for_open_port(5000)
    machine.succeed("curl --fail --user narjar-test:narjar-static-read-secret http://127.0.0.1:5000/healthz")
    assert_read_requires_credentials()

    fixed_directories = """
      /var/lib/narjar
      /var/lib/narjar/nar
      /var/lib/narjar/nar/.tmp
      /var/lib/narjar/.tmp
      /var/lib/narjar/.narjar-transactions
      /var/lib/narjar/realisations
      /var/lib/narjar/realisations/.tmp
      /var/lib/narjar/auth
      /var/lib/narjar/.narjar-validation
      /var/lib/narjar/.narjar-ingress
      /var/lib/narjar/.narjar-egress
      /var/lib/narjar/.narjar-chunks
      /var/lib/narjar/.narjar-manifests
    """.split()
    for path in fixed_directories:
        machine.succeed(f"test -d {path} && test ! -L {path}")
        assert_owner_and_mode(path, "narjar:narjar:700")

    fixed_files = """
      /var/lib/narjar/lock
      /var/lib/narjar/.narjar-layout
      /var/lib/narjar/.narjar-clean
      /var/lib/narjar/nix-cache-info
      /var/lib/narjar/trusted-public-keys
      /var/lib/narjar/auth/write.tokens
      /var/lib/narjar/auth/read.tokens
    """.split()
    for path in fixed_files:
        machine.succeed(f"test -f {path} && test ! -L {path}")
        assert_owner_and_mode(path, "narjar:narjar:600")

    machine.succeed("install -d -o root -g root -m 0711 /var/lib/narjar/nar/unmanaged-descendant")
    machine.succeed("install -o root -g root -m 0644 /dev/null /var/lib/narjar/nar/unmanaged-descendant/payload")
    machine.succeed("install -d -o root -g root -m 0711 /var/lib/narjar/.narjar-validation/unmanaged-descendant")
    machine.succeed("install -o root -g root -m 0644 /dev/null /var/lib/narjar/.narjar-validation/unmanaged-descendant/payload")
    machine.succeed("install -d -o root -g root -m 0711 /var/lib/narjar/.narjar-ingress/unmanaged-descendant")
    machine.succeed("install -o root -g root -m 0644 /dev/null /var/lib/narjar/.narjar-ingress/unmanaged-descendant/payload")
    machine.succeed("install -d -o root -g root -m 0711 /var/lib/narjar/.narjar-chunks/unmanaged-descendant")
    machine.succeed("install -o root -g root -m 0644 /dev/null /var/lib/narjar/.narjar-chunks/unmanaged-descendant/payload")
    machine.succeed("systemctl stop narjar.service")
    machine.succeed("chown root:root /var/lib/narjar/.narjar-validation && chmod 0755 /var/lib/narjar/.narjar-validation")
    machine.succeed("chown root:root /var/lib/narjar/.narjar-layout && chmod 0644 /var/lib/narjar/.narjar-layout")
    machine.succeed("rm /var/lib/narjar/.narjar-clean")
    machine.succeed("rm /var/lib/narjar/auth/read.tokens")
    machine.succeed("rm /var/lib/narjar/auth/write.tokens")
    machine.succeed("rm /var/lib/narjar/trusted-public-keys")
    machine.succeed("install -o root -g root -m 0666 /dev/null /var/lib/narjar/.narjar-recovery")
    machine.succeed("systemctl start narjar.service")
    machine.wait_for_open_port(5000)
    assert_owner_and_mode("/var/lib/narjar", "narjar:narjar:700")
    assert_owner_and_mode("/var/lib/narjar/.narjar-validation", "narjar:narjar:700")
    assert_owner_and_mode("/var/lib/narjar/.narjar-layout", "narjar:narjar:600")
    assert_owner_and_mode("/var/lib/narjar/.narjar-clean", "narjar:narjar:600")
    assert_owner_and_mode("/var/lib/narjar/auth/read.tokens", "narjar:narjar:600")
    assert_read_requires_credentials()
    machine.succeed("cmp /run/narjar-static-test/read.tokens /var/lib/narjar/auth/read.tokens")
    machine.succeed("cmp /run/narjar-static-test/write.tokens /var/lib/narjar/auth/write.tokens")
    machine.succeed("cmp /run/narjar-static-test/trusted-public-keys /var/lib/narjar/trusted-public-keys")
    machine.succeed("test ! -e /var/lib/narjar/.narjar-recovery")
    machine.succeed("test \"$(stat -c '%U:%G:%a' /var/lib/narjar/nar/unmanaged-descendant)\" = root:root:711")
    machine.succeed("test \"$(stat -c '%U:%G:%a' /var/lib/narjar/nar/unmanaged-descendant/payload)\" = root:root:644")
    machine.succeed("test \"$(stat -c '%U:%G:%a' /var/lib/narjar/.narjar-validation/unmanaged-descendant)\" = root:root:711")
    machine.succeed("test \"$(stat -c '%U:%G:%a' /var/lib/narjar/.narjar-validation/unmanaged-descendant/payload)\" = root:root:644")
    machine.succeed("test \"$(stat -c '%U:%G:%a' /var/lib/narjar/.narjar-ingress/unmanaged-descendant)\" = root:root:711")
    machine.succeed("test \"$(stat -c '%U:%G:%a' /var/lib/narjar/.narjar-ingress/unmanaged-descendant/payload)\" = root:root:644")
    machine.succeed("test \"$(stat -c '%U:%G:%a' /var/lib/narjar/.narjar-chunks/unmanaged-descendant)\" = root:root:711")
    machine.succeed("test \"$(stat -c '%U:%G:%a' /var/lib/narjar/.narjar-chunks/unmanaged-descendant/payload)\" = root:root:644")
    machine.succeed("curl --fail --user narjar-test:narjar-static-read-secret http://127.0.0.1:5000/healthz")

    machine.succeed("systemctl stop narjar.service")
    machine.succeed("mv /var/lib/narjar/.narjar-validation /var/lib/narjar/.narjar-validation.saved")
    machine.succeed("ln -s .narjar-validation.saved /var/lib/narjar/.narjar-validation")
    assert_start_fails_with("narjar: expected a real directory at /var/lib/narjar/.narjar-validation")
    machine.succeed("rm /var/lib/narjar/.narjar-validation && mv /var/lib/narjar/.narjar-validation.saved /var/lib/narjar/.narjar-validation")
    start_service()

    machine.succeed("systemctl stop narjar.service")
    machine.succeed("printf 'outside-marker\\n' > /run/narjar-static-test/external-target && chmod 0644 /run/narjar-static-test/external-target")
    machine.succeed("ln -s /run/narjar-static-test/external-target /var/lib/narjar/.narjar-recovery")
    assert_start_fails_with("narjar: expected an optional regular file at /var/lib/narjar/.narjar-recovery")
    assert_owner_and_mode("/run/narjar-static-test/external-target", "root:root:644")
    machine.succeed("grep -Fx outside-marker /run/narjar-static-test/external-target")
    machine.succeed("rm /var/lib/narjar/.narjar-recovery")
    start_service()

    machine.succeed("systemctl stop narjar.service")
    machine.succeed("rm /var/lib/narjar/trusted-public-keys")
    machine.succeed("ln -s /run/narjar-static-test/external-target /var/lib/narjar/trusted-public-keys")
    assert_start_fails_with("narjar: expected a regular managed credential file at /var/lib/narjar/trusted-public-keys")
    assert_owner_and_mode("/run/narjar-static-test/external-target", "root:root:644")
    machine.succeed("grep -Fx outside-marker /run/narjar-static-test/external-target")
    machine.succeed("rm /var/lib/narjar/trusted-public-keys")
    start_service()

    machine.succeed("systemctl stop narjar.service")
    machine.succeed("rm /var/lib/narjar/auth/write.tokens")
    machine.succeed("ln -s /run/narjar-static-test/missing-target /var/lib/narjar/auth/write.tokens")
    assert_start_fails_with("narjar: expected a regular managed credential file at /var/lib/narjar/auth/write.tokens")
    machine.succeed("rm /var/lib/narjar/auth/write.tokens")
    start_service()

    machine.succeed("systemctl stop narjar.service")
    machine.succeed("mv /var/lib/narjar/auth/read.tokens /var/lib/narjar/auth/read.tokens.saved")
    machine.succeed("mkdir /var/lib/narjar/auth/read.tokens")
    assert_start_fails_with("narjar: expected a regular managed credential file at /var/lib/narjar/auth/read.tokens")
    machine.succeed("rmdir /var/lib/narjar/auth/read.tokens && mv /var/lib/narjar/auth/read.tokens.saved /var/lib/narjar/auth/read.tokens")
    start_service()

    machine.succeed("systemctl stop narjar.service")
    machine.succeed("mv /var/lib/narjar/.narjar-layout /var/lib/narjar/.narjar-layout.saved")
    machine.succeed("mkdir /var/lib/narjar/.narjar-layout")
    assert_start_fails_with("narjar: expected a real regular file at /var/lib/narjar/.narjar-layout")
    machine.succeed("rmdir /var/lib/narjar/.narjar-layout && mv /var/lib/narjar/.narjar-layout.saved /var/lib/narjar/.narjar-layout")
    start_service()
  '';
}
