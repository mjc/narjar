{self}: {
  name = "narjar-filesystem-conformance";

  nodes.ext4 = {lib, pkgs, ...}: {
    imports = [self.nixosModules.default];

    services.narjar = {
      enable = true;
      dataDir = "/var/lib/narjar-ext4";
      dynamicUser = false;
      minFreeBytes = 0;
      auth.writeTokens = "/run/narjar-write.tokens";
    };

    virtualisation.emptyDiskImages = [512];
    systemd.services.narjar.wantedBy = lib.mkForce [];
    environment.systemPackages = [pkgs.curl pkgs.e2fsprogs];
  };

  nodes.tmpfs = {lib, pkgs, ...}: {
    imports = [self.nixosModules.default];

    services.narjar = {
      enable = true;
      dataDir = "/var/lib/narjar-tmpfs";
      dynamicUser = false;
      minFreeBytes = 0;
      auth.writeTokens = "/run/narjar-write.tokens";
    };

    fileSystems."/var/lib/narjar-tmpfs" = {
      device = "tmpfs";
      fsType = "tmpfs";
      options = ["mode=0700"];
    };
    systemd.services.narjar.wantedBy = lib.mkForce [];
    environment.systemPackages = [pkgs.curl pkgs.util-linux];
  };

  testScript = ''
    ext4.succeed("mkfs.ext4 -F /dev/vdb")
    ext4.succeed("mkdir -p /var/lib/narjar-ext4 && mount /dev/vdb /var/lib/narjar-ext4")
    ext4.succeed("rmdir /var/lib/narjar-ext4/lost+found")
    ext4.succeed("printf '%s\\n' 'test 4c6fe1d79dd5595d75e9b7c82dbdc4481996f7aea7143e7153c8eb5e9f94ea45' > /run/narjar-write.tokens")
    ext4.succeed("systemctl unmask narjar.service")
    ext4.succeed("systemctl start narjar.service")
    ext4.wait_for_unit("narjar.service")
    ext4.wait_for_open_port(5000)
    ext4.succeed("curl --fail http://127.0.0.1:5000/healthz")
    ext4.succeed("curl --fail -u narjar:test-write-token -X PUT --data-binary narjar http://127.0.0.1:5000/nar/0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar")
    ext4.succeed("test \"$(curl --fail http://127.0.0.1:5000/nar/0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar)\" = narjar")
    ext4.succeed("test -f /var/lib/narjar-ext4/nix-cache-info")
    ext4.succeed("systemctl restart narjar.service")
    ext4.wait_for_unit("narjar.service")
    ext4.wait_for_open_port(5000)
    ext4.succeed("curl --fail http://127.0.0.1:5000/nix-cache-info")
    ext4.succeed("systemctl stop narjar.service")
    ext4.succeed("umount /var/lib/narjar-ext4")
    ext4.succeed("mount /dev/vdb /var/lib/narjar-ext4")
    ext4.succeed("systemctl start narjar.service")
    ext4.wait_for_unit("narjar.service")
    ext4.wait_for_open_port(5000)
    ext4.succeed("curl --fail http://127.0.0.1:5000/healthz")
    ext4.succeed("test \"$(curl --fail http://127.0.0.1:5000/nar/0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar)\" = narjar")

    tmpfs.succeed("mkdir -p /var/lib/narjar-tmpfs && mount -t tmpfs -o mode=0700 tmpfs /var/lib/narjar-tmpfs")
    tmpfs.succeed("printf '%s\\n' 'test 4c6fe1d79dd5595d75e9b7c82dbdc4481996f7aea7143e7153c8eb5e9f94ea45' > /run/narjar-write.tokens")
    tmpfs.succeed("systemctl start narjar.service")
    tmpfs.wait_for_unit("narjar.service")
    tmpfs.wait_for_open_port(5000)
    tmpfs.succeed("mountpoint -q /var/lib/narjar-tmpfs")
    tmpfs.succeed("test \"$(stat -f -c %T /var/lib/narjar-tmpfs)\" = tmpfs")
    tmpfs.succeed("test -f /var/lib/narjar-tmpfs/nix-cache-info")
    tmpfs.succeed("curl --fail -u narjar:test-write-token -X PUT --data-binary narjar http://127.0.0.1:5000/nar/0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar")
    tmpfs.succeed("systemctl restart narjar.service")
    tmpfs.wait_for_unit("narjar.service")
    tmpfs.wait_for_open_port(5000)
    tmpfs.succeed("curl --fail http://127.0.0.1:5000/nix-cache-info")
    tmpfs.succeed("test \"$(curl --fail http://127.0.0.1:5000/nar/0li9rfm1hh9f00632vd0m0ihhnmwn4yvqvwcvkrfbi47da5a80nl.nar)\" = narjar")
  '';
}
