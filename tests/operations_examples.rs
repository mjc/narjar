use std::process::{Command, Output};

const OPERATIONS: &str = include_str!("../docs/operations.md");

fn example_starting_with(prefix: &str) -> &str {
    OPERATIONS
        .split("~~~sh\n")
        .find_map(|block| {
            block
                .starts_with(prefix)
                .then(|| block.split("~~~").next().unwrap())
        })
        .expect("the documented example exists")
}

fn run_example(mocks: &str, example: &str, failure: &str) -> Output {
    Command::new("bash")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            &format!("{mocks}\n{example}"),
        ])
        .env("FAIL_AT", failure)
        .env_remove("BASH_ENV")
        .output()
        .expect("run example with mock commands, without touching the filesystem")
}

fn log(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("mock command log is UTF-8")
}

const SETUP_MOCKS: &str = r#"
generated_key=
installed_key=
install() {
  printf 'install %s\n' "$*" >&2
  if [ "$1" = -d ]; then return; fi
  [ "$FAIL_AT" != install ] || return 1
  [ "$3" = "$generated_key" ]
  installed_key="$4"
}
narjar() {
  printf 'narjar %s\n' "$*" >&2
  case "$1 $2" in
    'init --data-dir') ;;
    'token create') [ "$FAIL_AT" != token ] ;;
    'key generate')
      [ "$FAIL_AT" != key ] || return 1
      generated_key="${@: -1}"
      ;;
    'serve --data-dir')
      [ "$installed_key" = /var/lib/narjar/trusted-public-keys ]
      [ "$(umask)" = 0077 ]
      ;;
    *) return 1 ;;
  esac
}
"#;

#[test]
fn fresh_start_installs_the_generated_key_before_serving() {
    let example = example_starting_with("set -euo pipefail\numask 077\n")
        .replace("> /run/narjar-credentials/narjar-ci-token", "> /dev/null");
    let output = run_example(SETUP_MOCKS, &example, "");
    assert!(output.status.success(), "{}", log(&output));
    assert!(log(&output).contains("install -d -m 0700 /run/narjar-credentials"));
    assert!(log(&output).contains("narjar serve --data-dir"));
}

#[test]
fn fresh_start_does_not_serve_after_credential_or_trust_installation_fails() {
    let example = example_starting_with("set -euo pipefail\numask 077\n")
        .replace("> /run/narjar-credentials/narjar-ci-token", "> /dev/null");
    for failure in ["token", "key", "install"] {
        let output = run_example(SETUP_MOCKS, &example, failure);
        assert!(!output.status.success(), "{failure}: {}", log(&output));
        assert!(
            !log(&output).contains("narjar serve"),
            "{failure}: {}",
            log(&output)
        );
    }
}

const RESTORE_MOCKS: &str = r#"
dataset=pool/narjar-data
snapshot=narjar-backup
destination_modified=0
test() {
  if [ "$*" = '! -e /mnt/narjar-restore' ]; then return 0; fi
  builtin test "$@"
}
zfs() {
  printf 'zfs %s\n' "$*" >&2
  case "$1" in
    list)
      case "${@: -1}" in
        pool/narjar-data)
          printf 'pool/narjar-data\t/var/lib/narjar\n'
          if [ "$FAIL_AT" = outside ]; then
            printf 'pool/narjar-data/content\t/production-outside-data\n'
          else
            printf 'pool/narjar-data/content\t/var/lib/narjar/nar\n'
            printf 'pool/narjar-data/metadata\t/var/lib/narjar/narinfo\n'
          fi
          ;;
        backup/narjar-restore)
          [ "$*" != 'list -H -o name backup/narjar-restore' ] || return 1
          printf 'backup/narjar-restore\t/mnt/narjar-restore\n'
          printf 'backup/narjar-restore/content\t/mnt/narjar-restore/nar\n'
          printf 'backup/narjar-restore/metadata\t/mnt/narjar-restore/narinfo\n'
          ;;
        *) return 1 ;;
      esac
      ;;
    mount)
      [ "$FAIL_AT" != mount ] || [ "$2" != backup/narjar-restore/content ]
      ;;
    send)
      case "$*" in
        *' -nP '*) ;;
        *' -i '*) printf 'incremental\n' ;;
        *) printf 'full\n' ;;
      esac
      ;;
    receive)
      local mode
      IFS= read -r mode
      if [ "$mode" = incremental ] && [ "$destination_modified" = 1 ]; then
        case " $* " in
          *' -F '*) ;;
          *) printf 'Incremental destination modified by verification\n' >&2; return 1 ;;
        esac
      fi
      ;;
    set|snapshot|unmount) ;;
    *) return 1 ;;
  esac
}
narjar() {
  printf 'narjar %s\n' "$*" >&2
  [ "$2 $3" = '--data-dir /mnt/narjar-restore' ]
  [ "$FAIL_AT" != "$1" ]
  destination_modified=1
}
"#;

#[test]
fn full_and_incremental_restores_verify_the_isolated_mounted_subtree() {
    let output = run_example(
        RESTORE_MOCKS,
        example_starting_with("set -euo pipefail\ntarget=backup/narjar-restore\n"),
        "",
    );
    let log = log(&output);
    assert!(output.status.success(), "{log}");
    let receive =
        "zfs receive -u -o mountpoint=/mnt/narjar-restore -o canmount=noauto backup/narjar-restore";
    assert_eq!(
        log.lines().filter(|line| *line == receive).count(),
        1,
        "{log}"
    );
    let incremental_receive = receive.replace("receive -u ", "receive -u -F ");
    assert_eq!(
        log.lines()
            .filter(|line| *line == incremental_receive)
            .count(),
        1,
        "{log}"
    );
    assert!(log.contains("zfs set mountpoint=/mnt/narjar-restore/nar canmount=noauto backup/narjar-restore/content"), "{log}");
    let verification = "zfs mount backup/narjar-restore\nzfs mount backup/narjar-restore/content\nzfs mount backup/narjar-restore/metadata\nnarjar doctor --data-dir /mnt/narjar-restore\nnarjar reconcile --data-dir /mnt/narjar-restore --verify-hashes\nnarjar verify --data-dir /mnt/narjar-restore\nzfs unmount backup/narjar-restore/metadata\nzfs unmount backup/narjar-restore/content\nzfs unmount backup/narjar-restore\n";
    assert_eq!(log.matches(verification).count(), 2, "{log}");
    assert!(
        log.contains("zfs send -R -i pool/narjar-data@narjar-backup pool/narjar-data@narjar-next"),
        "{log}"
    );
}

#[test]
fn failed_restore_verification_unmounts_all_received_children() {
    for failure in ["doctor", "reconcile", "verify"] {
        let output = run_example(
            RESTORE_MOCKS,
            example_starting_with("set -euo pipefail\ntarget=backup/narjar-restore\n"),
            failure,
        );
        let log = log(&output);
        assert!(!output.status.success(), "{failure}: {log}");
        assert!(log.ends_with("zfs unmount backup/narjar-restore/metadata\nzfs unmount backup/narjar-restore/content\nzfs unmount backup/narjar-restore\n"), "{failure}: {log}");
        assert!(!log.contains("zfs snapshot"), "{failure}: {log}");
    }
}

#[test]
fn failed_child_mount_unmounts_only_the_successfully_mounted_parent() {
    let output = run_example(
        RESTORE_MOCKS,
        example_starting_with("set -euo pipefail\ntarget=backup/narjar-restore\n"),
        "mount",
    );
    let log = log(&output);
    assert!(!output.status.success(), "{log}");
    assert!(
        log.ends_with("zfs unmount backup/narjar-restore\n"),
        "{log}"
    );
    assert!(!log.contains("narjar doctor"), "{log}");
}

#[test]
fn restore_rejects_source_mountpoints_outside_data_before_receiving() {
    let output = run_example(
        RESTORE_MOCKS,
        example_starting_with("set -euo pipefail\ntarget=backup/narjar-restore\n"),
        "outside",
    );
    let log = log(&output);
    assert!(!output.status.success(), "{log}");
    assert!(!log.contains("zfs receive"), "{log}");
    assert!(!log.contains("zfs mount"), "{log}");
}
