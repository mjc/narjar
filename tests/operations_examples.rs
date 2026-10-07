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
