use std::path::Path;

use super::Setup;

pub(super) fn quote_shell_argument(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub(super) fn print_upload_instructions(options: &Setup, secret_key: &Path) {
    println!(
        "push a path: narjar push {}--to {} --netrc-file {} --signing-key-file {} <store-path>",
        if options.cache_url.is_https() {
            ""
        } else {
            "--insecure-http "
        },
        quote_shell_argument(options.cache_url.as_str()),
        quote_shell_argument(
            &options
                .credentials_dir
                .join("narjar.netrc")
                .to_string_lossy()
        ),
        quote_shell_argument(&secret_key.to_string_lossy()),
    );
}

#[cfg(test)]
mod tests {
    use super::quote_shell_argument;

    #[test]
    fn copied_posix_arguments_preserve_spaces_unicode_and_apostrophes() {
        assert_eq!(quote_shell_argument("cache é's"), "'cache é'\\''s'");
    }
}
