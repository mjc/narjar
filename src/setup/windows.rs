use std::path::Path;

use super::Setup;

pub(super) fn quote_shell_argument(value: &str) -> String {
    std::iter::once('"')
        .chain(
            value
                .chars()
                .flat_map(escape_powershell_expandable_string_character),
        )
        .chain(std::iter::once('"'))
        .collect()
}

fn escape_powershell_expandable_string_character(character: char) -> impl Iterator<Item = char> {
    let escape = match character {
        '`' | '$' | '"' | '\u{201c}' | '\u{201d}' | '\u{201e}' => Some('`'),
        _ => None,
    };
    escape.into_iter().chain(std::iter::once(character))
}

pub(super) fn print_upload_instructions(options: &Setup, _: &Path) {
    println!(
        "Upload from a Linux or macOS Nix host with narjar push to {}.",
        options.cache_url,
    );
    println!("Copy the producer credentials to that host before uploading.");
}

#[cfg(test)]
mod tests {
    use super::quote_shell_argument;

    #[test]
    fn copied_powershell_arguments_preserve_backslashes_unicode_and_apostrophes() {
        assert_eq!(quote_shell_argument(r"C:\cache é's"), r#""C:\cache é's""#);
    }

    #[test]
    fn powershell_expansion_and_quote_characters_are_escaped_but_single_quotes_are_literal() {
        assert_eq!(
            quote_shell_argument("'‘’‚‛\"“”„$`"),
            "\"'‘’‚‛`\"`“`”`„`$``\""
        );
    }
}
