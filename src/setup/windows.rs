use std::path::Path;

use super::Setup;

pub(super) fn quote_shell_argument(value: &str) -> String {
    std::iter::once('\'')
        .chain(value.chars().flat_map(double_powershell_quote_delimiter))
        .chain(std::iter::once('\''))
        .collect()
}

fn double_powershell_quote_delimiter(character: char) -> impl Iterator<Item = char> {
    // PowerShell also treats these typographic characters as quote delimiters.
    let duplicate = match character {
        '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}' => Some(character),
        _ => None,
    };
    std::iter::once(character).chain(duplicate)
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
        assert_eq!(quote_shell_argument(r"C:\cache é's"), r"'C:\cache é''s'");
    }

    #[test]
    fn every_powershell_single_quote_delimiter_is_doubled_without_changing_its_value() {
        assert_eq!(quote_shell_argument("'‘’‚‛"), "'''‘‘’’‚‚‛‛'");
    }
}
