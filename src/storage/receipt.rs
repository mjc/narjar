use std::collections::BTreeMap;

pub(super) fn parse_legacy_fields(
    bytes: &[u8],
    expected_field_count: usize,
) -> Option<BTreeMap<&str, &str>> {
    let text = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    let fields = text.lines().try_fold(BTreeMap::new(), |mut fields, line| {
        let (name, value) = line.split_once('=')?;
        fields.insert(name, value).is_none().then_some(fields)
    })?;
    (fields.len() == expected_field_count).then_some(fields)
}
