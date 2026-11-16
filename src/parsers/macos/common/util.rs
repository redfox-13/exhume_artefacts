//! String and URL helpers shared by the macOS parsers.

/// Return `None` for `None` or all-whitespace strings, otherwise the original.
pub(crate) fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

/// Extract the host portion of a URL without pulling in a URL-parsing crate.
pub(crate) fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()?
        .split('@')
        .next_back()?
        .split(':')
        .next()?;
    non_empty(Some(host.to_string()))
}
