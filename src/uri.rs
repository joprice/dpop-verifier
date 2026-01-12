use crate::DpopError;
use url::{Position, Url};

/// Normalize scheme/host/port/path for DPoP htu compare:
/// - http/https only; lowercase scheme+host
/// - drop query & fragment
/// - elide default ports (80/443)
/// - ensure non-empty path ("/")
/// - resolve dot-segments
pub fn normalize_htu(input: &str) -> Result<String, DpopError> {
    let mut url = Url::parse(input).map_err(|e| DpopError::MalformedHtu(e.to_string()))?;
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(DpopError::MalformedHtu("scheme".to_string()));
    }

    match url.host_str() {
        Some(host) if !host.is_empty() => {
            let lower = host.to_ascii_lowercase();
            url.set_host(Some(&lower))
                .map_err(|e| DpopError::MalformedHtu(format!("Failed setting host: {e}")))?;
        }
        _ => {
            return Err(DpopError::MalformedHtu("Missing host".to_string()));
        }
    }

    url.set_fragment(None);
    url.set_query(None);

    let is_default = (scheme == "http" && url.port() == Some(80))
        || (scheme == "https" && url.port() == Some(443));
    if is_default {
        let _ = url.set_port(None);
    }
    if url.path().is_empty() {
        url.set_path("/");
    }
    // resolve dot-segments
    let mut norm: Vec<&str> = Vec::new();
    {
        let segs = url
            .path_segments()
            .ok_or_else(|| DpopError::MalformedHtu("Missing path segment".to_string()))?;
        for s in segs {
            match s {
                "" | "." => {}
                ".." => {
                    norm.pop();
                }
                other => norm.push(other),
            }
        }
    }
    let mut new_path = String::from("/");
    new_path.push_str(&norm.join("/"));
    url.set_path(&new_path);

    Ok(url[..Position::AfterPath].to_string())
}

/// Normalize HTTP method for DPoP htm compare.
pub fn normalize_method(method: &str) -> Result<String, DpopError> {
    let uppercase_method = method.trim().to_ascii_uppercase();
    // Restrict to standard methods (expand if you need more)
    if !matches!(
        uppercase_method.as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE"
    ) {
        return Err(DpopError::InvalidMethod);
    }
    Ok(uppercase_method)
}

#[cfg(test)]
mod tests {
    use super::normalize_htu;
    use crate::DpopError;

    #[test]
    fn lowercases_scheme_and_host_and_strips_qf_and_default_ports() {
        let got = normalize_htu("HTTPS://EXAMPLE.com:443/Api/v1?q=1#frag").unwrap();
        assert_eq!(got, "https://example.com/Api/v1");
    }

    #[test]
    fn keeps_non_default_port() {
        let got = normalize_htu("http://example.com:8080/a/b").unwrap();
        assert_eq!(got, "http://example.com:8080/a/b");
    }

    #[test]
    fn empty_path_becomes_root() {
        let got = normalize_htu("https://example.com").unwrap();
        assert_eq!(got, "https://example.com/");
    }

    #[test]
    fn resolves_dot_segments() {
        let got = normalize_htu("https://ex.com/a/./b/../c").unwrap();
        assert_eq!(got, "https://ex.com/a/c");
    }

    #[test]
    fn collapses_redundant_slashes() {
        // Multiple slashes produce empty path segments; our normalizer skips "".
        let got = normalize_htu("https://ex.com//a///b////c").unwrap();
        assert_eq!(got, "https://ex.com/a/b/c");
    }

    #[test]
    fn ipv6_and_default_port_elision() {
        let got = normalize_htu("https://[2001:db8::1]:443/a").unwrap();
        assert_eq!(got, "https://[2001:db8::1]/a");
    }

    #[test]
    fn ipv6_non_default_port_kept() {
        let got = normalize_htu("http://[2001:db8::1]:8080/a").unwrap();
        assert_eq!(got, "http://[2001:db8::1]:8080/a");
    }

    #[test]
    fn rejects_non_http_schemes() {
        let err = normalize_htu("ftp://example.com/a").unwrap_err();
        assert!(matches!(err, DpopError::MalformedHtu("a")));
    }

    #[test]
    fn rejects_missing_or_empty_host() {
        assert!(matches!(
            normalize_htu("https:"),
            Err(DpopError::MalformedHtu)
        ));
        assert!(matches!(
            normalize_htu("https://"),
            Err(DpopError::MalformedHtu)
        ));
    }

    #[test]
    fn idempotent_when_already_normalized() {
        let input = "https://example.com/a/b";
        let once = normalize_htu(input).unwrap();
        let twice = normalize_htu(&once).unwrap();
        assert_eq!(once, twice);
        assert_eq!(twice, "https://example.com/a/b");
    }

    #[test]
    fn preserves_path_case() {
        // Only scheme/host are lowercased; path casing must be preserved.
        let got = normalize_htu("https://EX.com/Api/V1/Users").unwrap();
        assert_eq!(got, "https://ex.com/Api/V1/Users");
    }

    #[test]
    fn removes_query_and_fragment_only() {
        let got = normalize_htu("http://ex.com/a/b?x=1&y=2#sec").unwrap();
        assert_eq!(got, "http://ex.com/a/b");
    }

    #[test]
    fn resolves_trailing_parent_segment() {
        let got = normalize_htu("http://ex.com/a/b/..").unwrap();
        assert_eq!(got, "http://ex.com/a");
    }
}
