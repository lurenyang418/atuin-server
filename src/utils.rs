use semver::{Version, VersionReq};

pub fn client_version_min(user_agent: &str, req: &str) -> bool {
    if user_agent.is_empty() {
        return false;
    }

    let version = user_agent.replace("atuin/", "");

    match (VersionReq::parse(req), Version::parse(version.as_str())) {
        (Ok(req), Ok(version)) => req.matches(&version),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::client_version_min;

    #[test]
    fn matches_supported_version() {
        assert!(client_version_min("atuin/15.2.0", ">=15.0.0"));
    }

    #[test]
    fn rejects_lower_version() {
        assert!(!client_version_min("atuin/14.9.0", ">=15.0.0"));
    }

    #[test]
    fn rejects_invalid_user_agent() {
        assert!(!client_version_min("not-a-version", ">=15.0.0"));
    }
}
