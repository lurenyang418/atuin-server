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
