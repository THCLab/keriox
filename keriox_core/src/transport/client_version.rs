//! keriox clients name their release in every request they send, so nodes
//! can tell which clients still talk to them and refuse ones too old for
//! what they write.

pub use semver::Version;

/// The `User-Agent` keriox clients send: `keriox/<release>`.
pub const CLIENT_AGENT: &str = concat!("keriox/", env!("CARGO_PKG_VERSION"));

/// The keriox release a request's `User-Agent` names, or `None` for a
/// request without one, or from another client.
pub fn client_version(user_agent: Option<&str>) -> Option<Version> {
    let agent = user_agent?.split_whitespace().next()?;
    Version::parse(agent.strip_prefix("keriox/")?).ok()
}

/// Whether a node that requires at least release `minimum` refuses a
/// request from `user_agent`: a keriox client of an older release, or a
/// client that names none.
pub fn is_too_old(user_agent: Option<&str>, minimum: &Version) -> bool {
    client_version(user_agent).map_or(true, |version| &version < minimum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_release_of_a_keriox_client() {
        assert_eq!(
            client_version(Some(CLIENT_AGENT)),
            Some(Version::parse(env!("CARGO_PKG_VERSION")).unwrap())
        );
        assert_eq!(
            client_version(Some("keriox/0.20.0-rc.1 extra")),
            Some(Version::parse("0.20.0-rc.1").unwrap())
        );
        for other in [None, Some("curl/8.0"), Some("keriox/latest"), Some("")] {
            assert_eq!(client_version(other), None, "{other:?}");
        }
    }

    #[test]
    fn an_older_release_or_none_is_too_old() {
        let minimum = Version::parse("0.20.0").unwrap();
        assert!(is_too_old(Some("keriox/0.19.0-rc.6"), &minimum));
        assert!(is_too_old(Some("keriox/0.20.0-rc.1"), &minimum));
        assert!(is_too_old(Some("curl/8.0"), &minimum));
        assert!(is_too_old(None, &minimum));
        assert!(!is_too_old(Some("keriox/0.20.0"), &minimum));
        assert!(!is_too_old(Some("keriox/0.21.3"), &minimum));
    }
}
