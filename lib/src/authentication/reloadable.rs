use crate::authentication::registry_based::Client;
use crate::authentication::Authenticator;
use crate::{authentication, log_utils};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Credentials as they arrive on the wire, mapped to the username behind them.
///
/// The username is only ever used to attribute traffic, so it is kept as an
/// `Arc<str>`: a metric label can hold a cheap clone that stays valid even if
/// the user is removed by a reload halfway through the connection.
type Clients = HashMap<Box<str>, Arc<str>>;

/// An [`Authenticator`] whose client list can be replaced while the endpoint is
/// running.
///
/// [`RegistryBasedAuthenticator`](super::registry_based::RegistryBasedAuthenticator)
/// reads its clients once at startup, so adding or removing a user means
/// restarting the endpoint and dropping every live connection with it. That is
/// fine for a hand-edited deployment, but not for one driven by a panel that
/// re-syncs its user list on a timer.
///
/// The client set therefore sits behind an `RwLock`: [`authenticate`] takes it
/// for reading, [`reload`] swaps it for writing, and no connection is
/// interrupted either way. Authentication is a short read on a small set, so
/// readers effectively never contend.
///
/// [`authenticate`]: Authenticator::authenticate
/// [`reload`]: ReloadableAuthenticator::reload
pub struct ReloadableAuthenticator {
    clients: RwLock<Clients>,
}

impl ReloadableAuthenticator {
    pub fn new(clients: &[Client]) -> Self {
        Self {
            clients: RwLock::new(Self::encode(clients)),
        }
    }

    /// Replace the client list, returning how many clients are now known.
    ///
    /// Callers are expected to keep the previous list on a parse failure rather
    /// than reloading an empty one: this is reachable from a periodic sync, and
    /// a truncated or half-written file must not be able to lock every user out.
    pub fn reload(&self, clients: &[Client]) -> usize {
        let next = Self::encode(clients);
        let count = next.len();
        *self.write() = next;
        count
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The username the given credentials belong to, if they are known.
    ///
    /// Traffic has to be attributed to a user before it can be billed, and the
    /// credentials are the only thing a connection carries: nothing downstream
    /// of authentication knows which account it is serving. Returning the name
    /// here keeps that lookup in the one place that already holds the mapping.
    pub fn username_for(&self, source: &authentication::Source<'_>) -> Option<Arc<str>> {
        self.read().get(Self::credentials(source)).cloned()
    }

    /// The credential encoding is shared with `RegistryBasedAuthenticator`, and
    /// has to stay that way: it is what arrives in a `Proxy-Authorization`
    /// header.
    fn encode(clients: &[Client]) -> Clients {
        clients
            .iter()
            .map(|x| {
                (
                    BASE64_ENGINE
                        .encode(format!("{}:{}", x.username, x.password))
                        .into_boxed_str(),
                    Arc::from(x.username.as_str()),
                )
            })
            .collect()
    }

    fn credentials<'a>(source: &'a authentication::Source<'_>) -> &'a str {
        match source {
            authentication::Source::ProxyBasic(str) => str,
            authentication::Source::Sni(str) => str,
        }
    }

    // A panic while the lock is held would poison it, and an authenticator that
    // panics on every subsequent request is a worse outcome than one that keeps
    // serving the set it already has. Neither critical section can panic, so
    // recovering the guard is the safe reading of a case that should not occur.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Clients> {
        self.clients.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Clients> {
        self.clients.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl Authenticator for ReloadableAuthenticator {
    fn authenticate(
        &self,
        source: &authentication::Source<'_>,
        _log_id: &log_utils::IdChain<u64>,
    ) -> authentication::Status {
        if self.read().contains_key(Self::credentials(source)) {
            authentication::Status::Pass
        } else {
            authentication::Status::Reject
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authentication::{Source, Status};
    use std::borrow::Cow;

    fn client(username: &str, password: &str) -> Client {
        Client {
            username: username.to_string(),
            password: password.to_string(),
            max_http2_conns: None,
            max_http3_conns: None,
        }
    }

    fn creds(username: &str, password: &str) -> Source<'static> {
        Source::ProxyBasic(Cow::Owned(
            BASE64_ENGINE.encode(format!("{username}:{password}")),
        ))
    }

    fn check(auth: &ReloadableAuthenticator, source: &Source<'_>) -> Status {
        auth.authenticate(source, &log_utils::IdChain::<u64>::empty())
    }

    #[test]
    fn accepts_a_known_client_and_rejects_others() {
        let auth = ReloadableAuthenticator::new(&[client("alice", "pw1")]);

        assert!(check(&auth, &creds("alice", "pw1")) == Status::Pass);
        assert!(check(&auth, &creds("alice", "wrong")) == Status::Reject);
        assert!(check(&auth, &creds("bob", "pw1")) == Status::Reject);
    }

    #[test]
    fn encodes_credentials_the_same_way_as_the_registry_authenticator() {
        // The two must stay interchangeable: a client that authenticates
        // against one has to authenticate against the other unchanged.
        let clients = [client("alice", "pw1"), client("bob", "pw2")];
        let reloadable = ReloadableAuthenticator::new(&clients);
        let registry = authentication::registry_based::RegistryBasedAuthenticator::new(&clients);

        for source in [creds("alice", "pw1"), creds("bob", "pw2"), creds("eve", "x")] {
            let id = log_utils::IdChain::<u64>::empty();
            assert!(
                reloadable.authenticate(&source, &id) == registry.authenticate(&source, &id),
                "the two authenticators disagreed"
            );
        }
    }

    #[test]
    fn a_reload_adds_and_removes_clients() {
        let auth = ReloadableAuthenticator::new(&[client("alice", "pw1")]);

        assert_eq!(auth.reload(&[client("bob", "pw2")]), 1);

        // The point of the type: the new user works and the old one stops
        // working, with no restart in between.
        assert!(check(&auth, &creds("bob", "pw2")) == Status::Pass);
        assert!(check(&auth, &creds("alice", "pw1")) == Status::Reject);
    }

    #[test]
    fn a_password_change_takes_effect() {
        let auth = ReloadableAuthenticator::new(&[client("alice", "old")]);
        auth.reload(&[client("alice", "new")]);

        assert!(check(&auth, &creds("alice", "new")) == Status::Pass);
        assert!(check(&auth, &creds("alice", "old")) == Status::Reject);
    }

    #[test]
    fn reloading_to_an_empty_list_rejects_everyone() {
        // Not a recommended thing to do - it is exactly what a truncated
        // credentials file would produce - but it must be predictable rather
        // than accidentally permissive.
        let auth = ReloadableAuthenticator::new(&[client("alice", "pw1")]);

        assert_eq!(auth.reload(&[]), 0);
        assert!(auth.is_empty());
        assert!(check(&auth, &creds("alice", "pw1")) == Status::Reject);
    }

    #[test]
    fn credentials_resolve_to_a_username() {
        // Traffic can only be billed once it has a name attached, and the
        // credentials are all a connection carries.
        let auth = ReloadableAuthenticator::new(&[client("alice", "pw1"), client("bob", "pw2")]);

        assert_eq!(
            auth.username_for(&creds("alice", "pw1")).as_deref(),
            Some("alice")
        );
        assert_eq!(
            auth.username_for(&creds("bob", "pw2")).as_deref(),
            Some("bob")
        );
        assert!(auth.username_for(&creds("eve", "pw")).is_none());
    }

    #[test]
    fn a_username_survives_the_user_being_removed() {
        // A connection is attributed for as long as it lives, so the name a
        // caller is holding must not dangle when a reload drops the user.
        let auth = ReloadableAuthenticator::new(&[client("alice", "pw1")]);
        let held = auth.username_for(&creds("alice", "pw1")).expect("known");

        auth.reload(&[]);

        assert_eq!(&*held, "alice");
        assert!(auth.username_for(&creds("alice", "pw1")).is_none());
    }

    #[test]
    fn a_password_change_keeps_the_same_username() {
        let auth = ReloadableAuthenticator::new(&[client("alice", "old")]);
        auth.reload(&[client("alice", "new")]);

        assert_eq!(
            auth.username_for(&creds("alice", "new")).as_deref(),
            Some("alice")
        );
        assert!(auth.username_for(&creds("alice", "old")).is_none());
    }

    #[test]
    fn duplicate_clients_collapse() {
        let auth = ReloadableAuthenticator::new(&[client("alice", "pw1"), client("alice", "pw1")]);
        assert_eq!(auth.len(), 1);
    }

    #[test]
    fn sni_credentials_are_accepted_too() {
        let auth = ReloadableAuthenticator::new(&[client("alice", "pw1")]);
        let encoded = BASE64_ENGINE.encode("alice:pw1");

        assert!(check(&auth, &Source::Sni(Cow::Owned(encoded))) == Status::Pass);
    }

    /// The reload path reads a file that some other process is writing, so the
    /// parser has to fail rather than panic on anything malformed. These go
    /// through `parse_clients_toml`, which is the same parser startup uses.
    mod credentials_file {
        use crate::settings::parse_clients_toml;

        #[test]
        fn parses_a_normal_file() {
            let clients = parse_clients_toml(
                r#"
                [[client]]
                username = "alice"
                password = "pw1"

                [[client]]
                username = "bob"
                password = "pw2"
                max_http2_conns = 4
                "#,
            )
            .expect("should parse");

            assert_eq!(clients.len(), 2);
            assert_eq!(clients[0].username, "alice");
            assert_eq!(clients[1].max_http2_conns, Some(4));
        }

        #[test]
        fn a_truncated_file_is_an_error_not_a_panic() {
            // What a reload would see mid-write.
            for content in [
                "[[client]]\nusername = \"alice\"",       // no password
                "[[client]]\npassword = \"pw1\"",         // no username
                "[[client]]\nusername = \"\"\npassword = \"pw\"", // empty
                "[[client]",                              // cut off
                "",                                       // empty file
            ] {
                assert!(
                    parse_clients_toml(content).is_err(),
                    "should have been rejected: {content:?}"
                );
            }
        }
    }

    #[test]
    fn readers_and_a_reloader_can_run_together() {
        use std::sync::Arc;

        // A reload happens under load, so the lock has to survive readers and a
        // writer at the same time rather than only being correct when idle.
        let auth = Arc::new(ReloadableAuthenticator::new(&[client("alice", "pw1")]));
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let auth = auth.clone();
                std::thread::spawn(move || {
                    for _ in 0..2_000 {
                        // Either answer is legitimate depending on whether the
                        // reload has landed; the assertion is that it returns.
                        let _ = check(&auth, &creds("alice", "pw1"));
                    }
                })
            })
            .collect();

        for i in 0..200 {
            auth.reload(&[client("alice", "pw1"), client(&format!("u{i}"), "pw")]);
        }
        for r in readers {
            r.join().expect("a reader thread panicked");
        }

        assert!(check(&auth, &creds("alice", "pw1")) == Status::Pass);
    }
}
