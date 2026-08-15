use crate::authentication::registry_based::Client;
use crate::authentication::Authenticator;
use crate::{authentication, log_utils};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::RwLock;

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
    clients: RwLock<HashSet<Cow<'static, str>>>,
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

    /// The credential encoding is shared with `RegistryBasedAuthenticator`, and
    /// has to stay that way: it is what arrives in a `Proxy-Authorization`
    /// header.
    fn encode(clients: &[Client]) -> HashSet<Cow<'static, str>> {
        clients
            .iter()
            .map(|x| BASE64_ENGINE.encode(format!("{}:{}", x.username, x.password)))
            .map(Cow::Owned)
            .collect()
    }

    // A panic while the lock is held would poison it, and an authenticator that
    // panics on every subsequent request is a worse outcome than one that keeps
    // serving the set it already has. Neither critical section can panic, so
    // recovering the guard is the safe reading of a case that should not occur.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashSet<Cow<'static, str>>> {
        self.clients.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashSet<Cow<'static, str>>> {
        self.clients.write().unwrap_or_else(|e| e.into_inner())
    }
}

impl Authenticator for ReloadableAuthenticator {
    fn authenticate(
        &self,
        source: &authentication::Source<'_>,
        _log_id: &log_utils::IdChain<u64>,
    ) -> authentication::Status {
        let creds = match &source {
            authentication::Source::ProxyBasic(str) => str,
            authentication::Source::Sni(str) => str,
        };
        if self.read().contains(creds.as_ref()) {
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
