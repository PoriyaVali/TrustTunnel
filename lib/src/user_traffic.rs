//! Per-user traffic accounting.
//!
//! The Prometheus counters in [`crate::metrics`] are totals labelled by
//! protocol, which answers "how busy is this endpoint" but not "how much has
//! this account used" - and the second question is the one a panel has to
//! answer to enforce a quota or bill for traffic.
//!
//! Two things make this a separate table rather than another label on the
//! existing counters:
//!
//! * a label carrying a username produces one time series per user per
//!   protocol, which grows without bound on a busy endpoint;
//! * a Prometheus counter only ever increases, while a panel wants to collect
//!   what has been used *since it last asked* and have the endpoint forget it.
//!   That is [`UserTraffic::drain`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Bytes moved by one user, in the direction names a panel expects.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Usage {
    /// Bytes sent by the client.
    pub uplink: u64,
    /// Bytes sent to the client.
    pub downlink: u64,
}

impl Usage {
    pub fn is_zero(&self) -> bool {
        self.uplink == 0 && self.downlink == 0
    }
}

/// One user's counters, held for the lifetime of a connection.
///
/// A connection takes this once and then only adds to it, so accounting costs
/// an atomic add per chunk of traffic rather than a map lookup or a lock. That
/// matters: this sits on the path every byte takes.
#[derive(Default, Debug)]
pub struct UserCounter {
    uplink: AtomicU64,
    downlink: AtomicU64,
}

impl UserCounter {
    pub fn add_uplink(&self, n: u64) {
        self.uplink.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_downlink(&self, n: u64) {
        self.downlink.fetch_add(n, Ordering::Relaxed);
    }

    /// Read the counters and reset them to zero in one step.
    fn take(&self) -> Usage {
        Usage {
            uplink: self.uplink.swap(0, Ordering::Relaxed),
            downlink: self.downlink.swap(0, Ordering::Relaxed),
        }
    }

    fn read(&self) -> Usage {
        Usage {
            uplink: self.uplink.load(Ordering::Relaxed),
            downlink: self.downlink.load(Ordering::Relaxed),
        }
    }
}

/// Traffic for every user the endpoint has served since the last drain.
#[derive(Default)]
pub struct UserTraffic {
    users: RwLock<HashMap<Arc<str>, Arc<UserCounter>>>,
}

impl UserTraffic {
    pub fn new() -> Self {
        Self::default()
    }

    /// The counter to add this connection's traffic to.
    ///
    /// Called once per connection - the returned handle is what the hot path
    /// uses. Two connections by the same user share one counter, which is what
    /// makes their traffic add up.
    pub fn counter_for(&self, user: &Arc<str>) -> Arc<UserCounter> {
        // The common case is a user who already has a counter, so try to get
        // away with a read lock before taking a write one.
        if let Some(counter) = self.read().get(user) {
            return counter.clone();
        }
        self.write().entry(user.clone()).or_default().clone()
    }

    /// Take everything accumulated since the last call, leaving the counters at
    /// zero.
    ///
    /// Live connections keep their handles and go on adding to them, so nothing
    /// is lost by draining mid-connection: the bytes simply land in the next
    /// drain instead of this one.
    ///
    /// Users with nothing to report are dropped, so a user who disconnects and
    /// never returns stops costing memory. A user still connected is kept even
    /// at zero, because their handle is about to be used again.
    pub fn drain(&self) -> Vec<(Arc<str>, Usage)> {
        let mut collected = Vec::new();
        self.write().retain(|user, counter| {
            let usage = counter.take();
            if !usage.is_zero() {
                collected.push((user.clone(), usage));
            }
            // Anything but our own map entry holding the counter means a live
            // connection is still using it.
            Arc::strong_count(counter) > 1
        });
        collected
    }

    /// Read without resetting, for a status page or a test.
    pub fn snapshot(&self) -> Vec<(Arc<str>, Usage)> {
        self.read()
            .iter()
            .map(|(user, counter)| (user.clone(), counter.read()))
            .collect()
    }

    pub fn tracked_users(&self) -> usize {
        self.read().len()
    }

    // As in the authenticator: a poisoned lock recovers rather than panicking,
    // because losing traffic accounting is better than taking the endpoint down
    // and neither critical section can panic in the first place.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<Arc<str>, Arc<UserCounter>>> {
        self.users.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<Arc<str>, Arc<UserCounter>>> {
        self.users.write().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str) -> Arc<str> {
        Arc::from(name)
    }

    fn usage_of(drained: &[(Arc<str>, Usage)], name: &str) -> Option<Usage> {
        drained
            .iter()
            .find(|(u, _)| &**u == name)
            .map(|(_, usage)| *usage)
    }

    #[test]
    fn counts_each_direction_separately() {
        let traffic = UserTraffic::new();
        let alice = traffic.counter_for(&user("alice"));

        alice.add_uplink(100);
        alice.add_downlink(900);

        let drained = traffic.drain();
        assert_eq!(
            usage_of(&drained, "alice"),
            Some(Usage {
                uplink: 100,
                downlink: 900
            })
        );
    }

    #[test]
    fn traffic_from_two_connections_by_one_user_adds_up() {
        let traffic = UserTraffic::new();
        let name = user("alice");

        // Two connections, each taking its own handle.
        let first = traffic.counter_for(&name);
        let second = traffic.counter_for(&name);
        first.add_uplink(10);
        second.add_uplink(32);

        assert_eq!(usage_of(&traffic.drain(), "alice").map(|u| u.uplink), Some(42));
    }

    #[test]
    fn a_drain_takes_everything_once() {
        let traffic = UserTraffic::new();
        let alice = traffic.counter_for(&user("alice"));
        alice.add_uplink(50);

        assert_eq!(usage_of(&traffic.drain(), "alice").map(|u| u.uplink), Some(50));
        // The whole point: a panel that asks twice must not be told 50 twice.
        assert_eq!(usage_of(&traffic.drain(), "alice"), None);
    }

    #[test]
    fn a_live_connection_keeps_counting_after_a_drain() {
        let traffic = UserTraffic::new();
        let alice = traffic.counter_for(&user("alice"));

        alice.add_uplink(10);
        traffic.drain();
        alice.add_uplink(7);

        assert_eq!(usage_of(&traffic.drain(), "alice").map(|u| u.uplink), Some(7));
    }

    #[test]
    fn a_departed_user_stops_costing_memory() {
        let traffic = UserTraffic::new();
        {
            let alice = traffic.counter_for(&user("alice"));
            alice.add_uplink(10);
        } // connection ends, handle dropped

        // The first drain still reports the traffic...
        assert_eq!(usage_of(&traffic.drain(), "alice").map(|u| u.uplink), Some(10));
        // ...and then the entry goes, rather than accumulating one per user
        // the endpoint has ever seen.
        assert_eq!(traffic.tracked_users(), 0);
    }

    #[test]
    fn a_connected_user_is_kept_even_with_nothing_to_report() {
        let traffic = UserTraffic::new();
        let _alice = traffic.counter_for(&user("alice"));

        assert!(traffic.drain().is_empty());
        // Still connected, so the handle must stay valid to add to.
        assert_eq!(traffic.tracked_users(), 1);
    }

    #[test]
    fn users_are_kept_apart() {
        let traffic = UserTraffic::new();
        traffic.counter_for(&user("alice")).add_uplink(1);
        traffic.counter_for(&user("bob")).add_uplink(2);

        let drained = traffic.drain();
        assert_eq!(usage_of(&drained, "alice").map(|u| u.uplink), Some(1));
        assert_eq!(usage_of(&drained, "bob").map(|u| u.uplink), Some(2));
    }

    #[test]
    fn nothing_is_lost_when_a_drain_lands_mid_traffic() {
        // Draining happens on a timer while traffic is flowing, so no byte may
        // be counted twice or dropped between the two.
        let traffic = Arc::new(UserTraffic::new());
        let name = user("alice");

        let writers: Vec<_> = (0..4)
            .map(|_| {
                let traffic = traffic.clone();
                let name = name.clone();
                std::thread::spawn(move || {
                    let counter = traffic.counter_for(&name);
                    for _ in 0..5_000 {
                        counter.add_uplink(1);
                    }
                })
            })
            .collect();

        let mut total = 0;
        let drainer = {
            let traffic = traffic.clone();
            std::thread::spawn(move || {
                let mut seen = 0;
                for _ in 0..200 {
                    seen += traffic
                        .drain()
                        .iter()
                        .map(|(_, u)| u.uplink)
                        .sum::<u64>();
                    std::thread::yield_now();
                }
                seen
            })
        };

        for w in writers {
            w.join().expect("a writer panicked");
        }
        total += drainer.join().expect("the drainer panicked");
        total += traffic.drain().iter().map(|(_, u)| u.uplink).sum::<u64>();

        assert_eq!(total, 20_000, "every byte should be reported exactly once");
    }
}
