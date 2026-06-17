use crate::MnemeError;

/// 128-bit node identifier for HLC (§5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub [u8; 16]);

impl NodeId {
    pub fn random() -> Self {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf).expect("getrandom");
        Self(buf)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Hybrid logical clock (Kulkarni et al., blueprint §5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u32,
    pub node_id: NodeId,
}

impl Hlc {
    pub fn zero(node_id: NodeId) -> Self {
        Self {
            wall_ms: 0,
            counter: 0,
            node_id,
        }
    }

    /// Local event: `wall = max(now_ms, last.wall)`, counter per §5.4.
    pub fn tick_local(&mut self, now_ms: u64) {
        let wall = now_ms.max(self.wall_ms);
        if wall == self.wall_ms {
            self.counter = self.counter.saturating_add(1);
        } else {
            self.wall_ms = wall;
            self.counter = 0;
        }
    }

    /// Merge against a remote HLC on receive (§5.4).
    pub fn merge_remote(&mut self, remote: &Hlc) {
        match remote.wall_ms.cmp(&self.wall_ms) {
            std::cmp::Ordering::Greater => {
                self.wall_ms = remote.wall_ms;
                self.counter = remote.counter.saturating_add(1);
            }
            std::cmp::Ordering::Equal => {
                self.counter = self.counter.max(remote.counter).saturating_add(1);
            }
            std::cmp::Ordering::Less => {
                self.counter = self.counter.saturating_add(1);
            }
        }
    }

    /// Opaque ordered bytes for root high-water mark (14 bytes, §5.7).
    pub fn to_bytes(&self) -> [u8; 14] {
        let mut out = [0u8; 14];
        out[0..8].copy_from_slice(&self.wall_ms.to_le_bytes());
        out[8..12].copy_from_slice(&self.counter.to_le_bytes());
        out[12..14].copy_from_slice(&self.node_id.0[..2]);
        out
    }

    pub fn from_bytes(bytes: &[u8; 14], node_id: NodeId) -> Result<Self, MnemeError> {
        let wall_ms = u64::from_le_bytes(bytes[0..8].try_into().expect("slice"));
        let counter = u32::from_le_bytes(bytes[8..12].try_into().expect("slice"));
        Ok(Self {
            wall_ms,
            counter,
            node_id,
        })
    }

    /// Compare for monotonic ordering (replay defense, INV-6).
    pub fn is_before(&self, other: &Self) -> bool {
        (self.wall_ms, self.counter, &self.node_id.0)
            < (other.wall_ms, other.counter, &other.node_id.0)
    }
}

/// Compare two 14-byte HLC wire forms (§5.7) in numeric monotonic order.
///
/// `Root::hlc_max` is little-endian for `wall_ms`/`counter`; lexicographic
/// `[u8;14]` compare is wrong across byte boundaries (e.g. 255 vs 256).
pub fn cmp_wire(a: &[u8; 14], b: &[u8; 14]) -> std::cmp::Ordering {
    let wall_a = u64::from_le_bytes(a[0..8].try_into().expect("hlc wall"));
    let wall_b = u64::from_le_bytes(b[0..8].try_into().expect("hlc wall"));
    match wall_a.cmp(&wall_b) {
        std::cmp::Ordering::Equal => {}
        ord => return ord,
    }
    let counter_a = u32::from_le_bytes(a[8..12].try_into().expect("hlc counter"));
    let counter_b = u32::from_le_bytes(b[8..12].try_into().expect("hlc counter"));
    match counter_a.cmp(&counter_b) {
        std::cmp::Ordering::Equal => {}
        ord => return ord,
    }
    a[12..14].cmp(&b[12..14])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hlc_local_tick_uses_max_wall() {
        let node = NodeId([1; 16]);
        let mut hlc = Hlc {
            wall_ms: 100,
            counter: 5,
            node_id: node,
        };
        hlc.tick_local(50);
        assert_eq!(hlc.wall_ms, 100);
        assert_eq!(hlc.counter, 6);

        hlc.tick_local(200);
        assert_eq!(hlc.wall_ms, 200);
        assert_eq!(hlc.counter, 0);
    }

    #[test]
    fn cmp_wire_orders_wall_ms_not_lexicographic() {
        let low = Hlc {
            wall_ms: 255,
            counter: 0,
            node_id: NodeId([0; 16]),
        }
        .to_bytes();
        let high = Hlc {
            wall_ms: 256,
            counter: 0,
            node_id: NodeId([0; 16]),
        }
        .to_bytes();
        assert_eq!(cmp_wire(&low, &high), std::cmp::Ordering::Less);
        assert_ne!(cmp_wire(&low, &high), low.cmp(&high));
    }

    #[test]
    fn hlc_merge_remote_kulkarni() {
        let node_a = NodeId([0xAA; 16]);
        let node_b = NodeId([0xBB; 16]);
        let mut local = Hlc {
            wall_ms: 100,
            counter: 2,
            node_id: node_a,
        };
        let remote = Hlc {
            wall_ms: 150,
            counter: 3,
            node_id: node_b,
        };
        local.merge_remote(&remote);
        assert_eq!(local.wall_ms, 150);
        assert_eq!(local.counter, 4);
    }

    /// INV-HLC-1: tick_local must be monotonically non-decreasing even when
    /// the wall clock jumps backward (e.g. NTP slew, VM clock warp).
    #[test]
    fn hlc_tick_local_skew_backward_never_decreases() {
        let node = NodeId([0xCC; 16]);
        let mut hlc = Hlc::zero(node);
        hlc.tick_local(1_000);
        let after_first = hlc;
        // Simulate a backward skew of 500 ms.
        hlc.tick_local(500);
        // The HLC must NOT have gone backward (hlc >= after_first).
        assert!(
            !hlc.is_before(&after_first),
            "HLC must not decrease under backward wall-clock skew: got {:?} < {:?}",
            hlc,
            after_first
        );
        assert_eq!(hlc.wall_ms, 1_000, "wall_ms must not drop below last seen");
        // Counter must have advanced (same wall_ms bucket).
        assert_eq!(hlc.counter, after_first.counter + 1);
    }

    /// INV-HLC-2: repeated tick_local calls produce a strictly increasing sequence
    /// when the wall clock is non-decreasing.
    #[test]
    fn hlc_tick_local_monotonic_increasing_sequence() {
        let node = NodeId([0xDD; 16]);
        let mut hlc = Hlc::zero(node);
        let mut prev = hlc;
        for ms in [100u64, 100, 100, 200, 200, 300] {
            hlc.tick_local(ms);
            assert!(
                prev.is_before(&hlc) || prev == hlc,
                "HLC must be non-decreasing across tick_local calls"
            );
            assert!(
                prev.is_before(&hlc),
                "each tick must strictly advance the HLC"
            );
            prev = hlc;
        }
    }

    /// INV-HLC-3: merge_remote with a lagging remote (remote.wall < local.wall)
    /// must not decrease local. Counter still advances by 1.
    #[test]
    fn hlc_merge_remote_lagging_peer_advances_counter() {
        let node_a = NodeId([0xEE; 16]);
        let node_b = NodeId([0xFF; 16]);
        let mut local = Hlc {
            wall_ms: 500,
            counter: 7,
            node_id: node_a,
        };
        let before = local;
        let lagging = Hlc {
            wall_ms: 100, // far behind
            counter: 999,
            node_id: node_b,
        };
        local.merge_remote(&lagging);
        assert_eq!(local.wall_ms, 500, "wall must stay at local max");
        assert_eq!(local.counter, 8, "counter must increment by 1");
        assert!(before.is_before(&local), "merge must advance the HLC");
    }

    /// INV-HLC-4: merge_remote equal-wall path must take max(counter) + 1.
    #[test]
    fn hlc_merge_remote_equal_wall_takes_max_counter_plus_one() {
        let node_a = NodeId([0x11; 16]);
        let node_b = NodeId([0x22; 16]);
        // Local counter > remote counter.
        let mut local = Hlc {
            wall_ms: 300,
            counter: 10,
            node_id: node_a,
        };
        let remote = Hlc {
            wall_ms: 300,
            counter: 5,
            node_id: node_b,
        };
        local.merge_remote(&remote);
        assert_eq!(local.counter, 11, "equal-wall: must take max(10,5)+1 = 11");

        // Remote counter > local counter.
        let mut local2 = Hlc {
            wall_ms: 300,
            counter: 3,
            node_id: node_a,
        };
        local2.merge_remote(&remote);
        assert_eq!(local2.counter, 6, "equal-wall: must take max(3,5)+1 = 6");
    }

    /// INV-HLC-5: `is_before` is total-order transitive.
    #[test]
    fn hlc_is_before_transitive() {
        let node = NodeId([0x33; 16]);
        let mut a = Hlc::zero(node);
        a.tick_local(100);
        let mut b = a;
        b.tick_local(100);
        let mut c = b;
        c.tick_local(200);
        assert!(a.is_before(&b), "a < b");
        assert!(b.is_before(&c), "b < c");
        assert!(a.is_before(&c), "a < c (transitivity)");
    }
}
