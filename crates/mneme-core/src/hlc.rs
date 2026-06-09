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
}
