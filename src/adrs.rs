//! The 22-byte address that makes every hash call a distinct function.
//!
//! One buffer, two readings. On the stateless path the leading nine bytes are
//! a hypertree layer and tree address; on the stateful path they are a node
//! height and index in the FXMSS tree. The `type` byte then gives meaning to
//! the twelve-byte payload, and stateless and stateful type values are drawn
//! from disjoint ranges so the two can never collide.
//!
//! The layout is exactly SLH-DSA's compressed address `ADRS_c` of FIPS 205
//! Figure 18, which is what lets the stateless path reuse SLH-DSA unmodified.

/// Stateless address types.
pub const SL_WOTS_TW_HASH: u8 = 0;
pub const SL_WOTS_TW_PK: u8 = 1;
pub const SL_XMSS_TREE: u8 = 2;
pub const SL_FORS_TREE: u8 = 3;
pub const SL_FORS_ROOTS: u8 = 4;
pub const SL_WOTS_TW_PRF: u8 = 5;
pub const SL_FORS_PRF: u8 = 6;

/// Stateful address types. Disjoint from the stateless values above.
pub const SF_WOTS_C_HASH: u8 = 16;
pub const SF_WOTS_C_PK: u8 = 17;
pub const SF_FXMSS_TREE: u8 = 18;
pub const SF_WOTS_C_PRF: u8 = 21;
pub const SF_WOTS_C_GRIND: u8 = 22;

pub const ADRS_SIZE: usize = 22;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Adrs(pub [u8; ADRS_SIZE]);

impl Default for Adrs {
    fn default() -> Self {
        Adrs([0u8; ADRS_SIZE])
    }
}

impl Adrs {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_bytes(&self) -> &[u8; ADRS_SIZE] {
        &self.0
    }

    // --- leading nine bytes, stateless reading ---------------------------
    pub fn set_layer(&mut self, layer: u8) -> &mut Self {
        self.0[0] = layer;
        self
    }
    pub fn set_tree_address(&mut self, tree: u64) -> &mut Self {
        self.0[1..9].copy_from_slice(&tree.to_be_bytes());
        self
    }

    // --- leading nine bytes, stateful reading ----------------------------
    pub fn set_node_height(&mut self, height: u8) -> &mut Self {
        self.0[0] = height;
        self
    }
    pub fn node_height(&self) -> u8 {
        self.0[0]
    }
    pub fn set_node_index(&mut self, index: u64) -> &mut Self {
        self.0[1..9].copy_from_slice(&index.to_be_bytes());
        self
    }

    // --- type and payload -------------------------------------------------
    pub fn set_type(&mut self, ty: u8) -> &mut Self {
        self.0[9] = ty;
        self
    }
    /// Payload bytes 0..4, the keypair index on the stateless path.
    pub fn set_payload0(&mut self, v: u32) -> &mut Self {
        self.0[10..14].copy_from_slice(&v.to_be_bytes());
        self
    }
    pub fn zero_payload0(&mut self) -> &mut Self {
        self.0[10..14].fill(0);
        self
    }
    /// The two structure bytes that bind an FXMSS tree shape into key derivation.
    pub fn set_structure(&mut self, structure: [u8; 2]) -> &mut Self {
        self.0[10..12].copy_from_slice(&structure);
        self
    }
    pub fn structure(&self) -> [u8; 2] {
        [self.0[10], self.0[11]]
    }
    /// Payload bytes 4..8: chain index, or tree height.
    pub fn set_payload1(&mut self, v: u32) -> &mut Self {
        self.0[14..18].copy_from_slice(&v.to_be_bytes());
        self
    }
    /// Payload bytes 8..12: hash index, or tree index.
    pub fn set_payload2(&mut self, v: u32) -> &mut Self {
        self.0[18..22].copy_from_slice(&v.to_be_bytes());
        self
    }
    pub fn zero_payload12(&mut self) -> &mut Self {
        self.0[14..22].fill(0);
        self
    }
    pub fn zero_payload(&mut self) -> &mut Self {
        self.0[10..22].fill(0);
        self
    }
}
