//! Minimal 256-bit unsigned integer — only the operations the stake target check
//! needs, implemented from scratch so the consensus math carries no third-party
//! dependency and can be audited in one sitting.
//!
//! Layout matches Divi's `uint256`: four 64-bit limbs, least-significant first,
//! which is also the byte order the kernel hash is compared in.

use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct U256(pub [u64; 4]); // limb 0 = least significant

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);

    pub fn from_u64(v: u64) -> Self {
        U256([v, 0, 0, 0])
    }

    /// Interpret 32 little-endian bytes (the internal order of a Divi `uint256`,
    /// i.e. the raw hash bytes, NOT the reversed form shown in block explorers).
    pub fn from_le_bytes(b: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[i * 8..i * 8 + 8]);
            *limb = u64::from_le_bytes(w);
        }
        U256(limbs)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u64; 4]
    }

    /// Shift left by `bits`; returns None if any set bit would be shifted out.
    pub fn checked_shl(self, bits: u32) -> Option<Self> {
        if bits >= 256 {
            return if self.is_zero() { Some(U256::ZERO) } else { None };
        }
        let limb_shift = (bits / 64) as usize;
        let bit_shift = bits % 64;
        let mut out = [0u64; 4];
        for i in (0..4).rev() {
            let src = self.0[i];
            if src == 0 {
                continue;
            }
            let dst = i + limb_shift;
            let hi = if bit_shift == 0 { 0 } else { src >> (64 - bit_shift) };
            let lo = src << bit_shift;
            // any portion landing beyond limb 3 is an overflow
            if dst > 3 || (hi != 0 && dst + 1 > 3) {
                return None;
            }
            out[dst] |= lo;
            if hi != 0 {
                out[dst + 1] |= hi;
            }
        }
        Some(U256(out))
    }

    /// Multiply by a 64-bit value; returns None on overflow (mirrors Divi's
    /// `uint256::MultiplyBy` returning false, which the staking code treats as
    /// "target is effectively unbounded", i.e. an automatic hit on regtest).
    pub fn checked_mul_u64(self, rhs: u64) -> Option<Self> {
        if rhs == 0 || self.is_zero() {
            return Some(U256::ZERO);
        }
        let mut out = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let prod = (self.0[i] as u128) * (rhs as u128) + carry;
            out[i] = prod as u64;
            carry = prod >> 64;
        }
        if carry != 0 {
            return None;
        }
        Some(U256(out))
    }

    /// Bitcoin/Divi "compact" (nBits) representation → full 256-bit target.
    /// Mirrors `uint256::SetCompact`. The sign bit is not meaningful for a
    /// difficulty target; an overflowing exponent yields None.
    pub fn set_compact(compact: u32) -> Option<Self> {
        let size = (compact >> 24) as u32;
        let mut word = (compact & 0x007f_ffff) as u64;
        if size <= 3 {
            word >>= 8 * (3 - size);
            Some(U256::from_u64(word))
        } else {
            U256::from_u64(word).checked_shl(8 * (size - 3))
        }
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        // compare most-significant limb first
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_by_magnitude() {
        assert!(U256::from_u64(1) < U256::from_u64(2));
        assert!(U256([0, 1, 0, 0]) > U256([u64::MAX, 0, 0, 0]));
        assert_eq!(U256::from_u64(7), U256::from_u64(7));
    }

    #[test]
    fn shl_matches_multiplication_and_detects_overflow() {
        assert_eq!(U256::from_u64(1).checked_shl(0).unwrap(), U256::from_u64(1));
        assert_eq!(U256::from_u64(1).checked_shl(64).unwrap(), U256([0, 1, 0, 0]));
        assert_eq!(U256::from_u64(1).checked_shl(255).unwrap(), U256([0, 0, 0, 1 << 63]));
        assert_eq!(U256::from_u64(1).checked_shl(256), None);
        assert_eq!(U256::from_u64(1).checked_shl(1).unwrap(), U256::from_u64(2));
        // a bit shifted off the top is an overflow, not a silent wrap
        assert_eq!(U256([0, 0, 0, 1 << 63]).checked_shl(1), None);
    }

    #[test]
    fn mul_carries_across_limbs_and_detects_overflow() {
        assert_eq!(U256::from_u64(3).checked_mul_u64(4).unwrap(), U256::from_u64(12));
        // u64::MAX * 2 must carry into limb 1, not wrap
        assert_eq!(
            U256::from_u64(u64::MAX).checked_mul_u64(2).unwrap(),
            U256([u64::MAX - 1, 1, 0, 0])
        );
        assert_eq!(U256::from_u64(0).checked_mul_u64(9).unwrap(), U256::ZERO);
        // overflowing the top limb reports None (the "always hits" case)
        assert_eq!(U256([0, 0, 0, 1 << 63]).checked_mul_u64(4), None);
    }

    #[test]
    fn set_compact_matches_bitcoin_reference_vectors() {
        // Canonical Bitcoin SetCompact vectors — Divi inherits this format.
        // Note the mantissa is the full low 3 bytes, and for size <= 3 it is
        // shifted DOWN, which is easy to get backwards.
        assert_eq!(U256::set_compact(0x0100_3456).unwrap(), U256::ZERO);
        assert_eq!(U256::set_compact(0x0112_3456).unwrap(), U256::from_u64(0x12));
        assert_eq!(U256::set_compact(0x0200_8000).unwrap(), U256::from_u64(0x80));
        assert_eq!(U256::set_compact(0x0500_9234).unwrap(), U256::from_u64(0x9234_0000));
        assert_eq!(U256::set_compact(0x0412_3456).unwrap(), U256::from_u64(0x1234_5600));

        // The difficulty-1 target: 0xffff shifted left by 8*(0x1d-3) = 208 bits,
        // which lands in the most-significant limb.
        assert_eq!(
            U256::set_compact(0x1d00_ffff).unwrap(),
            U256([0, 0, 0, 0x0000_0000_ffff_0000])
        );
    }

    #[test]
    fn from_le_bytes_reads_internal_order() {
        let mut b = [0u8; 32];
        b[0] = 1; // least significant byte
        assert_eq!(U256::from_le_bytes(&b), U256::from_u64(1));
        let mut b2 = [0u8; 32];
        b2[31] = 0x80; // most significant bit
        assert_eq!(U256::from_le_bytes(&b2), U256([0, 0, 0, 1 << 63]));
    }
}
