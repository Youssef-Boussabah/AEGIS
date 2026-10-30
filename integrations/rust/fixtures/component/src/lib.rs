//! AEGIS-owned release fixture. Its Cargo profile disables overflow checks,
//! so these integer additions have modular semantics. No third-party code/assets.

#[inline(never)]
pub fn mix(a: u32, b: u32) -> u32 {
    a + b + a.rotate_left(7)
}

#[inline(never)]
pub fn wide(a: u64, b: u64) -> u64 {
    a + b + 0x9e3779b97f4a7c15
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;

    #[test]
    fn edges() {
        for a in [0u32, 1, 127, 255, 1 << 31, u32::MAX] {
            for b in [0u32, 1, 255, u32::MAX] {
                let expected = ((a as u64 + b as u64 + a.rotate_left(7) as u64)
                    & 0xffff_ffff) as u32;
                assert_eq!(mix(black_box(a), black_box(b)), expected);
            }
        }
    }

    #[test]
    fn exhaustive_bytes() {
        for a in 0..=255u32 {
            for b in 0..=255u32 {
                assert_eq!(mix(black_box(a), black_box(b)), a + b + (a << 7));
            }
        }
    }

    #[test]
    fn wide_edges_and_seeded_pairs() {
        let mut state = 0x123456789abcdef0u64;
        for a in [0, 1, 1 << 63, u64::MAX] {
            for b in [0, 1, u64::MAX] {
                let expected = ((a as u128 + b as u128 + 0x9e3779b97f4a7c15u128)
                    & u64::MAX as u128) as u64;
                assert_eq!(wide(black_box(a), black_box(b)), expected);
            }
        }
        for _ in 0..100_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let b = state.rotate_left(29);
            let expected = ((state as u128 + b as u128 + 0x9e3779b97f4a7c15u128)
                & u64::MAX as u128) as u64;
            assert_eq!(wide(black_box(state), black_box(b)), expected);
        }
    }

    #[test]
    fn cargo_compile_metadata() {
        assert_eq!(env!("CARGO_PKG_NAME"), "aegis-rust-component");
    }
}
