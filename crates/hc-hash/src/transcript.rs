use hc_core::field::FieldElement;

use crate::hash::{HashDigest, HashFunction};

const U64_BYTES: usize = core::mem::size_of::<u64>();

pub struct Transcript<H: HashFunction> {
    state: H::State,
    counter: u64,
}

impl<H: HashFunction> Clone for Transcript<H> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            counter: self.counter,
        }
    }
}

impl<H: HashFunction> Transcript<H> {
    pub fn new(domain: impl AsRef<[u8]>) -> Self {
        let mut state = H::new();
        frame::<H>(&mut state, b"domain", domain.as_ref());
        Self { state, counter: 0 }
    }

    pub fn append_message(&mut self, label: impl AsRef<[u8]>, data: impl AsRef<[u8]>) {
        frame::<H>(&mut self.state, label.as_ref(), data.as_ref());
    }

    pub fn challenge_bytes(&mut self, label: impl AsRef<[u8]>) -> HashDigest {
        let mut state = self.state.clone();
        let counter_bytes = self.counter.to_le_bytes();
        self.counter += 1;
        frame::<H>(&mut state, label.as_ref(), &counter_bytes);
        H::finalize(state)
    }

    pub fn challenge_u64(&mut self, label: impl AsRef<[u8]>) -> u64 {
        let digest = self.challenge_bytes(label);
        let mut buf = [0u8; U64_BYTES];
        buf.copy_from_slice(&digest.as_bytes()[..U64_BYTES]);
        u64::from_le_bytes(buf)
    }

    pub fn challenge_field<F: FieldElement>(&mut self, label: impl AsRef<[u8]>) -> F {
        let digest = self.challenge_bytes(label);
        let bytes = digest.as_bytes();
        let deg = F::EXTENSION_DEGREE;
        debug_assert!(
            deg >= 1 && deg * U64_BYTES <= bytes.len(),
            "extension degree too large for digest"
        );
        let mut limbs = [0u64; 4];
        for (i, slot) in limbs.iter_mut().enumerate().take(deg) {
            let mut buf = [0u8; U64_BYTES];
            buf.copy_from_slice(&bytes[i * U64_BYTES..(i + 1) * U64_BYTES]);
            *slot = u64::from_le_bytes(buf);
        }
        F::from_base_u64s(&limbs[..deg])
    }
}

fn frame<H: HashFunction>(state: &mut H::State, label: &[u8], data: &[u8]) {
    let label_len = (label.len() as u64).to_le_bytes();
    let data_len = (data.len() as u64).to_le_bytes();
    H::update(state, &label_len);
    H::update(state, label);
    H::update(state, &data_len);
    H::update(state, data);
}

#[cfg(test)]
mod tests {
    use hc_core::field::{
        extension::QuadExtension, prime_field::GoldilocksField, FieldElement,
    };

    use super::*;
    use crate::blake3::Blake3;

    type K = QuadExtension<GoldilocksField>;

    #[test]
    fn transcript_produces_deterministic_challenges() {
        let mut transcript_a = Transcript::<Blake3>::new("hc-stark");
        transcript_a.append_message("public_input", b"123");
        let mut transcript_b = Transcript::<Blake3>::new("hc-stark");
        transcript_b.append_message("public_input", b"123");

        assert_eq!(
            transcript_a.challenge_bytes("beta"),
            transcript_b.challenge_bytes("beta")
        );
    }

    #[test]
    fn transcript_field_challenge_maps_into_field() {
        let mut transcript = Transcript::<Blake3>::new("hc-stark");
        transcript.append_message("msg", b"abc");
        let challenge: GoldilocksField = transcript.challenge_field("alpha");
        assert!(!challenge.is_zero());
    }

    // -----------------------------------------------------------------------
    // Task 7b-0: extension-aware challenge tests
    // -----------------------------------------------------------------------

    /// v3 unchanged: base-field challenge_field uses the first 8 bytes of the
    /// digest, byte-for-byte identical to the old `F::from_u64(challenge_u64(label))`.
    #[test]
    fn base_field_challenge_unchanged_from_v3() {
        // Transcript A: use challenge_field (new code path).
        let mut t_a = Transcript::<Blake3>::new("hc-stark-v3-compat");
        t_a.append_message("seed", b"determinism-test");
        let field_challenge: GoldilocksField = t_a.challenge_field("alpha");

        // Transcript B: manually squeeze challenge_bytes and take first 8 bytes,
        // which is exactly what the old `challenge_u64` + `from_u64` did.
        let mut t_b = Transcript::<Blake3>::new("hc-stark-v3-compat");
        t_b.append_message("seed", b"determinism-test");
        let digest = t_b.challenge_bytes("alpha");
        let bytes = digest.as_bytes();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[..8]);
        let manual: GoldilocksField = GoldilocksField::from_u64(u64::from_le_bytes(buf));

        assert_eq!(
            field_challenge, manual,
            "base-field challenge_field must be byte-identical to the old from_u64(challenge_u64) path"
        );
    }

    /// K full entropy: challenge_field::<K> fills c0 from bytes[0..8] and c1
    /// from bytes[8..16] independently, and at least one challenge has c1 != 0.
    #[test]
    fn extension_field_challenge_fills_both_limbs() {
        let mut t = Transcript::<Blake3>::new("hc-stark-ext");
        t.append_message("seed", b"extension-entropy");

        // Squeeze the digest independently to check the layout.
        let mut t_ref = Transcript::<Blake3>::new("hc-stark-ext");
        t_ref.append_message("seed", b"extension-entropy");

        let k_challenge: K = t.challenge_field("fri-alpha");
        let digest = t_ref.challenge_bytes("fri-alpha");
        let bytes = digest.as_bytes();

        let expected_c0 = GoldilocksField::from_u64(u64::from_le_bytes(bytes[0..8].try_into().unwrap()));
        let expected_c1 = GoldilocksField::from_u64(u64::from_le_bytes(bytes[8..16].try_into().unwrap()));

        assert_eq!(
            k_challenge.c0, expected_c0,
            "c0 must come from bytes[0..8]"
        );
        assert_eq!(
            k_challenge.c1, expected_c1,
            "c1 must come from bytes[8..16]"
        );
    }

    /// K challenges have c1 != 0 for at least one of several distinct labels,
    /// confirming independent entropy (not always-zero like the old path).
    #[test]
    fn extension_field_challenge_nonzero_c1() {
        let labels = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let mut t = Transcript::<Blake3>::new("hc-stark-ext-entropy");
        t.append_message("seed", b"nonzero-c1-check");

        let mut found_nonzero_c1 = false;
        for label in &labels {
            let k: K = t.challenge_field(label);
            if !k.c1.is_zero() {
                found_nonzero_c1 = true;
                break;
            }
        }
        assert!(
            found_nonzero_c1,
            "at least one K challenge across several labels must have c1 != 0"
        );
    }

    /// Determinism: same seed produces identical K challenges.
    #[test]
    fn extension_field_challenge_is_deterministic() {
        let mut t_a = Transcript::<Blake3>::new("hc-stark-det");
        t_a.append_message("pub", b"xyz");
        let mut t_b = Transcript::<Blake3>::new("hc-stark-det");
        t_b.append_message("pub", b"xyz");

        let ka: K = t_a.challenge_field("round-0");
        let kb: K = t_b.challenge_field("round-0");
        assert_eq!(ka, kb, "same seed must produce identical K challenges");
    }
}
