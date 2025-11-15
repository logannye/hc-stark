use hc_core::field::FieldElement;

use crate::hash::{HashDigest, HashFunction};

const U64_BYTES: usize = core::mem::size_of::<u64>();

pub struct Transcript<H: HashFunction> {
    state: H::State,
    counter: u64,
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
        F::from_u64(self.challenge_u64(label))
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
    use hc_core::field::prime_field::GoldilocksField;

    use super::*;
    use crate::blake3::Blake3;

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
}
