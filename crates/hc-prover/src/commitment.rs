use ark_bn254::G1Projective;
use ark_serialize::CanonicalSerialize;
use hc_hash::{hash::HashDigest, Blake3, HashFunction};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitmentScheme {
    Stark,
    Kzg,
}

#[derive(Clone, Debug)]
pub enum Commitment {
    Stark { root: HashDigest },
    Kzg { points: Vec<G1Projective> },
}

impl CommitmentScheme {
    pub fn from_label(label: &str) -> Option<Self> {
        match label.to_ascii_lowercase().as_str() {
            "stark" | "merkle" => Some(Self::Stark),
            "kzg" => Some(Self::Kzg),
            _ => None,
        }
    }
}

impl Commitment {
    pub fn scheme(&self) -> CommitmentScheme {
        match self {
            Commitment::Stark { .. } => CommitmentScheme::Stark,
            Commitment::Kzg { .. } => CommitmentScheme::Kzg,
        }
    }

    pub fn as_root(&self) -> Option<HashDigest> {
        match self {
            Commitment::Stark { root } => Some(*root),
            Commitment::Kzg { .. } => None,
        }
    }
}

pub fn commitment_digest(commitment: &Commitment) -> HashDigest {
    match commitment {
        Commitment::Stark { root } => *root,
        Commitment::Kzg { points } => {
            let mut bytes = Vec::with_capacity(points.len() * 96);
            for point in points {
                point
                    .serialize_compressed(&mut bytes)
                    .expect("serialization should succeed");
            }
            Blake3::hash(&bytes)
        }
    }
}
