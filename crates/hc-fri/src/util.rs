use hc_core::field::FieldElement;

pub(crate) fn serialize_evaluations<F: FieldElement>(values: &[F]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(values.len() * core::mem::size_of::<u64>());
    for value in values {
        buffer.extend_from_slice(&value.to_u64().to_le_bytes());
    }
    buffer
}
