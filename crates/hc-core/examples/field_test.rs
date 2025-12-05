use hc_core::field::{prime_field::GoldilocksField, FieldElement};

fn main() {
    let a = GoldilocksField::new(42);
    let b = GoldilocksField::new(17);

    let sum = a.add(b);
    let diff = a.sub(b);
    let product = a.mul(b);
    let inverse = b.inverse().expect("b should be invertible");
    let identity = b.mul(inverse);

    println!("a + b = {}", sum.to_u64());
    println!("a - b = {}", diff.to_u64());
    println!("a * b = {}", product.to_u64());
    println!("b^-1 = {}", inverse.to_u64());
    println!("b * b^-1 = {}", identity.to_u64());
}
