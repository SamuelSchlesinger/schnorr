use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use curve25519_dalek::RistrettoPoint;
use rand_core::{OsRng, RngCore};
use schnorr::{PrivateKey, PublicKey, Signature};

fn benchmark_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation", |b| {
        b.iter(|| {
            let _private_key: PrivateKey<RistrettoPoint> = PrivateKey::random(&mut OsRng);
        });
    });
}

fn benchmark_signing(c: &mut Criterion) {
    let private_key: PrivateKey<RistrettoPoint> = PrivateKey::random(&mut OsRng);

    // Create message of different sizes for benchmarking
    let small_message = [0u8; 64];
    let medium_message = [0u8; 1024];
    let large_message = [0u8; 8192];

    let mut group = c.benchmark_group("signing");

    group.bench_function("small_message", |b| {
        b.iter(|| private_key.sign(&small_message, &mut OsRng));
    });

    group.bench_function("medium_message", |b| {
        b.iter(|| private_key.sign(&medium_message, &mut OsRng));
    });

    group.bench_function("large_message", |b| {
        b.iter(|| private_key.sign(&large_message, &mut OsRng));
    });

    group.finish();
}

fn benchmark_verification(c: &mut Criterion) {
    // Generate new random messages for each iteration
    let mut group = c.benchmark_group("verification");

    group.bench_function("verify", |b| {
        b.iter_batched(
            || {
                // Setup: Create key pair and sign a random message
                let private_key: PrivateKey<RistrettoPoint> = PrivateKey::random(&mut OsRng);
                let public_key = private_key.public();

                let mut message = [0u8; 128];
                OsRng.fill_bytes(&mut message);

                let signature = private_key.sign(&message, &mut OsRng);

                (signature, message, public_key.clone())
            },
            |(signature, message, public_key)| {
                // The actual operation we're benchmarking
                signature.verify(&message, &public_key)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn benchmark_e2e(c: &mut Criterion) {
    c.bench_function("end_to_end", |b| {
        b.iter(|| {
            // Generate a key pair
            let private_key: PrivateKey<RistrettoPoint> = PrivateKey::random(&mut OsRng);

            // Create a random message
            let mut message = [0u8; 128];
            OsRng.fill_bytes(&mut message);

            // Sign the message
            let signature = private_key.sign(&message, &mut OsRng);

            // Verify the signature
            signature.verify(&message, private_key.public())
        });
    });
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_signing,
    benchmark_verification,
    benchmark_e2e
);
criterion_main!(benches);
