//! Authentication cost: token checks, the per-request path, and sign-in.

use std::{hint::black_box, sync::Arc, time::Duration};

use auth_gate::*;
use criterion::{Criterion, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    let keys = GateKeys::derive(&[1; 32]).expect("keys");
    let gate = AuthGate::builder(GateKeys::derive(&[1; 32]).expect("keys"))
        .password_policy(PasswordPolicy::insecure_for_tests())
        .signals(Arc::new(NoSignals))
        .build()
        .expect("gate");
    gate.create_account("a@x.io", "benchmark password", Standing::Active, &[])
        .expect("account");
    let SignIn::Verified(v) = gate.sign_in("a@x.io", "benchmark password", &Presented::new())
    else {
        panic!("sign-in");
    };
    let client = Presented::new()
        .peer("192.0.2.1".parse().expect("ip"))
        .user_agent(Some(b"Mozilla/5.0 (bench)"));
    let issued = gate
        .issue(v, Payload::new(&[7; 120]).expect("payload"), &client)
        .expect("issue");
    let token = issued.token.as_str().to_owned();
    let mut forged = token.clone().into_bytes();
    forged[20] ^= 1;
    let forged = String::from_utf8(forged).unwrap_or_default();

    c.bench_function("token/check_valid", |b| {
        b.iter(|| check_token(black_box(&keys), black_box(token.as_bytes())))
    });
    c.bench_function("token/check_forged", |b| {
        b.iter(|| check_token(black_box(&keys), black_box(forged.as_bytes())))
    });
    let hit = client.token(Some(token.as_bytes()));
    c.bench_function("authenticate/member", |b| {
        b.iter(|| gate.authenticate(black_box(&hit)))
    });
    c.bench_function("authenticate/no_credential", |b| {
        b.iter(|| gate.authenticate(black_box(&client)))
    });
    let bad = client.token(Some(b"garbage"));
    c.bench_function("authenticate/malformed", |b| {
        b.iter(|| gate.authenticate(black_box(&bad)))
    });

    // Sign-in at the production cost (crypt-io's default Argon2id).
    let real = AuthGate::builder(GateKeys::derive(&[2; 32]).expect("keys"))
        .signals(Arc::new(NoSignals))
        .build()
        .expect("gate");
    real.create_account("a@x.io", "benchmark password", Standing::Active, &[])
        .expect("account");
    let mut g = c.benchmark_group("sign_in");
    g.sample_size(10).measurement_time(Duration::from_secs(10));
    g.bench_function("argon2id_default", |b| {
        b.iter(|| {
            real.sign_in(
                black_box("a@x.io"),
                black_box("benchmark password"),
                &Presented::new(),
            )
        })
    });
    g.bench_function("unknown_account", |b| {
        b.iter(|| {
            real.sign_in(
                black_box("nobody@x.io"),
                black_box("benchmark password"),
                &Presented::new(),
            )
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
