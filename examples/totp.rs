//! Enrol TOTP, then sign in with password and code.
//!
//! Run with `cargo run --example totp`.

use auth_gate::{
    AuthGate, GateKeys, PasswordPolicy, Payload, Presented, SignIn, Standing, totp_now,
};

fn main() -> Result<(), auth_gate::AuthError> {
    let gate = AuthGate::builder(GateKeys::derive(&[5u8; 32])?)
        .password_policy(PasswordPolicy::insecure_for_tests())
        .build()?;
    let user = gate.create_account(
        "alice@example.com",
        "correct horse battery",
        Standing::Active,
        &[],
    )?;

    let secret = gate.enroll_totp(user)?;
    println!(
        "scan this: {}",
        secret.uri("Example", "alice@example.com").as_str()
    );
    let first = totp_now(&secret, gate.now())?;
    println!("confirmed: {}", gate.confirm_totp(user, &first)?);

    let client = Presented::new();
    let SignIn::NeedsSecondFactor(challenge) =
        gate.sign_in("alice@example.com", "correct horse battery", &client)
    else {
        println!("expected a second-factor step");
        return Ok(());
    };
    println!("password ok, asking for the code");
    // The same code cannot be used twice: wait for the next 30-second step.
    let code = loop {
        let c = totp_now(&secret, gate.now())?;
        if c != first {
            break c;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    };
    match gate.second_factor(&challenge.to_text(), &code, &client) {
        SignIn::Verified(v) => {
            let issued = gate.issue(v, Payload::EMPTY, &client)?;
            println!("signed in, session {}", issued.record.id);
        }
        other => println!("refused: {other:?}"),
    }
    Ok(())
}
