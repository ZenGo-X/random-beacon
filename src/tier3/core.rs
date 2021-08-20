//! # Tier 3 protocol defined as a sequence of computations
//!
//! ## Setup
//!
//! 1. Initial seed $σ_0$
//! 2. Random oracle $H$ (we fix it to sha2_512)
//!
//! ## Protocol
//!
//! ### 0. Obtain the seed
//!
//! Seed is 64 bytes that come from output of tiers 1 or 2. Seed is updated every time the protocol
//! outputs new randomness.
//!
//! ```rust
//! # use random_beacon::tier3::core::*;
//! # let cryptographically_strong_seed = [0; 64];
//! let mut seed = Tier3Seed::initial(cryptographically_strong_seed);
//! ```
//!
//! ### 1. Generate and publish local key
//!
//! Every party generates local [secret key](SecretKey), and publish their public keys
//!
//! ```rust
//! # fn publish<T>(_: &T) {}
//! use random_beacon::vrf::SecretKey;
//! let sk_i = SecretKey::generate();
//! publish(&sk_i.public_key());
//! ```
//!
//! ### 2. Receive others' public keys
//!
//! Complete keygen by receiving published public keys
//!
//! ```rust,no_run
//! # use random_beacon::tier3::core::*;
//! # use random_beacon::vrf::*;
//! # fn receive<T>() -> T { unimplemented!() }
//! # fn main() -> Result<(), InvalidSetup> {
//! # let sk_i = SecretKey::generate();
//! #
//! let pk: Vec<PublicKey> = receive();
//! let rounds_limit = 25; // any reasonable limit is fine
//! let setup = ProtocolSetup::new(sk_i, pk, rounds_limit);
//! #
//! # Ok(()) }
//! ```
//!
//! ### 3. Generate randomness
//!
//! Generate randomness locally and broadcast it
//!
//! > Note: if `proceed_locally` results into `ProceedError::RoundsLimitExceeded`, go to step 0.
//!
//! ```rust,no_run
//! # use random_beacon::tier3::core::*;
//! # use random_beacon::vrf::*;
//! # fn publish<T>(_: &T) {}
//! # fn main() -> Result<(), ProceedError> {
//! # let (setup, seed) = unimplemented!();
//! #
//! let local_randomness = proceed_locally(&setup, &seed)?;
//! publish(&local_randomness);
//! #
//! # Ok(()) }
//! ```
//!
//! Receive randomness from other parties, and combine them
//!
//! ```rust,no_run
//! # use random_beacon::tier3::core::*;
//! # use random_beacon::vrf::*;
//! # fn receive<T>() -> T { unimplemented!() }
//! # fn main() -> Result<(), CombineError> {
//! # let (setup, mut seed) = unimplemented!();
//! #
//! let board = receive::<Msgs<VerifiableRandomness>>();
//! let (randomness, next_seed) = combine(&setup, seed, &board)?;
//! seed = next_seed;
//! #
//! # Ok(()) }
//! ```
//!
//! Repeat step 3 until you reach rounds limit.

use sha2::{Digest, Sha512};

use crate::vrf::{PublicKey, SecretKey, VerifiableRandomness};

pub use crate::tier1::core::Msgs;

#[derive(Clone)]
pub struct ProtocolSetup {
    /// List of parties' public keys
    ///
    /// $pk_i$ corresponds to public key of $\ith$ party
    ///
    /// `setup.pk[setup.i]` must be equal to `setup.pk_i`
    pub pk: Vec<PublicKey>,
    /// Local party secret key
    pub sk_i: SecretKey,
    /// Maximum number of rounds
    ///
    /// After exceeding round limit, parties must regenerate secret keys and issue new randomness seed
    pub rounds_limit: u16,
}

impl ProtocolSetup {
    pub fn new(
        sk_i: SecretKey,
        pk: Vec<PublicKey>,
        rounds_limit: u16,
    ) -> Result<Self, InvalidSetup> {
        if pk.is_empty() {
            return Err(InvalidSetup::EmptyPk);
        }
        pk.iter()
            .find(|pk_i| **pk_i == sk_i.public_key())
            .ok_or(InvalidSetup::PkDoesntIncludeLocalPartyPublicKey)?;

        Ok(ProtocolSetup {
            pk,
            sk_i,
            rounds_limit,
        })
    }
}

#[derive(Debug, Clone)]
pub enum InvalidSetup {
    EmptyPk,
    PkDoesntIncludeLocalPartyPublicKey,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tier3Seed {
    r: u16,
    seed: [u8; 64],
}

impl Tier3Seed {
    pub fn initial(seed: [u8; 64]) -> Self {
        Self { r: 0, seed }
    }
}

/// Applies VRF locally producing verifiable local randomness that should be published on board
pub fn proceed_locally(
    setup: &ProtocolSetup,
    seed: &Tier3Seed,
) -> Result<VerifiableRandomness, ProceedError> {
    if setup.rounds_limit == seed.r {
        return Err(ProceedError::RoundsLimitExceeded {
            limit: setup.rounds_limit,
        });
    }

    let mut m = [0; 66];
    m[..2].copy_from_slice(&(seed.r + 1).to_be_bytes());
    m[2..].copy_from_slice(&seed.seed);

    Ok(setup.sk_i.eval::<Sha512>(&m))
}

#[derive(Clone, Debug)]
pub enum ProceedError {
    RoundsLimitExceeded { limit: u16 },
}

/// Verifies and combines randomness evaluated by every party and published on board
pub fn combine(
    setup: &ProtocolSetup,
    seed: Tier3Seed,
    board: &Msgs<VerifiableRandomness>,
) -> Result<([u8; 64], Tier3Seed), CombineError> {
    if setup.pk.len() != board.len() {
        return Err(CombineError::MismatchedNumberOfMsgs {
            expected: setup.pk.len(),
            actual: board.len(),
        });
    }
    if setup.rounds_limit == seed.r {
        return Err(CombineError::RoundsLimitExceeded {
            limit: setup.rounds_limit,
        });
    }

    let mut m = [0; 66];
    m[..2].copy_from_slice(&(seed.r + 1).to_be_bytes());
    m[2..].copy_from_slice(&seed.seed);

    let mut result_randomness = [0; 64];

    for (pk_i, rnd) in setup
        .pk
        .iter()
        .zip(board)
        .flat_map(|(pk_i, msg)| Some((pk_i, msg.as_ref()?)))
    {
        if rnd.verify::<Sha512>(pk_i, &m).is_ok() {
            result_randomness
                .iter_mut()
                .zip(rnd.randomness())
                .for_each(|(x, r)| *x ^= *r);
        }
    }

    let next_seed = Tier3Seed {
        r: seed.r + 1,
        seed: result_randomness,
    };
    let randomness = Sha512::digest(&result_randomness);
    let mut randomness_arr = [0; 64];
    randomness_arr.copy_from_slice(&randomness);

    Ok((randomness_arr, next_seed))
}

#[derive(Debug, Clone)]
pub enum CombineError {
    MismatchedNumberOfMsgs { expected: usize, actual: usize },
    RoundsLimitExceeded { limit: u16 },
}
