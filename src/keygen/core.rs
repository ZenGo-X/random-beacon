//! # Keygen protocol defined as a sequence of computations
//!
//! ## Setup
//!
//! 1. A public bulletin board which parties use to communicate with each other
//! 2. Curve `E`
//! 3. Every party holds a secret key `sk_i` (`Scalar<E>`)
//! 4. A list of parties public keys `pk` (`Vec<Point<E>>`) is distributed among protocol participants \
//!    where `pk_i = Point::generator() * sk_i`
//!
//! ## Protocol
//!
//! 0. Provide setup parameters
//!    ```rust
//!    # use curv::elliptic::curves::*;
//!    # use random_beacon::keygen::core::*;
//!    # use sha2::Sha256;
//!    # fn main() -> Result<(), InvalidSetup> {
//!    # let party_sk = Scalar::random();
//!    # let random_point = || Point::generator() * Scalar::random();
//!    # let parties_pk = vec![Point::generator() * &party_sk, random_point(), random_point()];
//!    # let t = 1;
//!    let setup = ProtocolSetup::<Secp256k1, Sha256>::new(party_sk, parties_pk, t)?;
//!    # Ok(()) }
//!    ```
//!
//!    List of parties public keys `parties_pk` must be the same for all parties in the system
//!    (and order of public keys must be the same too!).
//!
//! 1. Generate local secret `s`, polynomial `f`, and encryption randomness `encryption_randomness`
//!    ```rust,no_run
//!    # use curv::elliptic::curves::*;
//!    # use curv::cryptographic_primitives::secret_sharing::Polynomial;
//!    # use random_beacon::keygen::core::*;
//!    # let setup: ProtocolSetup<Secp256k1, sha2::Sha256> = unimplemented!();
//!    #
//!    let s = Scalar::<Secp256k1>::random();
//!    let f = Polynomial::sample_exact_with_fixed_const_term(setup.t, s);
//!    ```
//! 2. Share local secret, and publish encrypted shares to bulletin board
//!    ```rust,no_run
//!    # use curv::elliptic::curves::*;
//!    # use curv::cryptographic_primitives::secret_sharing::Polynomial;
//!    # use random_beacon::keygen::core::*;
//!    # fn publish<T>(_: T) {}
//!    # fn main() -> Result<(), ShareLocalSecretError> {
//!    # let (setup, f): (ProtocolSetup<Secp256k1, sha2::Sha256>, Polynomial<Secp256k1>) = unimplemented!();
//!    let encrypted_shares = share_local_secret(&setup, &f)?;
//!    publish(&encrypted_shares);
//!    # Ok(()) }
//!    ```
//! 3. Decrypt shares
//!
//!    Receive encrypted shares published on bulletin board, decrypt them,
//!    and publish a list of complaints on a board.
//!       ```
//! 4. Process complaints published on board
//!
//!    Receive published complaints, process them, publish justification
//!    message on board (unless `justification_required_for.is_empty()`)
//!    ```rust,no_run
//!    # use curv::elliptic::curves::*;
//!    # use random_beacon::keygen::core::*;
//!    # use curv::cryptographic_primitives::secret_sharing::Polynomial;
//!    # fn publish<T>(_: T) {}
//!    # fn receive<T>() -> T { unimplemented!() }
//!    # fn main() -> Result<(), ProcessComplaintsError> {
//!    # let (setup, mut disqualified, f): (ProtocolSetup<_, sha2::Sha256>, _, Polynomial<Secp256k1>) = unimplemented!();
//!    let complaints: Msgs<Complaints> = receive();
//!    let (justification, justification_required_for) =
//!        process_complaints(&setup, &f, &mut disqualified, &complaints)?;
//!    if !justification_required_for.is_empty() {
//!        publish(&justification);
//!    }
//!    # Ok(()) }
//!    ```
//! 5. Process justifications
//!
//!    This round can be skipped if `justification_required_for.is_empty()`
//!
//!    Receive published justification messages, and process justifications
//!    ```rust,no_run
//!    # use curv::elliptic::curves::*;
//!    # use random_beacon::keygen::core::*;
//!    # fn publish<T>(_: T) {}
//!    # fn receive<T>() -> T { unimplemented!() }
//!    # fn main() -> Result<(), ProcessJustificationError> {
//!    # let (setup, mut disqualified, justification_required_for, encrypted_shares): (_, _, JustificationRequiredFor, Msgs<EncryptedSecretShares<Secp256k1, sha2::Sha256>>) = unimplemented!();
//!    if !justification_required_for.is_empty() {
//!        let justifications: Msgs<Justification<Secp256k1>> = receive();
//!        process_justifications(&setup, &mut disqualified, &justification_required_for, &encrypted_shares, &justifications)?;
//!    }
//!    # Ok(()) }
//!    ```
//! 6. Determine set Q of parties who didn't get disqualified
//!    ```rust,no_run
//!    # use random_beacon::keygen::core::*;
//!    # use curv::elliptic::curves::*;
//!    # let (setup, disqualified): (ProtocolSetup<Secp256k1, sha2::Sha256>, DisqualifiedParties) = unimplemented!();
//!    let q = deduce_set_Q(setup.n, &disqualified);
//!    ```
//!    And filter out encrypted and decrypted shares (from step 3) from shares
//!    of parties who got disqualified
//!    ```rust,no_run
//!    # use curv::elliptic::curves::*;
//!    # use random_beacon::keygen::core::*;
//!    # let (encrypted_shares, decrypted_shares, disqualified, setup): (Vec<Option<EncryptedSecretShares<Secp256k1, sha2::Sha256>>>, Vec<Option<DecryptedSecretShare<Secp256k1>>>, _, ProtocolSetup<Secp256k1, sha2::Sha256>) = unimplemented!();
//!    let encrypted_shares = filter_out_disqualified(encrypted_shares, setup.n, &disqualified);
//!    let decrypted_shares = filter_out_disqualified(decrypted_shares, setup.n, &disqualified);
//!    ```
//! 7. Construct and commit local secret
//!
//!    Publish committed local secret on a board
//!
//!    ```rust,no_run
//!    # use random_beacon::keygen::core::*;
//!    # use curv::elliptic::curves::*;
//!    # fn publish<T>(_: T) {}
//!    # fn main() -> Result<(), ConstructAndCommitLocalSecretError> {
//!    # let (setup, q, decrypted_shares): (ProtocolSetup<_, sha2::Sha256>, _, Vec<DecryptedSecretShare<Secp256k1>>) = unimplemented!();
//!    let (local_secret, committed_secret) =
//!        construct_and_commit_local_secret(&setup, &q, &decrypted_shares)?;
//!    publish(&committed_secret);
//!    # Ok(()) }
//!    ```
//! 8. Verify commitments and construct resulting public key `tpk`
//!
//!    ```rust,no_run
//!    # use random_beacon::keygen::core::*;
//!    # use curv::elliptic::curves::*;
//!    # use sha2::Sha256;
//!    # fn publish<T>(_: T) {}
//!    # fn receive<T>() -> T { unimplemented!() }
//!    # fn main() -> Result<(), ConstructTpkError> {
//!    # let (setup, q, encrypted_shares): (_, _, Vec<EncryptedSecretShares<Secp256k1, Sha256>>) = unimplemented!();
//!    let commitments: Msgs<CommittedLocalPartySecret<Secp256k1, Sha256>> =
//!        receive();
//!    let (tpk, set_i) = verify_commitments_and_construct_tpk(
//!        &setup,
//!        &q,
//!        &encrypted_shares,
//!        &commitments,
//!        &DefaultI2J,
//!    )?;
//!    # Ok(()) }
//!    ```
//! 9. Construct resulting elgamal keys:
//!    
//!    ```rust,no_run
//!    # use curv::elliptic::curves::*;
//!    # use random_beacon::keygen::core::*;
//!    # let (setup, set_i, local_secret, tpk, committed_secret): (ProtocolSetup<_, sha2::Sha256>, Vec<_>, LocalPartySecret<Secp256k1>, _, Msgs<CommittedLocalPartySecret<_, sha2::Sha256>>) = unimplemented!();
//!    let partial_pk = msgs_subset(
//!        committed_secret.iter().map(|m| m.as_ref().map(|m| &m.S)),
//!        &set_i
//!    );
//!    let (tsk_i, decryption, tpk) = construct_elgamal_keys(
//!        &setup,
//!        &set_i,
//!        &partial_pk,
//!        local_secret,
//!        tpk
//!    );
//!    ```
//!
//!    Now you can use [`tpk`](ElgamalPublicKey) to encrypt plaintext, [`tsk_i`](ElgamalLocalShare) to
//!    partially decrypt a ciphertext, and [`decryption`](ElgamalDecrypt) to decrypt ciphertext once
//!    `t+1` parties published valid partial decryptions.
//!
//! ## Note: Slow parties
//!
//! You don't need to wait until all parties publish their messages on
//! board. E.g. it might be adversary who running slow to abort the
//! protocol. If i-th party didn't publish it's message, set
//! `msgs[i] = None`. There might be no more than `t` missing messages.
//! All parties in the system must agree on the same set of received
//! messages (ie. list of received messages must be the same for all
//! honest parties)

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt;
use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};
use sha2::Sha256;

use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::cryptographic_primitives::proofs::low_degree_exponent_interpolation::{
    InvalidLdeiStatement, LdeiProof, LdeiStatement, LdeiWitness,
};
use curv::cryptographic_primitives::secret_sharing::{Polynomial, PolynomialDegree};
use curv::elliptic::curves::{Curve, Point, Scalar};
use curv::BigInt;

use crate::elgamal::{
    ElgamalDecrypt, ElgamalLocalShare, ElgamalPartialPublicKey, ElgamalPublicKey,
};
use crate::utils::IteratorExt;

/// Protocol setup parameters
pub struct ProtocolSetup<E: Curve, H: Digest + Clone> {
    /// Local party private key
    pub sk_i: Scalar<E>,
    /// Local party public key
    pub pk_i: Point<E>,
    /// Public keys of all protocol parties (i-th party has public key `pk[i]`)_
    pub pk: Vec<Point<E>>,

    /// Number of protocol participants. Equals to `pk.len()`.
    pub n: u16,
    /// Protocol threshold value
    pub t: u16,
    /// Index of local party (`pk[i] == pk_i`)
    pub i: u16,

    pub _hash_choice: curv::HashChoice<H>,
}

impl<E: Curve, H: Digest + Clone> ProtocolSetup<E, H> {
    /// Constructs protocol setup from local party's private key, list of parties public keys, and
    /// protocol threshold value
    ///
    /// Returns error if:
    /// * List of parties public keys is empty
    /// * List of parties public keys doesn't include public key of local party `pk_i = sk_i * G`
    /// * Threshold value is not in range `[1; (n - 1)/2]`
    /// * Number of parties in the protocol more than 2^16-1
    pub fn new(sk_i: Scalar<E>, parties_pk: Vec<Point<E>>, t: u16) -> Result<Self, InvalidSetup> {
        if parties_pk.is_empty() {
            return Err(InvalidSetup::EmptyPk);
        }
        let pk_i = Point::generator() * &sk_i;
        let i = parties_pk
            .iter()
            .position_u16(|pk_j| pk_i == *pk_j)
            .ok_or(InvalidSetup::PkDoesntIncludeLocalPartyPublicKey)?;
        let n = u16::try_from(parties_pk.len()).or(Err(InvalidSetup::TooManyParties))?;
        let t_range = 1..=(n - 1) / 2;
        if !t_range.contains(&t) {
            return Err(InvalidSetup::ThresholdValueIsNotInTheRange {
                threshold: t,
                expected_range: t_range,
            });
        }
        Ok(Self {
            sk_i,
            pk_i,
            pk: parties_pk,
            t,
            n,
            i,
            _hash_choice: curv::HashChoice::new(),
        })
    }
}

/// Error indicating that protocol setup parameters are invalid
#[derive(Debug)]
pub enum InvalidSetup {
    EmptyPk,
    PkDoesntIncludeLocalPartyPublicKey,
    ThresholdValueIsNotInTheRange {
        threshold: u16,
        expected_range: RangeInclusive<u16>,
    },
    TooManyParties,
}

/// Secret shared between parties
///
/// Secret is divided into `n` pieces, i-th share is encrypted via public key of i-th party.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EncryptedSecretShares<E: Curve, H: Digest + Clone> {
    /// Committed secret shares
    ///
    /// `Ŝ_i = σ_i * pk_i`
    pub Ŝ: Vec<Point<E>>,
    /// Proof that secret was correctly shared
    ///
    /// `π = LDEI (pk_i, Ŝ_i, t)`
    pub π: LdeiProof<E, H>,
    /// Encrypted secret shares
    ///
    /// `E_i = σ_i ⊕ H(σ_i G)`
    pub E: Vec<BigInt>,
}

/// Shares and commits a local party secret `f(0)` using shares `σ_i = f(i), i = [1; n]`, encrypts
/// shares using given randomness `encryption_randomness`.
///
/// Requirements:
/// * Polynomial degree `f` must be at most `setup.t`
/// * `encryption_randomness` must be sampled for `setup.n`
/// * Following the protocol, local secret `f(0)`, polynomial `f`, and randomness `encryption_randomness`
///   must be ephemeral, ie. must not be used anywhere else
///
/// Returns:
/// * `SharedSecret<E>` that verifiable commits secret shares, and contains `n` shares encrypted
///   for every party (encrypted with party public key). Should be published on bulletin board.
/// * `Vec<EncryptionMaterials<E>>` that must be kept in secret until it's needed to be revealed in
///   the protocol
pub fn share_local_secret<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    f: &Polynomial<E>,
) -> Result<EncryptedSecretShares<E, H>, ShareLocalSecretError> {
    // 0. Validate input
    // TODO: I should be able to write `f.degree().is_finite() && f.degree() > setup.t`
    if matches!(f.degree(), PolynomialDegree::Finite(d) if d > setup.t) {
        return Err(ShareLocalSecretError::PolynomialDegreeTooBig {
            degree: f.degree(),
            expected_degree_at_most: setup.t,
        });
    }

    // 1. Share secret `s`
    let σ = f.evaluate_many_bigint(1..=setup.n).collect::<Vec<_>>();
    let Ŝ = setup
        .pk
        .iter()
        .zip(&σ)
        .map(|(pk_i, σ_i)| pk_i * σ_i)
        .collect::<Vec<_>>();

    // 2. Prove correctness of sharing secret `s`
    let ldei_stmt = LdeiStatement {
        alpha: (1..=setup.n).map(|i| Scalar::from(i)).collect(),
        g: setup.pk.clone(),
        x: Ŝ.clone(),
        d: setup.t,
    };
    let π = LdeiProof::prove(&LdeiWitness { w: f.clone() }, &ldei_stmt)
        .map_err(ShareLocalSecretError::CannotProveLdei)?;

    // 3. Encrypt σ_i for party i using its public key pk_i
    let E: Vec<_> = σ
        .iter()
        .map(|σ_i| {
            σ_i.to_bigint()
                ^ Sha256::new()
                    .chain_point(&(Point::generator() * σ_i))
                    .result_bigint()
        })
        .collect();

    // 4. Publish Ŝ, π, E
    let shared_secret = EncryptedSecretShares { Ŝ, π, E };

    Ok(shared_secret)
}

#[derive(Debug)]
pub enum ShareLocalSecretError {
    CannotProveLdei(InvalidLdeiStatement),
    PolynomialDegreeTooBig {
        degree: PolynomialDegree,
        expected_degree_at_most: u16,
    },
    MismatchedLengthOfEncryptionRandomness {
        actual: usize,
        expected: u16,
    },
}

/// List of messages published on bulletin board by all parties
///
/// List must have length `n` (number of parties in the protocol). If i-th party has published
/// message on bulletin board, `msgs[i]` is `Some(msg)`. Otherwise, it's `None`. It's allowed to have
/// no more than `t` (protocol threshold value) missing messages.
pub type Msgs<M> = Vec<Option<M>>;

/// Set of disqualified parties
pub type DisqualifiedParties = HashMap<u16, DisqualificationReason>;

/// The reason why party was disqualified
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DisqualificationReason {
    DidntPublishEncryptedShares,
    /// Party had to provide `n` shares, but it provided different number of shares
    IncorrectNumberOfShares,
    /// At least `t+1` parties complaint against this party LDEI proof
    InvalidLdeiProof,
    /// One or more shares encrypted by this party were claimed as invalid, and the
    /// party hasn't proven it was right.
    InvalidEncryption,
    /// Party claimed that counterparty incorrectly encrypted its share, and the counterparty
    /// proved that share is correctly encrypted
    LiedAboutInvalidEncryption,
}

#[derive(Clone, PartialEq)]
pub struct DecryptedSecretShare<E: Curve> {
    /// Received (and decrypted) secret share
    pub σ: Scalar<E>,
    /// Cached point `Ŝ = σ PK`
    pub Ŝ: Point<E>,
    /// Cached point `S = σG`
    pub S: Point<E>,
}

impl<E: Curve> fmt::Debug for DecryptedSecretShare<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut f = f.debug_struct("DecryptedSecretShare");
        if cfg!(test) {
            // Display σ only in tests
            f.field("σ", &self.σ);
        }
        f.field("Ŝ", &self.Ŝ).field("S", &self.S).finish()
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Complaints(pub Vec<Complaint>);

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Complaint {
    pub against: u16,
    pub reason: ComplaintReason,
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum ComplaintReason {
    LdeiProof,
    Encryption,
}

/// Tries to decrypt secret shares published by other parties
///
/// Takes protocol setup parameters, a set of disqualified parties, and a list of encrypted shares
/// (where `encrypted_shares[i]` is published by i-th party).
///
/// If party didn't published EncryptedSecretShares message on board (`encrypted_shares[i]` is
/// `None`), or it published obviously incorrect message, it gets disqualified.
///
/// Returns a list of decrypted secret shares `d`, and a list of complaints. If secret share
/// received from i-th party was correctly decrypted, then `d[i]` is `Some(decrypted_share)`.
/// Otherwise, `d[i]` is `None`, and list of complaints includes a complaint against i-th party.
///
/// List of complaints should be published on bulletin board.
// TODO: validate_and_decrypt_shares
pub fn decrypt_shares<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    disqualified: &mut DisqualifiedParties,
    encrypted_shares: &Msgs<EncryptedSecretShares<E, H>>,
) -> Result<(Vec<Option<DecryptedSecretShare<E>>>, Complaints), MismatchedNumberOfMsgs> {
    if encrypted_shares.len() != usize::from(setup.n) {
        return Err(MismatchedNumberOfMsgs {
            expected: setup.n,
            got: encrypted_shares.len(),
        });
    }

    let mut complaints = Vec::with_capacity(usize::from(setup.n) * 2);
    let mut decrypted_shares = Vec::with_capacity(usize::from(setup.n));
    let alphas: Vec<_> = (1..=setup.n).map(Scalar::<E>::from).collect();

    let sk_inv = setup.sk_i.invert().expect("sk_i must be nonzero");

    for (i, encrypted_share) in encrypted_shares.iter().enumerate_u16() {
        // 0. Pre-validate the message. If it's missing or obviously incorrect, party gets disqualified
        let encrypted_share = match encrypted_share {
            Some(s) => s,
            None => {
                disqualified
                    .entry(i)
                    .or_insert(DisqualificationReason::DidntPublishEncryptedShares);
                decrypted_shares.push(None);
                continue;
            }
        };
        if encrypted_share.E.len() != usize::from(setup.n)
            || encrypted_share.Ŝ.len() != usize::from(setup.n)
        {
            // Clearly party is corrupted
            disqualified
                .entry(i)
                .or_insert(DisqualificationReason::IncorrectNumberOfShares);
            decrypted_shares.push(None);
            continue;
        }

        // 1. Verify the proof
        let ldei_stmt = LdeiStatement {
            alpha: alphas.clone(),
            g: setup.pk.clone(),
            x: encrypted_share.Ŝ.clone(),
            d: setup.t,
        };
        let valid = encrypted_share.π.verify(&ldei_stmt).is_ok();
        if !valid {
            // Proof is not valid, but party will be disqualified only if t+1 parties set
            // complaint against this proof
            complaints.push(Complaint {
                against: i,
                reason: ComplaintReason::LdeiProof,
            })
        }

        // 2. Decrypt i-th share
        let Ŝ_i = &encrypted_share.Ŝ[usize::from(setup.i)];
        let E_i = &encrypted_share.E[usize::from(setup.i)];
        let σ_i = Scalar::<E>::from_bigint(
            &(E_i ^ Sha256::new().chain_point(&(Ŝ_i * &sk_inv)).result_bigint()),
        );

        let Ŝ_i_expected = &σ_i * &setup.pk_i;
        if Ŝ_i != &Ŝ_i_expected {
            // Encryption is not valid
            complaints.push(Complaint {
                against: i,
                reason: ComplaintReason::Encryption,
            });
            decrypted_shares.push(None);
        } else {
            decrypted_shares.push(Some(DecryptedSecretShare {
                Ŝ: Ŝ_i.clone(),
                S: Point::generator() * &σ_i,
                σ: σ_i,
            }));
        }
    }

    Ok((decrypted_shares, Complaints(complaints)))
}

#[derive(Debug)]
pub struct MismatchedNumberOfMsgs {
    pub expected: u16,
    pub got: usize,
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Justification<E: Curve> {
    pub revealed_σ: Vec<Scalar<E>>,
}

pub type JustificationRequiredFor = HashMap<u16, Vec<u16>>;

/// Processes complaints published by parties
///
/// If any party receives more than `t` complaints against its LDEI proof, party get disqualified.
/// If any party receives complaint against its encrypted share, it must reveal unencrypted share
/// $σ_i$.
///
/// Returns a justification message (list of revealed encryption materials, nonempty if anyone set
/// complaint against local party encrypted share), and a set of parties `justification_required_for`
/// who must reveal encryption materials.
///
/// Justification message should be published on bulletin board unless
/// `justification.encryption_materials.is_empty()`.
pub fn process_complaints<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    f: &Polynomial<E>,
    disqualified: &mut DisqualifiedParties,
    complaints: &Msgs<Complaints>,
) -> Result<(Justification<E>, JustificationRequiredFor), ProcessComplaintsError> {
    if complaints.len() != usize::from(setup.n) {
        return Err(ProcessComplaintsError::MismatchedNumberOfMsgs {
            expected: setup.n,
            got: complaints.len(),
        });
    }

    let mut proof_complaints = vec![0u16; usize::from(setup.n)];
    let mut justification_required_for = HashMap::with_capacity(usize::from(setup.n));

    for (complainer, complaints) in complaints.iter().enumerate_u16() {
        let complaints = match complaints {
            Some(c) => c,
            None => continue,
        };
        for Complaint { against, reason } in &complaints.0 {
            if *against >= setup.n {
                continue;
            }

            match reason {
                ComplaintReason::LdeiProof => proof_complaints[usize::from(*against)] += 1,
                ComplaintReason::Encryption => justification_required_for
                    .entry(*against)
                    .or_insert_with(|| Vec::with_capacity(usize::from(setup.n)))
                    .push(complainer),
            }
        }
    }

    for (guilty_party, &number_of_complaints) in proof_complaints.iter().enumerate_u16() {
        if number_of_complaints > setup.t {
            disqualified
                .entry(guilty_party)
                .or_insert(DisqualificationReason::InvalidLdeiProof);
        }
    }

    let justification = {
        let mut revealed_σ = vec![];
        for &complainer in justification_required_for
            .get(&setup.i)
            .iter()
            .flat_map(|l| l.iter())
        {
            // Complainer index is guaranteed to be valid, due to for-loop above
            debug_assert!(complainer < setup.n);

            revealed_σ.push(f.evaluate_bigint(complainer + 1))
        }
        Justification { revealed_σ }
    };

    Ok((justification, justification_required_for))
}

#[derive(Debug)]
pub enum ProcessComplaintsError {
    MismatchedNumberOfMsgs { expected: u16, got: usize },
    MismatchedNumberOfEncryptionMaterials { expected: u16, got: usize },
}

/// Processes justification messages published by parties
///
/// Every party in `justification_required_for` set must reveal encryption materials that were used
/// to encrypt shares for parties `justification_required_for[i]`.
///
/// If party will manage to proof that complaint against its encryption were biased, then complainer
/// is disqualified. Otherwise, party is disqualified.
///
/// This round can be skipped if `justification_required_for.is_empty()`.
pub fn process_justifications<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    disqualified: &mut DisqualifiedParties,
    justification_required_for: &JustificationRequiredFor,
    encrypted_shares: &Msgs<EncryptedSecretShares<E, H>>,
    justifications: &Msgs<Justification<E>>,
) -> Result<(), ProcessJustificationError> {
    if justifications.len() != usize::from(setup.n) {
        return Err(
            ProcessJustificationError::MismatchedNumberOfJustifications {
                expected: setup.n,
                got: justifications.len(),
            },
        );
    }
    if encrypted_shares.len() != usize::from(setup.n) {
        return Err(
            ProcessJustificationError::MismatchedNumberOfJustifications {
                expected: setup.n,
                got: encrypted_shares.len(),
            },
        );
    }

    let present_justifications = justifications
        .iter()
        .enumerate_u16()
        .flat_map(|(i, m)| Some((i, m.as_ref()?)));
    for (defendant, justification) in present_justifications {
        if disqualified.contains_key(&defendant) {
            // Party is already disqualified
            continue;
        }
        let complainers = match justification_required_for.get(&defendant) {
            Some(c) => c,
            None => continue,
        };

        if justification.revealed_σ.len() < complainers.len() {
            // defendant failed to justify himself
            disqualified
                .entry(defendant)
                .or_insert(DisqualificationReason::InvalidEncryption);
            continue;
        }

        let original_message = match &encrypted_shares[usize::from(defendant)] {
            Some(m) => m,
            None => {
                // Party didn't publish encrypted shares. It should have been already disqualified...
                disqualified
                    .entry(defendant)
                    .or_insert(DisqualificationReason::InvalidEncryption);
                continue;
            }
        };

        for (&complainer, revealed_σ) in complainers.iter().zip(&justification.revealed_σ) {
            let complainer_pk = &setup.pk[usize::from(complainer)];

            let E = &original_message.E[usize::from(complainer)];
            let E_expected = revealed_σ.to_bigint()
                ^ Sha256::new()
                    .chain_point(&(Point::generator() * revealed_σ))
                    .result_bigint();

            let Ŝ = &original_message.Ŝ[usize::from(complainer)];
            let Ŝ_expected = revealed_σ * complainer_pk;

            if E == &E_expected && Ŝ == &Ŝ_expected {
                // Defendant proved that he encrypted share correctly, disqualify complainer party
                disqualified
                    .entry(complainer)
                    .or_insert(DisqualificationReason::LiedAboutInvalidEncryption);
            } else {
                // Proof is invalid, disqualify defendant party
                disqualified
                    .entry(defendant)
                    .or_insert(DisqualificationReason::InvalidEncryption);
            }
        }
    }

    for &skipped_defense in justification_required_for
        .keys()
        .filter(|&&i| justifications[usize::from(i)].is_none())
    {
        // Complaint wasn't disputed
        disqualified
            .entry(skipped_defense)
            .or_insert(DisqualificationReason::InvalidEncryption);
    }

    Ok(())
}

#[derive(Debug)]
pub enum ProcessJustificationError {
    MismatchedNumberOfJustifications { expected: u16, got: usize },
    MismatchedNumberOfEncryptedShares { expected: u16, got: usize },
}

/// Filters out elements of list corresponding to disqualified parties
///
/// Takes a `list` of `n` options (`Vec<Option<T>>`), returns a new list (`Vec<T>`) that doesn't
/// contains elements corresponding to disqualified party (ie. `list[i]` won't be included to final
/// list if `disqualified.contains_key(&i)`)
///
/// ## Example
///
/// ```rust
/// # #![allow(mixed_script_confusables)]
/// # use std::collections::HashMap;
/// # use std::iter::FromIterator;
/// # use curv::elliptic::curves::{Secp256k1, Point, Scalar};
/// # use random_beacon::keygen::core::{DecryptedSecretShare, DisqualificationReason, DisqualifiedParties, filter_out_disqualified};
/// #
/// # let (pk1, pk3) = (Point::generator() * Scalar::random(), Point::generator() * Scalar::random());
/// # let (σ1, σ3) = (Scalar::random(), Scalar::random());
/// # let share1 = DecryptedSecretShare::<Secp256k1> { Ŝ: &σ1 * &pk1, S: Point::generator() * &σ1, σ: σ1 };
/// # let share3 = DecryptedSecretShare::<Secp256k1> { Ŝ: &σ3 * &pk3, S: Point::generator() * &σ3, σ: σ3 };
/// #
/// // Let `list` be a list of decrypted shares:
/// let shares = vec![Some(share1.clone()), None, Some(share3.clone())];
/// // 2nd party didn't provide correctly encrypted share so it were disqualified:
/// let disqualified = DisqualifiedParties::from_iter([(1, DisqualificationReason::InvalidEncryption)]);
/// // Now we want to get a list of shares from parties who're not disqualified:
/// let shares = filter_out_disqualified(shares, 3, &disqualified);
///
/// assert_eq!(shares, vec![share1, share3]);
/// ```
///
/// ## Panics
/// This function panics if arguments were invalid:
/// * `list.len() != n`
/// * `disqualified.len() > n`
/// * If i-th party is not disqualified, but `list[i]` is `None` \
///   i.e. `exist i. !disqualified.contains_key(&i) && list[i].is_none()`
pub fn filter_out_disqualified<T: 'static>(
    list: Vec<Option<T>>,
    n: u16,
    disqualified: &DisqualifiedParties,
) -> Vec<T> {
    assert_eq!(list.len(), usize::from(n));
    assert!(disqualified.len() <= usize::from(n));

    list.into_iter()
        .enumerate_u16()
        .flat_map(move |(i, el)| {
            if disqualified.contains_key(&i) {
                None
            } else {
                Some(el.expect(&format!(
                    "party {} wasn't disqualified, so element must be Some(_)",
                    i
                )))
            }
        })
        .collect()
}

/// Defines set Q (of parties who're not disqualified) from number of parties `n` and set of
/// disqualified parties
pub fn deduce_set_Q(n: u16, disqualified: &DisqualifiedParties) -> HashSet<u16> {
    let mut Q = HashSet::with_capacity(usize::from(n) - disqualified.len());
    Q.extend((0..n).filter(|i| !disqualified.contains_key(i)));
    Q
}

#[derive(Clone)]
pub struct LocalPartySecret<E: Curve> {
    pub σ: Scalar<E>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct CommittedLocalPartySecret<E: Curve, H: Digest + Clone> {
    pub S: Point<E>,
    pub Ŝ: Point<E>,
    pub proof: LdeiProof<E, H>,
}

/// Constructs local party secret from secret shares received and decrypted from parties who are
/// not disqualified
///
/// Returns constructed secret and commitment. Commitment should be published to bulletin board.
///
/// _Note_ that list of secret shares must have length equal to `Q.len()` and have type
/// `[DecryptedSecretShare<E>]`. Initially, you obtain list of secret shares from step [decrypt_shares]
/// that returns `Vec<Option<DecryptedSecretShare<E>>>`. To filter out shares from disqualified
/// parties, you should use [filter_out_disqualified] function.
pub fn construct_and_commit_local_secret<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    Q: &HashSet<u16>,
    secret_shares: &[DecryptedSecretShare<E>],
) -> Result<
    (LocalPartySecret<E>, CommittedLocalPartySecret<E, H>),
    ConstructAndCommitLocalSecretError,
> {
    if secret_shares.len() != Q.len() {
        return Err(
            ConstructAndCommitLocalSecretError::MismatchedNumberOfSecretShares {
                expected: Q.len(),
                got: secret_shares.len(),
            },
        );
    }

    let (σ, S, Ŝ) = secret_shares.iter().fold(
        (Scalar::zero(), Point::zero(), Point::zero()),
        |(σ, S, Ŝ), share| (σ + &share.σ, S + &share.S, Ŝ + &share.Ŝ),
    );

    // DLEQ(g, S, pk, Ŝ)
    let w = Polynomial::from_coefficients(vec![σ.clone()]);
    let stmt = LdeiStatement {
        alpha: vec![Scalar::from(1), Scalar::from(2)],
        g: vec![Point::generator().to_point(), setup.pk_i.clone()],
        x: vec![S.clone(), Ŝ.clone()],
        d: 0,
    };
    let proof = LdeiProof::prove(&LdeiWitness { w }, &stmt)
        .map_err(ConstructAndCommitLocalSecretError::ProveDleq)?;

    let local_secret = LocalPartySecret { σ };
    let commitment = CommittedLocalPartySecret { S, Ŝ, proof };

    Ok((local_secret, commitment))
}

#[derive(Debug)]
pub enum ConstructAndCommitLocalSecretError {
    MismatchedNumberOfSecretShares { expected: usize, got: usize },
    ProveDleq(InvalidLdeiStatement),
}

/// I2J maps set I to subset J of t+1 elements.
///
/// [DefaultI2J] provides default implementation
pub trait I2J {
    fn map_I_to_J<T: Clone>(&self, t: u16, I: &[T]) -> Vec<T>;
}

impl<M: I2J> I2J for &M {
    fn map_I_to_J<T: Clone>(&self, t: u16, I: &[T]) -> Vec<T> {
        M::map_I_to_J(self, t, I)
    }
}

/// Provides default implementation of [I -> J](I2J) mapping by taking first `t+1` elements from
/// set I
#[derive(Copy, Clone)]
pub struct DefaultI2J;

impl I2J for DefaultI2J {
    fn map_I_to_J<T: Clone>(&self, t: u16, I: &[T]) -> Vec<T> {
        I[..usize::from(t) + 1].to_vec()
    }
}

/// Verifies published commitments of parties local secrets
///
/// Takes set Q of parties who didn't get disqualified, encrypted shares
/// received earlier at [decrypt_shares] but filtered out from shares from
/// disqualified parties (see [filter_out_disqualified]), secret commitments
/// published on bulletin board.
///
/// Outputs resulting tpk along with set I of parties who correctly committed
/// their local secret, and set J that was used to derive `tpk`.
pub fn verify_commitments_and_construct_tpk<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    Q: &HashSet<u16>,
    encrypted_shares: &[EncryptedSecretShares<E, H>],
    secret_commitments: &Msgs<CommittedLocalPartySecret<E, H>>,
    i2j: impl I2J,
) -> Result<(Point<E>, Vec<u16>), ConstructTpkError> {
    if secret_commitments.len() != usize::from(setup.n) {
        return Err(ConstructTpkError::MismatchedNumberOfCommitments {
            expected: setup.n,
            got: secret_commitments.len(),
        });
    }
    if encrypted_shares.len() != Q.len() {
        return Err(ConstructTpkError::MismatchedNumberOfEncryptedShares {
            expected: Q.len(),
            got: encrypted_shares.len(),
        });
    }

    let mut I = Vec::with_capacity(usize::from(setup.n));
    let mut I_x = Vec::with_capacity(usize::from(setup.n));
    let mut I_y = Vec::with_capacity(usize::from(setup.n));
    for (party_i, com) in secret_commitments.iter().enumerate_u16() {
        let com = match com {
            Some(com) => com,
            None => {
                // Party didn't commit its secret => it won't be included to set I
                continue;
            }
        };
        let Ŝ: Point<E> = encrypted_shares
            .iter()
            .map(|share| &share.Ŝ[usize::from(party_i)])
            .sum();
        if Ŝ != com.Ŝ {
            // Party provided wrong Ŝ => it won't be included to set I
            continue;
        }

        let stmt = LdeiStatement {
            alpha: vec![Scalar::from(1), Scalar::from(2)],
            g: vec![
                Point::generator().to_point(),
                setup.pk[usize::from(party_i)].clone(),
            ],
            x: vec![com.S.clone(), Ŝ],
            d: 0,
        };
        let valid = com.proof.verify(&stmt).is_ok();
        if !valid {
            // Party's commitment proof is not valid => it won't be included to set I
            continue;
        }

        I.push(party_i);
        I_x.push(Scalar::from(party_i + 1));
        I_y.push(com.S.clone());
    }

    if I.len() < usize::from(setup.t + 1) {
        return Err(ConstructTpkError::TooFewHonestParties {
            honest_parties_count: I.len(),
            required_at_least: setup.t + 1,
        });
    }

    let J_x = i2j.map_I_to_J(setup.t, &I_x);
    let J_y = i2j.map_I_to_J(setup.t, &I_y);

    debug_assert_eq!(J_x.len(), usize::from(setup.t) + 1);
    debug_assert_eq!(J_y.len(), usize::from(setup.t) + 1);

    let tpk: Point<E> = J_y
        .iter()
        .enumerate_u16()
        .map(|(i, y_i)| y_i * Polynomial::lagrange_basis(&Scalar::zero(), i, &J_x))
        .sum();

    Ok((tpk, I))
}

pub fn construct_elgamal_keys<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    I: &[u16],
    partial_tpk: &[Point<E>],
    tsk_i: LocalPartySecret<E>,
    tpk: Point<E>,
) -> (
    ElgamalLocalShare<E, H>,
    ElgamalDecrypt<E>,
    ElgamalPublicKey<E>,
) {
    assert_eq!(I.len(), partial_tpk.len());
    let q = I
        .iter()
        .zip(partial_tpk)
        .map(|(i, tpk_i)| (i + 1, ElgamalPartialPublicKey::new(tpk_i.clone())))
        .collect();
    let tsk_i = ElgamalLocalShare::new(setup.i + 1, tsk_i.σ);
    let decrypt = ElgamalDecrypt::new(setup.t, q);
    let tpk = ElgamalPublicKey::new(tpk);
    (tsk_i, decrypt, tpk)
}

#[derive(Debug)]
pub enum ConstructTpkError {
    MismatchedNumberOfCommitments {
        expected: u16,
        got: usize,
    },
    MismatchedNumberOfEncryptedShares {
        expected: usize,
        got: usize,
    },
    TooFewHonestParties {
        honest_parties_count: usize,
        required_at_least: u16,
    },
}

/// Returns subset of `msgs` by keeping only messages from specified list of parties
///
/// `msgs[i]` will be included to the final list if `keep_msgs_from` contains `i`. List of parties
/// `keep_msgs_from` must be sorted. If `keep_msgs_from` contains `i`, then `msgs[i]` must be `Some(_)`,
/// otherwise the function will **panic**.
///
/// ## Example
///
/// ```rust
/// # use curv::elliptic::curves::*;
/// # use curv::cryptographic_primitives::proofs::low_degree_exponent_interpolation::LdeiProof;
/// # use curv::cryptographic_primitives::secret_sharing::Polynomial;
/// # let random_point = || Point::generator() * Scalar::random();
/// # let dummy_proof = || LdeiProof{ a: vec![], e: Scalar::random(), z: Polynomial::sample_exact(0), hash_choice: curv::HashChoice::<sha2::Sha256>::new() };
/// # let secret_com_i = || CommittedLocalPartySecret::<Secp256k1, sha2::Sha256> {S: random_point(), Ŝ: random_point(), proof: dummy_proof()};
/// # let (secret_com1, secret_com2, secret_com3) = (secret_com_i(), secret_com_i(), secret_com_i());
/// use random_beacon::keygen::core::*;
/// // Let `msgs` be a list of committed parties' local secrets (that includes parties' partial public keys)
/// let committed_secrets = vec![
///     Some(secret_com1.clone()),
///     Some(secret_com2.clone()),
///     Some(secret_com3.clone())
/// ];
/// // Suppose, we checked proofs for given commitments, and the 2nd party's
/// // proof happened to be invalid
/// let good_proofs = &[0, 2];
/// // Now we want to get a list of partial pks from parties who's proof
/// // is valid
/// let partial_pk = msgs_subset(committed_secrets.iter().map(|m| m.as_ref().map(|m| &m.S)), good_proofs);
///
/// assert_eq!(partial_pk, vec![secret_com1.S, secret_com3.S]);
/// ```
pub fn msgs_subset<'m, T: Clone + 'm>(
    msgs: impl IntoIterator<Item = Option<&'m T>>,
    keep_msgs_from: &[u16],
) -> Vec<T> {
    let mut v = vec![];
    let mut keep_msgs_from = keep_msgs_from.iter().peekable();

    for (i, msg) in msgs.into_iter().enumerate() {
        match keep_msgs_from.peek() {
            Some(&&j) if i == usize::from(j) => {
                let _ = keep_msgs_from.next(); // advance the iterator
                v.push(
                    msg.expect(&format!(
                        "`keep_msgs_from` contains {i} => `msgs[{i}]` must be Some(_)",
                        i = i
                    ))
                    .clone(),
                )
            }
            Some(_) => continue,
            None => break,
        }
    }

    v
}
