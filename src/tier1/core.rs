//! Tier 1 protocol defined as a sequence of computations
//!
//! ## Setup
//!
//! 1. A public bulletin board which parties use to communicate with each other
//! 2. Curve `E`
//! 3. Every party holds a secret key $\sk_i\in\Zq$ ([`Scalar<E>`](Scalar))
//! 4. A list of parties public keys $\pk$ (`Vec<Point<E>>`) is distributed among protocol participants \
//!    where $\pk_i = \sk_i \G$
//! 5. Parameters: $t$, $\ell$, $\ellʹ$ \
//!    $1 \le t \le \frac{n - \ell}{2}, \ellʹ = n - 2t, 1 \le \ell \le \ellʹ$
//! 6. Resilient matrix $M \in \Zq^{\ellʹ \times n-t}$
//!
//! ## Protocol
//!
//! ### 0. Setup
//!
//! Provide setup parameters:
//!
//! ```rust
//! # use curv::elliptic::curves::*;
//! # use random_beacon::tier1::core::*;
//! # use sha2::Sha256;
//! # fn main() -> Result<(), InvalidSetup> {
//! let party_sk = Scalar::random();
//! # let random_point = || Point::generator() * Scalar::random();
//! # let parties_pk = vec![Point::generator() * &party_sk, random_point(), random_point(), random_point(), random_point()];
//! # let (n, t, l, a) = (5, 1, 3, Scalar::<Secp256k1>::random());
//! #
//! let matrix = ResilientMatrix::new(a, n - 2*t, n - t);
//! let setup = ProtocolSetup::<Secp256k1, Sha256>::new(party_sk, parties_pk, t, l, matrix)?;
//! #
//! # Ok(()) }
//! ```
//!
//! ### 1. Sharing
//!
//! Sample random polynomial $f$ of degree at most $t+\ell-1$, verifiable split it into
//! $n$ shares, publish derived message on board:
//!
//! ```rust,no_run
//! # use curv::elliptic::curves::*;
//! # use random_beacon::tier1::core::*;
//! # fn publish<T>(_: &T) {}
//! # fn main() -> Result<(), SharingError> {
//! # use curv::cryptographic_primitives::secret_sharing::Polynomial;
//! # let setup: ProtocolSetup<Secp256k1, sha2::Sha256> = unimplemented!();
//! #
//! let f = Polynomial::sample_exact(setup.t + setup.l - 1);
//! let shared_secret = sharing(&setup, &f)?;
//! publish(&shared_secret);
//! #
//! # Ok(()) }
//! ```
//!
//! ### 2. Verification
//!
//! On receiving shared secret published on board, check its correctness using [is_secret_correctly_shared].
//! Grab first $n-t$ valid shares:
//!
//! ```rust,no_run
//! # use curv::elliptic::curves::*;
//! # use random_beacon::tier1::core::*;
//! # fn receive<T>() -> (usize, T) { unimplemented!() }
//! # fn main() -> Result<(), SharingError> {
//! # let setup: ProtocolSetup<Secp256k1, sha2::Sha256> = unimplemented!();
//! #
//! // shared_secrets[i] is a shared secret received from i-th party
//! let mut shared_secrets = vec![None; usize::from(setup.n)];
//! let mut received_shared_secrets = 0u16;
//! loop {
//!     let (sender, shared_secret) = receive();
//!     if is_secret_correctly_shared(&setup, &shared_secret).is_ok()
//!         && shared_secrets[sender].is_none()
//!     {
//!         shared_secrets[sender] = Some(shared_secret);
//!         received_shared_secrets += 1;
//!         if received_shared_secrets == setup.n - setup.t {
//!             break;
//!         }
//!     }
//! }
//! #
//! # Ok(()) }
//! ```
//!
//! ### 3. Reconstruction
//!
//! Once $n-t$ valid shares are published, parties who published them need to reveal their original
//! secret:
//!
//! ```rust,no_run
//! # use curv::elliptic::curves::*;
//! # use random_beacon::tier1::core::*;
//! # fn publish<T>(_: &T) { unimplemented!() }
//! # fn receive<T>() -> T { unimplemented!() }
//! # fn main() -> Result<(), OpenedSecretsVerificationError> {
//! # use curv::cryptographic_primitives::secret_sharing::Polynomial;
//! # let (setup, shared_secrets, f): (ProtocolSetup<Secp256k1, sha2::Sha256>, Msgs<SharedSecret<_, _>>, Polynomial<Secp256k1>) = unimplemented!();
//! #
//! // Check if we need to reveal the secret
//! if shared_secrets[usize::from(setup.i)].is_some() {
//!     // Local party managed to publish secrets share in time => need to open the secret
//!     publish(&f);
//! }
//!
//! // Receive all the opened secrets and validate them
//! let opened_secrets: Msgs<Polynomial<_>> = receive();
//! let mut correctly_opened_secrets = OpenedSecrets::new();
//! let parties_who_didnt_open_their_secrets = validate_opened_secrets(
//!     &setup,
//!     &shared_secrets,
//!     &opened_secrets,
//!     &mut correctly_opened_secrets
//! )?;
//! #
//! # Ok(()) }
//! ```
//!
//! If list of parties who didn't open their secrets is not empty, then parties need to collaborate
//! in order to open them. Every party need to partially open the secrets, and publish their openings
//! on board.
//!
//! ```rust,no_run
//! # use curv::elliptic::curves::*;
//! # use random_beacon::tier1::core::*;
//! # fn publish<T>(_: &T) { unimplemented!() }
//! # fn receive<T>() -> T { unimplemented!() }
//! # fn main() -> Result<(), PartiallyOpenSecretError> {
//! # use curv::cryptographic_primitives::secret_sharing::Polynomial;
//! # let (setup, shared_secrets, parties_who_didnt_open_their_secrets): (ProtocolSetup<Secp256k1, sha2::Sha256>, Msgs<SharedSecret<_, _>>, PartiesWhoDidntOpenTheirSecrets) = unimplemented!();
//! #
//! let mut local_partial_opened_secrets = vec![];
//! for non_cooperative_party in parties_who_didnt_open_their_secrets {
//!     local_partial_opened_secrets.push(partially_open_secret(
//!         &setup,
//!         &shared_secrets[usize::from(non_cooperative_party)].unwrap(),
//!     )?)
//! }
//! publish(&local_partial_opened_secrets);
//! #
//! # Ok(()) }
//! ```
//!
//! Once $t+\ell$ valid partial openings are published, original secret can be reconstructed.
//!
//! ```rust,no_run
//! # use curv::elliptic::curves::*;
//! # use random_beacon::tier1::core::*;
//! # use sha2::Sha256;
//! # fn publish<T>(_: &T) { unimplemented!() }
//! # fn receive<T>() -> (u16, T) { unimplemented!() }
//! # fn main() -> Result<(), OpenSharedSecretError> {
//! # use curv::cryptographic_primitives::secret_sharing::Polynomial;
//! # let (setup, shared_secrets, parties_who_didnt_open_their_secrets, mut correctly_opened_secrets): (ProtocolSetup<Secp256k1, sha2::Sha256>, Msgs<SharedSecret<_, _>>, PartiesWhoDidntOpenTheirSecrets, OpenedSecrets<Secp256k1>) = unimplemented!();
//! #
//! let mut partial_reconstructions = vec![(vec![], vec![]); parties_who_didnt_open_their_secrets.len()];
//! let mut secrets_left = parties_who_didnt_open_their_secrets.len();
//! while secrets_left > 0 {
//!     let (sender, partials) = receive::<Vec<PartiallyOpenedSecret<Secp256k1, Sha256>>>();
//!     for ((&uncooperative_party, reconstruction), partial) in parties_who_didnt_open_their_secrets.iter()
//!         .zip(&mut partial_reconstructions)
//!         .zip(&partials)
//!     {
//!         let shared_secret = shared_secrets[usize::from(uncooperative_party)].as_ref().unwrap();
//!         let valid = validate_partially_opened_secret(
//!             &setup,
//!             sender,
//!             shared_secret,
//!             partial,
//!         ).is_ok();
//!         
//!         if valid {
//!             reconstruction.0.push(sender);
//!             reconstruction.1.push(partial.clone());
//!             if reconstruction.0.len() == usize::from(setup.t + setup.l) {
//!                 let opened_secret = open_shared_secret(&setup, &reconstruction.0, &reconstruction.1)?;
//!                 correctly_opened_secrets.insert(uncooperative_party, opened_secret);
//!                 secrets_left -= 1;
//!             }
//!         }
//!     }
//! }
//! #
//! # Ok(()) }
//! ```
//!
//! ### 4. Aggregation
//!
//! Once all $n-t$ published secrets are opened, we can extract randomness:
//!
//! ```rust,no_run
//! # use curv::elliptic::curves::*;
//! # use random_beacon::tier1::core::*;
//! # fn main() -> Result<(), ExtractRandomnessError> {
//! # use curv::cryptographic_primitives::secret_sharing::Polynomial;
//! # let (setup, correctly_opened_secrets): (ProtocolSetup<Secp256k1, sha2::Sha256>, OpenedSecrets<Secp256k1>) = unimplemented!();
//! #
//! let secrets_matrix = OpenedSecretsMatrix::from(correctly_opened_secrets);
//! let randomness = extract_randomness(&setup, &secrets_matrix)?;
//! #
//! # Ok(()) }
//! ```
//!
//! It will output $\ell \cdot \ellʹ$ random points

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::ops;

use serde::{Deserialize, Serialize};

use curv::cryptographic_primitives::proofs::low_degree_exponent_interpolation::{
    InvalidLdeiStatement, LdeiProof, LdeiStatement, LdeiWitness,
};
use curv::cryptographic_primitives::proofs::ProofError;
use curv::cryptographic_primitives::secret_sharing::{Polynomial, PolynomialDegree};
use curv::elliptic::curves::*;
use sha2::Digest;

use crate::utils::IteratorExt;

// Re-export
pub use crate::keygen::core::Msgs;

pub struct ProtocolSetup<E: Curve, H: Digest + Clone> {
    /// Local party private key
    pub sk_i: Scalar<E>,
    /// Local party public key
    pub pk_i: Point<E>,

    /// List of parties' public keys
    ///
    /// $pk_i$ corresponds to public key of $\ith$ party
    ///
    /// `setup.pk[setup.i]` must be equal to `setup.pk_i`
    pub pk: Vec<Point<E>>,

    /// Resilient matrix $M \in \Zq^{\ellʹ \times n-t}$
    pub M: ResilientMatrix<E>,

    /// Number of parties
    ///
    /// Equals to `pk.len()`
    pub n: u16,
    /// Threshold value $1 \le t \le \frac{n - \ell}{2}$
    pub t: u16,
    /// $1 \le \ell \le \ellʹ$
    pub l: u16,
    /// $\ellʹ = n - 2t$
    pub lʹ: u16,
    /// Index of local party
    pub i: u16,

    pub _hash_choice: curv::HashChoice<H>,
}

impl<E: Curve, H: Digest + Clone> ProtocolSetup<E, H> {
    pub fn new(
        sk_i: Scalar<E>,
        pk: Vec<Point<E>>,
        t: u16,
        l: u16,
        M: ResilientMatrix<E>,
    ) -> Result<Self, InvalidSetup> {
        if pk.is_empty() {
            return Err(InvalidSetup::EmptyPk);
        }
        if sk_i.is_zero() {
            return Err(InvalidSetup::ZeroSk);
        }
        let pk_i = Point::generator() * &sk_i;
        let i = pk
            .iter()
            .position_u16(|pk_j| pk_i == *pk_j)
            .ok_or(InvalidSetup::PkDoesntIncludeLocalPartyPublicKey)?;
        let n = u16::try_from(pk.len()).or(Err(InvalidSetup::TooManyParties))?;

        let zero_pk_i = pk.iter().position_u16(|pk_i| pk_i.is_zero());
        if let Some(i) = zero_pk_i {
            return Err(InvalidSetup::ZeroPk { i });
        }

        if !(t >= 1 && t <= (n - l) / 2 && n > 2 * t) {
            return Err(InvalidSetup::ThresholdNotInRange { t, n, l });
        }

        let lʹ = n - 2 * t;
        if !(1 <= l && l <= lʹ) {
            return Err(InvalidSetup::LNotInRange { l, n, t });
        }

        if !(M.height() == lʹ && M.width() == n - t) {
            return Err(InvalidSetup::UnexpectedResilientMatrix {
                width: M.width(),
                height: M.height(),
                expected_width: n - t,
                expected_height: lʹ,
            });
        }

        Ok(Self {
            sk_i,
            pk_i,
            pk,

            M,

            i,
            n,
            t,
            l,
            lʹ,

            _hash_choice: curv::HashChoice::new(),
        })
    }
}

#[derive(Debug, Clone)]
pub enum InvalidSetup {
    EmptyPk,
    PkDoesntIncludeLocalPartyPublicKey,
    ZeroSk,
    ZeroPk {
        i: u16,
    },
    TooManyParties,
    LNotInRange {
        l: u16,
        n: u16,
        t: u16,
    },
    ThresholdNotInRange {
        t: u16,
        n: u16,
        l: u16,
    },
    UnexpectedResilientMatrix {
        width: u16,
        height: u16,
        expected_width: u16,
        expected_height: u16,
    },
}

#[derive(Clone, Debug)]
pub struct ResilientMatrix<E: Curve> {
    matrix: Vec<Scalar<E>>,
    h: u16,
    w: u16,
}

impl<E: Curve> ResilientMatrix<E> {
    /// Creates new resilient matrix `M: h × w` such as `M_ij = i*j * α`
    pub fn new(α: Scalar<E>, h: u16, w: u16) -> Self {
        let mut matrix = Vec::with_capacity(usize::from(h) * usize::from(w));

        for i in 0..h {
            let i_s = Scalar::from(i + 1);
            for j in 0..w {
                let m_ij = &i_s * Scalar::from(j + 1) * &α;
                matrix.push(m_ij)
            }
        }

        Self { matrix, h, w }
    }

    pub fn height(&self) -> u16 {
        self.h
    }
    pub fn width(&self) -> u16 {
        self.w
    }

    pub fn get(&self, i: u16, j: u16) -> Option<&Scalar<E>> {
        if !(i <= self.h) {
            return None;
        }
        if !(j <= self.w) {
            return None;
        }
        Some(
            self.matrix
                .get(usize::from(i) * usize::from(self.h) + usize::from(j))
                .expect("i, j are in valid range"),
        )
    }
}

impl<E: Curve> ops::Index<[u16; 2]> for ResilientMatrix<E> {
    type Output = Scalar<E>;
    fn index(&self, index: [u16; 2]) -> &Self::Output {
        assert!(index[0] <= self.height(), "i not in range");
        assert!(index[1] <= self.width(), "j not in range");
        self.get(index[0], index[1]).unwrap()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SharedSecret<E: Curve, H: Digest + Clone> {
    pub Ŝ: Vec<Point<E>>,
    pub π: LdeiProof<E, H>,
}

#[derive(Debug, Clone)]
pub enum SharingError {
    MismatchedPolynomialDegree {
        degree: PolynomialDegree,
        expected_degree_at_most: u16,
    },
    LdeiProve(InvalidLdeiStatement),
}

/// Shares local secret using Packed PVSS
///
/// Takes a polynomial $f$ of degree at most $t + \ell - 1$ that encodes local secrets
/// $s_j = f(-j), j \in \[0; \ell-1]$, produces $n$ shares $Ŝ_i = f(i) \cdot \pk_i, i \in \[1;n]$,
/// such as any set of $t+\ell$ honest parties can recover $(s_0 G, \dots, s_{\ell-1} G)$,
/// and also produces a proof that shares are valid.
pub fn sharing<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    f: &Polynomial<E>,
) -> Result<SharedSecret<E, H>, SharingError> {
    if !(f.degree() <= setup.t + setup.l - 1) {
        return Err(SharingError::MismatchedPolynomialDegree {
            degree: f.degree(),
            expected_degree_at_most: setup.t + setup.l - 1,
        });
    }

    let σ = f.evaluate_many_bigint(1..=setup.n).collect::<Vec<_>>();
    let Ŝ = setup
        .pk
        .iter()
        .zip(&σ)
        .map(|(pk_i, σ_i)| pk_i * σ_i)
        .collect::<Vec<_>>();

    let stmt = LdeiStatement {
        alpha: (1..=setup.n).map(Scalar::from).collect(),
        g: setup.pk.clone(),
        x: Ŝ.clone(),
        d: setup.t + setup.l - 1,
    };
    let witness = LdeiWitness { w: f.clone() };
    let π = LdeiProof::prove(&witness, &stmt).map_err(SharingError::LdeiProve)?;

    Ok(SharedSecret { Ŝ, π })
}

/// Checks if [SharedSecret] is correctly shared by checking the proof
pub fn is_secret_correctly_shared<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    shared_secret: &SharedSecret<E, H>,
) -> Result<(), ProofError> {
    let stmt = LdeiStatement {
        alpha: (1..=setup.n).map(Scalar::from).collect(),
        g: setup.pk.clone(),
        x: shared_secret.Ŝ.clone(),
        d: setup.t + setup.l - 1,
    };

    shared_secret.π.verify(&stmt)
}

pub type OpenedSecrets<E> = BTreeMap<u16, OpenedSecret<E>>;
pub type OpenedSecret<E> = Vec<Point<E>>;
pub type PartiesWhoDidntOpenTheirSecrets = Vec<u16>;

#[derive(Debug, Clone)]
pub enum OpenedSecretsVerificationError {
    UnexpectedLengthOfSharedSecrets { len: usize, expected: u16 },
    UnexpectedLengthOfOpenedSecrets { len: usize, expected: u16 },
    UnexpectedNumberOfSharedSecrets { expected: u16, actual: u16 },
    CorrectlyOpenedSecretsOverride { i: u16 },
}

/// Verifies that `opened_secrets` are consistent with `shared_secrets` posted before
///
/// Returns a list of parties who incorrectly opened their secrets. If it's nonempty, then additional
/// round of communication is required — parties need to collaborate with each other to open secrets.
///
/// Note that `shared_secrets` must contain exactly $n - t$ valid shares (first $n - t$ valid shares
/// posted on board), messages from other parties must be `None` (even if they published valid shares,
/// but didn't manage to do it quick enough)
pub fn validate_opened_secrets<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    shared_secrets: &Msgs<SharedSecret<E, H>>,
    opened_secrets: &Msgs<Polynomial<E>>,
    correctly_opened_secrets: &mut OpenedSecrets<E>,
) -> Result<PartiesWhoDidntOpenTheirSecrets, OpenedSecretsVerificationError> {
    let mut parties_who_didnt_open_their_secrets = vec![];
    let mut shared_secrets_num = 0u16;

    let secrets = shared_secrets
        .iter()
        .zip(opened_secrets)
        .enumerate_u16()
        .flat_map(|(i, (com, revealed))| Some((i, com.as_ref()?, revealed.as_ref())))
        .inspect(|_| shared_secrets_num += 1);

    for (i, com, revealed) in secrets {
        let revealed = match revealed {
            Some(p) if p.degree() <= setup.t + setup.l - 1 => p,
            _ => {
                parties_who_didnt_open_their_secrets.push(i);
                continue;
            }
        };

        let expected_com = setup
            .pk
            .iter()
            .zip(revealed.evaluate_many_bigint(1..=setup.n))
            .map(|(pk_i, σ_i)| pk_i * σ_i)
            .collect::<Vec<_>>();

        if com.Ŝ != expected_com {
            parties_who_didnt_open_their_secrets.push(i);
            continue;
        }

        let s = revealed
            .evaluate_many_bigint(-i32::from(setup.l - 1)..=0)
            .map(|s_i| Point::generator() * s_i)
            .collect();

        let overwritten = correctly_opened_secrets.insert(i, s).is_some();
        if overwritten {
            return Err(OpenedSecretsVerificationError::CorrectlyOpenedSecretsOverride { i });
        }
    }

    if shared_secrets_num != setup.n - setup.t {
        return Err(
            OpenedSecretsVerificationError::UnexpectedNumberOfSharedSecrets {
                expected: setup.n - setup.t,
                actual: shared_secrets_num,
            },
        );
    }

    Ok(parties_who_didnt_open_their_secrets)
}

/// Partially opened secret
///
/// Secret can be recovered from any set of valid $t + \ell$ distinct partial openings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PartiallyOpenedSecret<E: Curve, H: Digest + Clone> {
    pub S: Point<E>,
    pub π: LdeiProof<E, H>,
}

#[derive(Debug, Clone)]
pub enum PartiallyOpenSecretError {
    ZeroSk,
    IncorrectSharedSecret,
    LdeiProve(InvalidLdeiStatement),
}

/// Partially opens a correctly shared secret
pub fn partially_open_secret<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    shared_secret: &SharedSecret<E, H>,
) -> Result<PartiallyOpenedSecret<E, H>, PartiallyOpenSecretError> {
    let sk_i_inv = setup
        .sk_i
        .invert()
        .ok_or(PartiallyOpenSecretError::ZeroSk)?;
    let Ŝ_i = shared_secret
        .Ŝ
        .get(usize::from(setup.i))
        .ok_or(PartiallyOpenSecretError::IncorrectSharedSecret)?;
    let S_i = Ŝ_i * &sk_i_inv;

    let w = Polynomial::from_coefficients(vec![setup.sk_i.clone()]);
    let stmt = LdeiStatement {
        alpha: vec![Scalar::from(1), Scalar::from(2)],
        g: vec![Point::generator().to_point(), S_i.clone()],
        x: vec![setup.pk_i.clone(), Ŝ_i.clone()],
        d: 0,
    };
    let π =
        LdeiProof::prove(&LdeiWitness { w }, &stmt).map_err(PartiallyOpenSecretError::LdeiProve)?;

    Ok(PartiallyOpenedSecret { S: S_i, π })
}

pub enum InvalidPartialOpening {
    PartyIndexOutOfRange { i: u16, n: u16 },
    IncorrectSharedSecret,
    ProofError,
}

/// Verifies correctness of partial opening
pub fn validate_partially_opened_secret<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    party_i: u16,
    shared_secret: &SharedSecret<E, H>,
    partially_opened: &PartiallyOpenedSecret<E, H>,
) -> Result<(), InvalidPartialOpening> {
    if party_i >= setup.n {
        return Err(InvalidPartialOpening::PartyIndexOutOfRange {
            i: party_i,
            n: setup.n,
        });
    }

    let pk_i = &setup.pk[usize::from(party_i)];
    let Ŝ_i = shared_secret
        .Ŝ
        .get(usize::from(party_i))
        .ok_or(InvalidPartialOpening::IncorrectSharedSecret)?;

    let stmt = LdeiStatement {
        alpha: vec![Scalar::from(1), Scalar::from(2)],
        g: vec![Point::generator().to_point(), partially_opened.S.clone()],
        x: vec![pk_i.clone(), Ŝ_i.clone()],
        d: 0,
    };
    partially_opened
        .π
        .verify(&stmt)
        .or(Err(InvalidPartialOpening::ProofError))
}

#[derive(Debug, Clone)]
pub enum OpenSharedSecretError {
    MismatchedNumberOfParties { expected: u16, actual: usize },
    MismatchedNumberOfOpenings { expected: u16, actual: usize },
}

/// Opens committed secrets from $t+\ell$ partial openings
///
/// Assumes that partial openings are verified to be valid using [validate_partially_opened_secret].
pub fn open_shared_secret<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    parties_who_provided_partial_openings: &[u16],
    partial_openings: &[PartiallyOpenedSecret<E, H>],
) -> Result<OpenedSecret<E>, OpenSharedSecretError> {
    if parties_who_provided_partial_openings.len() != usize::from(setup.t + setup.l) {
        return Err(OpenSharedSecretError::MismatchedNumberOfParties {
            expected: setup.t + setup.l,
            actual: parties_who_provided_partial_openings.len(),
        });
    }
    if partial_openings.len() != usize::from(setup.t + setup.l) {
        return Err(OpenSharedSecretError::MismatchedNumberOfOpenings {
            expected: setup.t + setup.l,
            actual: parties_who_provided_partial_openings.len(),
        });
    }
    let xs = parties_who_provided_partial_openings
        .iter()
        .map(|i| Scalar::from(i + 1))
        .collect::<Vec<_>>();

    let mut opened_secrets = vec![Point::zero(); usize::from(setup.l)];
    for (i, partial_opening) in partial_openings.iter().enumerate_u16() {
        for (x, s) in opened_secrets.iter_mut().enumerate_u16() {
            let x = Scalar::from(i32::from(x) - i32::from(setup.l - 1));
            *s = &*s + &partial_opening.S * Polynomial::lagrange_basis(&x, i, &xs);
        }
    }

    Ok(opened_secrets)
}

pub struct OpenedSecretsMatrix<E: Curve> {
    matrix: Vec<Point<E>>,
    w: u16,
    h: u16,
}

impl<E: Curve> OpenedSecretsMatrix<E> {
    pub fn width(&self) -> u16 {
        self.w
    }

    pub fn height(&self) -> u16 {
        self.h
    }

    pub fn get(&self, i: u16, j: u16) -> Option<&Point<E>> {
        if i >= self.height() || j >= self.width() {
            return None;
        }
        Some(
            self.matrix
                .get(usize::from(i) * usize::from(self.width()) + usize::from(j))
                .expect("i, j are valid"),
        )
    }
}

impl<E: Curve> From<OpenedSecrets<E>> for OpenedSecretsMatrix<E> {
    fn from(s: OpenedSecrets<E>) -> Self {
        let h = u16::try_from(s.len()).unwrap();
        let w = match s.values().next() {
            Some(row) => u16::try_from(row.len()).unwrap(),
            None => 0,
        };

        let mut matrix = Vec::with_capacity(usize::from(w) * usize::from(h));
        for s in s.values() {
            matrix.extend_from_slice(s);
        }
        Self { matrix, w, h }
    }
}

impl<E: Curve> ops::Index<[u16; 2]> for OpenedSecretsMatrix<E> {
    type Output = Point<E>;

    fn index(&self, index: [u16; 2]) -> &Self::Output {
        assert!(index[0] < self.height(), "i is out of range");
        assert!(index[1] < self.width(), "j is out of range");
        self.get(index[0], index[1]).unwrap()
    }
}

#[derive(Debug, Clone)]
pub enum ExtractRandomnessError {
    MismatchedOpenedSecretsMatrixSize {
        w: u16,
        h: u16,
        expected_w: u16,
        expected_h: u16,
    },
}

/// Extracts randomness from matrix of correctly opened secrets
pub fn extract_randomness<E: Curve, H: Digest + Clone>(
    setup: &ProtocolSetup<E, H>,
    secrets: &OpenedSecretsMatrix<E>,
) -> Result<Vec<Point<E>>, ExtractRandomnessError> {
    if !(secrets.height() == setup.n - setup.t && secrets.width() == setup.l) {
        return Err(ExtractRandomnessError::MismatchedOpenedSecretsMatrixSize {
            w: secrets.width(),
            h: secrets.height(),
            expected_w: setup.l,
            expected_h: setup.n - setup.t,
        });
    }

    let mut randomness = Vec::with_capacity(usize::from(setup.lʹ) * usize::from(setup.l));
    for k in 0..setup.lʹ {
        for j in 0..setup.l {
            let o = (0..secrets.height())
                .map(|a| &setup.M[[k, a]] * &secrets[[a, j]])
                .sum();
            randomness.push(o);
        }
    }

    Ok(randomness)
}
