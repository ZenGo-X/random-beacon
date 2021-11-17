use std::collections::HashMap;

use sha2::{Digest};

use curv::cryptographic_primitives::proofs::low_degree_exponent_interpolation::{
    LdeiProof, LdeiStatement, LdeiWitness,
};
use curv::cryptographic_primitives::secret_sharing::Polynomial;
use curv::elliptic::curves::*;

use crate::utils::IteratorExt;

pub struct ElgamalLocalShare<E: Curve, H: Digest + Clone> {
    /// `x` coordinate of party's local secret (ie. in terms of elgamal protocol -
    /// index of the party)
    local_share_x: u16,
    /// Local party secret `y = f(x)`
    local_share_y: Scalar<E>,
    /// Committed local party secret (ie. local party partial public key)
    local_share_y_com: Point<E>,
    _hash_choice: curv::HashChoice<H>,
}

#[derive(PartialEq, Clone, Debug)]
pub struct ElgamalPublicKey<E: Curve> {
    pub pk: Point<E>,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ElgamalPartialPublicKey<E: Curve> {
    pub pk_i: Point<E>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ciphertext<E: Curve> {
    pub c: Point<E>,
    pub d: Point<E>,
}

/// Partial decryption produced by one of the parties
///
/// Contains a proof that decryption is correct. To decrypt a certain ciphertext,
/// you need to grab `t+1` distinct correct partial decryptions.
pub struct ElgamalPartialDecryption<E: Curve, H: Digest + Clone> {
    /// Index of the party who performed local decryption
    pub x: u16,
    /// Decryption
    pub partial_decryption: Point<E>,
    /// Proof that decryption was performed correctly
    pub proof: LdeiProof<E, H>,
}

/// Decrypts ciphertext from given list of partial decryptions
#[derive(Clone, PartialEq, Debug)]
pub struct ElgamalDecrypt<E: Curve> {
    /// Maps party index (its `local_share_x`) to its partial public key
    /// (`local_share_y_com`)
    ///
    /// It might contain gaps — ie. some partial pk might be missing. It
    /// doesn't matter if these parties are not going to participate in
    /// the decryption.
    q: HashMap<u16, ElgamalPartialPublicKey<E>>,
    /// Threshold value of the distributed key
    t: u16,
}

pub struct ElgamalDecryption<'k, E: Curve> {
    key_info: &'k ElgamalDecrypt<E>,
    ciphertext: &'k Ciphertext<E>,

    x: Vec<Scalar<E>>,
    y: Vec<Point<E>>,
}

#[derive(Debug)]
pub struct DecryptionError;

#[derive(Debug)]
pub struct InvalidPartialDecryption;

impl<E: Curve> ElgamalPublicKey<E> {
    pub fn new(pk: Point<E>) -> Self {
        Self { pk }
    }

    pub fn encrypt(&self, plaintext: &Point<E>) -> Ciphertext<E> {
        self.encrypt_with_randomness(plaintext, &Scalar::random())
    }

    pub fn encrypt_with_randomness(
        &self,
        plaintext: &Point<E>,
        randomness: &Scalar<E>,
    ) -> Ciphertext<E> {
        Ciphertext {
            c: Point::generator() * randomness,
            d: plaintext + &self.pk * randomness,
        }
    }
}

impl<E: Curve> ElgamalPartialPublicKey<E> {
    pub fn new(pk_i: Point<E>) -> Self {
        Self { pk_i }
    }

    pub fn validate_partial_decryption<H: Digest + Clone>(
        &self,
        ciphertext: &Ciphertext<E>,
        partial_decryption: &ElgamalPartialDecryption<E, H>,
    ) -> Result<(), InvalidPartialDecryption> {
        let stmt = LdeiStatement {
            alpha: vec![Scalar::from(1), Scalar::from(2)],
            g: vec![Point::generator().to_point(), ciphertext.c.clone()],
            x: vec![
                self.pk_i.clone(),
                partial_decryption.partial_decryption.clone(),
            ],
            d: 0,
        };

        partial_decryption
            .proof
            .verify(&stmt)
            .or(Err(InvalidPartialDecryption))
    }
}

impl<E: Curve, H: Digest + Clone> ElgamalLocalShare<E, H> {
    /// Constructs party's local share from its `x` and `y = f(x)` coordinates
    pub fn new(x: u16, y: Scalar<E>) -> Self {
        Self {
            local_share_y_com: Point::generator() * &y,
            local_share_y: y,
            local_share_x: x,
            _hash_choice: curv::HashChoice::new(),
        }
    }

    pub fn decrypt_locally(
        &self,
        ciphertext: &Ciphertext<E>,
    ) -> ElgamalPartialDecryption<E, H> {
        let partial_decryption = &self.local_share_y * &ciphertext.c;

        let f = Polynomial::from_coefficients(vec![self.local_share_y.clone()]);
        let stmt = LdeiStatement {
            alpha: vec![Scalar::from(1), Scalar::from(2)],
            g: vec![Point::generator().to_point(), ciphertext.c.clone()],
            x: vec![self.local_share_y_com.clone(), partial_decryption.clone()],
            d: 0,
        };
        let proof = LdeiProof::prove(&LdeiWitness { w: f }, &stmt).expect("prove must not fail");
        ElgamalPartialDecryption {
            x: self.local_share_x,
            partial_decryption,
            proof,
        }
    }

    pub fn partial_pk(&self) -> ElgamalPartialPublicKey<E> {
        ElgamalPartialPublicKey {
            pk_i: self.local_share_y_com.clone(),
        }
    }
}

impl<E: Curve> ElgamalDecrypt<E> {
    /// Constructs ElgamalDecrypt from key threshold value `t`, and a set of parties indexes mapped
    /// to their partial public keys
    pub fn new(t: u16, q: HashMap<u16, ElgamalPartialPublicKey<E>>) -> Self {
        Self { t, q }
    }

    /// Decrypts a ciphertext with given partial decryptions
    ///
    /// Fails if not sufficient valid partial decryptions were provided. Note that it might fail
    /// even if `partial_decryptions.len() >= t+1` as some of partial decryption might be invalid.
    /// To validate correctness of partial decryption use [validate_partial_decryption]
    ///
    /// [validate_partial_decryption]: ElgamalPartialPublicKey::validate_partial_decryption
    pub fn decrypt<'d, H: Digest + Clone + 'static>(
        &self,
        ciphertext: &Ciphertext<E>,
        partial_decryptions: impl IntoIterator<Item = &'d ElgamalPartialDecryption<E, H>>,
    ) -> Result<Point<E>, DecryptionError> {
        let mut decryption = self.decryption(ciphertext);
        for partial_decryption in partial_decryptions {
            let _ = decryption.add_partial_decryption(partial_decryption);
        }
        decryption.complete()
    }

    /// Initiates decryption
    ///
    /// In order to decrypt given `ciphertext`, you'll need to provide sufficient amount of partial
    /// decryptions (see [add_partial_decryption](ElgamalDecryption::add_partial_decryption)).
    pub fn decryption<'k>(&'k self, ciphertext: &'k Ciphertext<E>) -> ElgamalDecryption<'k, E> {
        ElgamalDecryption {
            key_info: self,
            ciphertext,
            x: vec![],
            y: vec![],
        }
    }
}

impl<'k, E: Curve> ElgamalDecryption<'k, E> {
    pub fn add_partial_decryption<H: Digest + Clone>(
        &mut self,
        partial_decryption: &ElgamalPartialDecryption<E, H>,
    ) -> Result<(), InvalidPartialDecryption> {
        let x_scalar = Scalar::from(partial_decryption.x);
        if self.x.contains(&x_scalar) {
            return Err(InvalidPartialDecryption);
        }

        let pk_i = match self.key_info.q.get(&partial_decryption.x) {
            Some(p) => &p.pk_i,
            None => return Err(InvalidPartialDecryption),
        };

        let stmt = LdeiStatement {
            alpha: vec![Scalar::from(1), Scalar::from(2)],
            g: vec![Point::generator().to_point(), self.ciphertext.c.clone()],
            x: vec![pk_i.clone(), partial_decryption.partial_decryption.clone()],
            d: 0,
        };

        let valid = partial_decryption.proof.verify(&stmt).is_ok();
        if !valid {
            return Err(InvalidPartialDecryption);
        }

        self.x.push(x_scalar);
        self.y.push(partial_decryption.partial_decryption.clone());

        Ok(())
    }

    pub fn is_completed(&self) -> bool {
        self.x.len() >= usize::from(self.key_info.t) + 1
    }

    pub fn complete(self) -> Result<Point<E>, DecryptionError> {
        if !self.is_completed() {
            return Err(DecryptionError);
        }

        let y = &self.y[..usize::from(self.key_info.t) + 1];
        let x = &self.x[..usize::from(self.key_info.t) + 1];

        let y: Point<E> = y
            .iter()
            .enumerate_u16()
            .map(|(i, y_i)| y_i * Polynomial::lagrange_basis(&Scalar::zero(), i, x))
            .sum();

        Ok(&self.ciphertext.d - y)
    }
}

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::*;
    use sha2::Sha256;

    use crate::keygen::tests::KeygenSimulation;

    use super::*;

    fn keygen(
        t: u16,
        n: u16,
    ) -> (
        Vec<ElgamalLocalShare<Secp256k1, Sha256>>,
        ElgamalDecrypt<Secp256k1>,
        ElgamalPublicKey<Secp256k1>,
    ) {
        let keygen = KeygenSimulation::<Secp256k1, Sha256>::setup(t, n);
        let phase0 = keygen.phase0_generate_parties_local_secrets();
        let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
        let phase2 = keygen.phase2_decrypt_shares(&phase1);
        keygen.phase3_skipped(&phase2);
        keygen.phase4_skipped(&phase2, None);
        let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, None, None);
        let phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);
        let phase7 = keygen.phase7_validate_shares_commitments(&phase5, &phase6);
        keygen.phase8_construct_elgamal_keys(&phase6, &phase7)
    }

    #[test]
    fn encrypt_decrypt_t1_n3() {
        let (tsk, threshold_decryption, tpk) = keygen(1, 3);

        let plaintext = Point::generator() * Scalar::random();
        let ciphertext = tpk.encrypt(&plaintext);

        let partial1 = tsk[0].decrypt_locally(&ciphertext);
        let partial2 = tsk[1].decrypt_locally(&ciphertext);

        let decrypted = threshold_decryption
            .decrypt(&ciphertext, [&partial1, &partial2])
            .unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn tpk_is_correct() {
        let (tsk, _decryption, tpk) = keygen(1, 3);

        let s = [Scalar::from(1), Scalar::from(2)];
        let share1 = Point::generator()
            * &tsk[0].local_share_y
            * Polynomial::lagrange_basis(&Scalar::zero(), 0, &s);
        let share2 = Point::generator()
            * &tsk[1].local_share_y
            * Polynomial::lagrange_basis(&Scalar::zero(), 1, &s);

        assert_eq!(tpk.pk, share1 + share2);
    }

    /// Tests shows how encryption/decryption work
    #[test]
    fn manual_encrypt_decrypt_t1_n3() {
        let (tsk, _decryption, tpk) = keygen(1, 3);

        let plaintext = Point::generator() * Scalar::random();

        let encryption_randomness = Scalar::random();
        let ciphertext_c = Point::generator() * &encryption_randomness;
        let ciphertext_d = &plaintext + &encryption_randomness * &tpk.pk;
        drop(encryption_randomness);

        let share1 = &ciphertext_c * &tsk[0].local_share_y;
        let share2 = &ciphertext_c * &tsk[1].local_share_y;

        let s = [Scalar::from(1), Scalar::from(2)];
        let y_1 = share1 * Polynomial::lagrange_basis(&Scalar::zero(), 0, &s);
        let y_2 = share2 * Polynomial::lagrange_basis(&Scalar::zero(), 1, &s);

        let y = y_1 + y_2;

        let decrypted = ciphertext_d - y;

        assert_eq!(plaintext, decrypted);
    }
}
