use std::collections::HashSet;
use std::iter::FromIterator;
use std::{iter, ops};

use rand::rngs::SmallRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;

use curv::arithmetic::*;
use curv::cryptographic_primitives::secret_sharing::Polynomial;
use curv::elliptic::curves::*;

use crate::elgamal::{ElgamalDecrypt, ElgamalLocalShare, ElgamalPublicKey};
use crate::keygen::core::*;
use crate::utils::IteratorExt;
use std::time::{Duration, Instant};

pub struct KeygenSimulation<E: Curve> {
    parties: Vec<ProtocolSetup<E>>,
    t: u16,
    n: u16,
    pk: Vec<Point<E>>,
}

impl<E: Curve> KeygenSimulation<E> {
    pub fn setup(t: u16, n: u16) -> Self {
        let sk = iter::repeat_with(|| Scalar::<E>::random())
            .take(usize::from(n))
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .map(|sk_i| Point::generator() * sk_i)
            .collect::<Vec<_>>();
        let parties = sk
            .into_iter()
            .map(|sk_i| ProtocolSetup::new(sk_i, pk.clone(), t).unwrap())
            .collect();
        Self { parties, t, n, pk }
    }

    pub fn phase0_generate_parties_local_secrets(&self) -> Phase0GeneratedLocalSecrets<E> {
        let mut f = vec![];
        let mut took = vec![];

        for _ in 0..self.n {
            let start = Instant::now();
            let s_i = Scalar::random();
            let f_i = Polynomial::sample_exact_with_fixed_const_term(self.t, s_i);
            took.push(start.elapsed());
            f.push(f_i);
        }
        Phase0GeneratedLocalSecrets { f, took }
    }

    pub fn phase1_share_and_commit_shares(
        &self,
        phase0: &Phase0GeneratedLocalSecrets<E>,
    ) -> Phase1SharedAndCommittedSecret<E> {
        let mut encrypted_shares = vec![];
        let mut took = vec![];

        for i in 0..self.n {
            let start = Instant::now();
            encrypted_shares.push(
                share_local_secret(&self.parties[usize::from(i)], &phase0.f[usize::from(i)])
                    .expect(&format!("sharing secret failed for party {}", i)),
            );
            took.push(start.elapsed());
        }
        Phase1SharedAndCommittedSecret {
            board: encrypted_shares.iter().map(|m| Some(m.clone())).collect(),

            encrypted_shares,

            took,
        }
    }

    pub fn phase2_decrypt_shares(
        &self,
        phase1: &Phase1SharedAndCommittedSecret<E>,
    ) -> Phase2DecryptedShares<E> {
        let mut disqualified = vec![];
        let mut complaints = vec![];
        let mut decrypted_shares = vec![];
        let mut board = vec![];
        let mut took = vec![];

        for (i, party_setup) in self.parties.iter().enumerate_u16() {
            let start = Instant::now();
            let mut disqualified_i = DisqualifiedParties::new();
            let (decrypted_shares_i, complaints_i) =
                decrypt_shares(party_setup, &mut disqualified_i, &phase1.board)
                    .expect(&format!("decrypt_shares failed for party {}", i));
            took.push(start.elapsed());

            disqualified.push(disqualified_i);
            complaints.push(complaints_i.clone());
            decrypted_shares.push(decrypted_shares_i);

            board.push(Some(complaints_i));
        }

        Phase2DecryptedShares {
            disqualified,
            complaints,
            decrypted_shares,
            board,
            took,
        }
    }

    pub fn phase3_process_complaints_and_publish_justifications(
        &self,
        phase0: &Phase0GeneratedLocalSecrets<E>,
        phase2: &Phase2DecryptedShares<E>,
    ) -> Phase3PublishedJustifications<E> {
        let mut justification_required_for = vec![];
        let mut justifications = vec![];
        let mut disqualified = vec![];
        let mut board = vec![];
        let mut took = vec![];

        for (i, (party_setup, f)) in self.parties.iter().zip(&phase0.f).enumerate_u16() {
            let start = Instant::now();
            let mut disqualified_i = DisqualifiedParties::new();
            let (justification_i, justification_required_for_i) =
                process_complaints(&party_setup, f, &mut disqualified_i, &phase2.board)
                    .expect(&format!("process_complaints failed for party {}", i));
            took.push(start.elapsed());

            justification_required_for.push(justification_required_for_i);
            justifications.push(justification_i.clone());
            disqualified.push(disqualified_i);
            board.push(Some(justification_i));
        }

        Phase3PublishedJustifications {
            justification_required_for,
            justifications,
            disqualified,
            board,
            took,
        }
    }

    pub fn phase3_skipped(&self, phase2: &Phase2DecryptedShares<E>) {
        for complaints in &phase2.board {
            assert!(complaints.as_ref().map(|c| c.0.is_empty()).unwrap_or(true));
        }
    }

    pub fn phase4_process_justifications(
        &self,
        phase1: &Phase1SharedAndCommittedSecret<E>,
        phase3: &Phase3PublishedJustifications<E>,
    ) -> Phase4ProcessedJustifications {
        let mut disqualified = vec![];
        let mut took = vec![];

        for (i, (party_setup, justification_required_for)) in self
            .parties
            .iter()
            .zip(&phase3.justification_required_for)
            .enumerate()
        {
            let start = Instant::now();
            let mut disqualified_i = DisqualifiedParties::new();
            process_justifications(
                party_setup,
                &mut disqualified_i,
                justification_required_for,
                &phase1.board,
                &phase3.board,
            )
            .expect(&format!("process_justifications failed for party {}", i));

            took.push(start.elapsed());
            disqualified.push(disqualified_i);
        }

        Phase4ProcessedJustifications { disqualified, took }
    }

    pub fn phase4_skipped(
        &self,
        phase2: &Phase2DecryptedShares<E>,
        phase3: Option<&Phase3PublishedJustifications<E>>,
    ) {
        if let Some(phase3) = phase3 {
            for jrf in &phase3.justification_required_for {
                assert!(jrf.is_empty());
            }
        } else {
            self.phase3_skipped(phase2)
        }
    }

    pub fn phase5_deduce_set_Q(
        &self,
        phase1: &Phase1SharedAndCommittedSecret<E>,
        phase2: &Phase2DecryptedShares<E>,
        phase3: Option<&Phase3PublishedJustifications<E>>,
        phase4: Option<&Phase4ProcessedJustifications>,
    ) -> Phase5SetQ<E> {
        let mut Q = vec![];
        let mut encrypted_shares = vec![];
        let mut decrypted_shares = vec![];
        let mut took = vec![];

        for i in 0..self.n {
            let mut disqualified = DisqualifiedParties::new();
            if let Some(phase4) = phase4 {
                disqualified.extend(&phase4.disqualified[usize::from(i)]);
            }
            if let Some(phase3) = phase3 {
                disqualified.extend(&phase3.disqualified[usize::from(i)]);
            }
            disqualified.extend(&phase2.disqualified[usize::from(i)]);

            let start = Instant::now();
            let Q_i = deduce_set_Q(self.n, &disqualified);
            let encrypted_shares_i =
                filter_out_disqualified(phase1.board.clone(), self.n, &disqualified);
            let decrypted_shares_i = filter_out_disqualified(
                phase2.decrypted_shares[usize::from(i)].clone(),
                self.n,
                &disqualified,
            );

            took.push(start.elapsed());
            Q.push(Q_i);
            encrypted_shares.push(encrypted_shares_i);
            decrypted_shares.push(decrypted_shares_i);
        }

        Phase5SetQ {
            Q,
            encrypted_shares,
            decrypted_shares,
            took,
        }
    }

    pub fn phase6_construct_and_commit_local_secret(
        &self,
        phase5: &Phase5SetQ<E>,
    ) -> Phase6ConstructedAndCommittedLocalSecret<E> {
        let mut parties_secrets = vec![];
        let mut committed_parties_secrets = vec![];
        let mut board = vec![];
        let mut took = vec![];

        for i in 0..self.n {
            let start = Instant::now();
            let (local_secret, committed_secret) = construct_and_commit_local_secret(
                &self.parties[usize::from(i)],
                &phase5.Q[usize::from(i)],
                &phase5.decrypted_shares[usize::from(i)],
            )
            .unwrap();

            took.push(start.elapsed());
            parties_secrets.push(local_secret);
            committed_parties_secrets.push(committed_secret.clone());
            board.push(Some(committed_secret));
        }

        Phase6ConstructedAndCommittedLocalSecret {
            parties_secrets,
            committed_parties_secrets,
            board,
            took,
        }
    }

    pub fn phase7_validate_shares_commitments(
        &self,
        phase5: &Phase5SetQ<E>,
        phase6: &Phase6ConstructedAndCommittedLocalSecret<E>,
    ) -> Phase7ValidatedPartiesShares<E> {
        self.phase7_validate_shares_commitments_with_i2j(
            phase5,
            phase6,
            &vec![DefaultI2J; usize::from(self.n)],
        )
    }

    pub fn phase7_validate_shares_commitments_with_i2j(
        &self,
        phase5: &Phase5SetQ<E>,
        phase6: &Phase6ConstructedAndCommittedLocalSecret<E>,
        i2j: &[impl I2J],
    ) -> Phase7ValidatedPartiesShares<E> {
        let mut tpk = vec![];
        let mut I = vec![];
        let mut took = vec![];

        for i in 0..self.n {
            let start = Instant::now();
            let (tpk_i, i) = verify_commitments_and_construct_tpk(
                &self.parties[usize::from(i)],
                &phase5.Q[usize::from(i)],
                &phase5.encrypted_shares[usize::from(i)],
                &phase6.board,
                &i2j[usize::from(i)],
            )
            .unwrap();
            took.push(start.elapsed());
            tpk.push(tpk_i);
            I.push(i);
        }

        Phase7ValidatedPartiesShares { tpk, I, took }
    }

    pub fn phase8_construct_elgamal_keys(
        &self,
        phase6: &Phase6ConstructedAndCommittedLocalSecret<E>,
        phase7: &Phase7ValidatedPartiesShares<E>,
    ) -> (
        Vec<ElgamalLocalShare<E>>,
        ElgamalDecrypt<E>,
        ElgamalPublicKey<E>,
    ) {
        let mut tsk = vec![];
        let mut tpk = None;
        let mut decrypt = None;
        let mut took = vec![];

        for i in 0..self.n {
            let start = Instant::now();
            let partial_pk = msgs_subset(
                phase6.board.iter().map(|m| m.as_ref().map(|m| &m.S)),
                &phase7.I[usize::from(i)],
            );
            let (tsk_i, decrypt_i, tpk_i) = construct_elgamal_keys(
                &self.parties[usize::from(i)],
                &phase7.I[usize::from(i)],
                &partial_pk,
                phase6.parties_secrets[usize::from(i)].clone(),
                phase7.tpk[usize::from(i)].clone(),
            );
            took.push(start.elapsed());
            tsk.push(tsk_i);

            if let Some(tpk) = &tpk {
                assert_eq!(tpk, &tpk_i)
            }
            if let Some(decrypt) = &decrypt {
                assert_eq!(decrypt, &decrypt_i);
            }

            tpk = Some(tpk_i);
            decrypt = Some(decrypt_i)
        }

        (tsk, decrypt.unwrap(), tpk.unwrap())
    }
}

impl<E: Curve> ops::Index<u16> for KeygenSimulation<E> {
    type Output = ProtocolSetup<E>;
    fn index(&self, index: u16) -> &Self::Output {
        self.parties.get(usize::from(index)).unwrap()
    }
}

pub struct Phase0GeneratedLocalSecrets<E: Curve> {
    /// `f_i` is a polynomial of degree at most `t` that were used by i-th party in
    /// order to derive its shares
    ///
    /// `f_i(0)` is a local secret generated by i-th party, and `σ_j = f_i(j)` is a share
    /// sent to j-th party encrypted with `pk_j`
    pub f: Vec<Polynomial<E>>,

    /// $\text{took}_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase1SharedAndCommittedSecret<E: Curve> {
    /// `encrypted_shares[i]` is a message that i-th party supposed to publish on board
    pub encrypted_shares: Vec<EncryptedSecretShares<E>>,

    /// List of messages that was published on bulletin board. `board[i]` is a message
    /// published by i-th party. `board[i]` being `None` means that i-th party didn't
    /// manage to publish its message in time.
    pub board: Msgs<EncryptedSecretShares<E>>,

    /// $\text{took}_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase2DecryptedShares<E: Curve> {
    /// `disqualified[i]` is a set of disqualified parties at phase 2 from point of view of
    /// i-th party
    pub disqualified: Vec<DisqualifiedParties>,
    /// `complaints[i]` is a list of complaints sey by i-th party
    pub complaints: Vec<Complaints>,
    /// `decrypted_shares[i][j]` is a decrypted share that was sent by j-th party,
    /// and received by i-th party. `decrypted_shares[i][j]` being `None` means that
    /// i-th party wasn't able to decrypt a share sent by j-th party.
    pub decrypted_shares: Vec<Vec<Option<DecryptedSecretShare<E>>>>,

    /// List of messages that was published on bulletin board. `board[i]` is a
    /// message published by i-th party. `board[i]` being `None` means that i-th
    /// party didn't manage to publish its message in time.
    pub board: Msgs<Complaints>,

    /// $\text{took}_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase3PublishedJustifications<E: Curve> {
    /// `justification_required_for[i]` is a set of parties who's required to publish a justification
    /// (from point of view of i-th party)
    pub justification_required_for: Vec<JustificationRequiredFor>,
    /// `justifications[i]` is a justification message produced by i-th party
    pub justifications: Vec<Justification<E>>,
    /// `disqualified[i]` is a set of disqualified parties at phase 3 from point of view of
    /// i-th party
    pub disqualified: Vec<DisqualifiedParties>,

    /// List of messages that was published on bulletin board. `board[i]` is a
    /// message published by i-th party. `board[i]` being `None` means that i-th
    /// party didn't manage to publish its message in time.
    pub board: Msgs<Justification<E>>,

    /// $\text{took}_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase4ProcessedJustifications {
    /// `disqualified[i]` is a set of disqualified parties at phase 4 from point of view of
    /// i-th party
    pub disqualified: Vec<DisqualifiedParties>,

    /// $\text{took}_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase5SetQ<E: Curve> {
    /// `Q[i]` is a set of parties who didn't get disqualified from i-th party perspective
    pub Q: Vec<HashSet<u16>>,
    /// `encrypted_shares[i]` is a list of messages sent at [phase1_share_and_commit_shares](KeygenSimulation::phase1_share_and_commit_shares)
    /// and received by i-th party, filtered out from messages sent by parties that do not belong to set `Q[i]`
    pub encrypted_shares: Vec<Vec<EncryptedSecretShares<E>>>,
    /// `decrypted_shares[i]` is a list of decrypted shares obtained at [phase2_decrypt_shares](KeygenSimulation::phase2_decrypt_shares)
    /// by i-th party, filtered out from shares sent by parties that do not belong to set `Q[i]`
    pub decrypted_shares: Vec<Vec<DecryptedSecretShare<E>>>,

    /// $\text{took}_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase6ConstructedAndCommittedLocalSecret<E: Curve> {
    /// `parties_secrets[i]` is a local secret of i-th party
    pub parties_secrets: Vec<LocalPartySecret<E>>,
    /// `committed_parties_secrets[i]` is a proof that `parties_secrets[i]` was correctly constructed
    pub committed_parties_secrets: Vec<CommittedLocalPartySecret<E>>,

    /// List of messages that was published on bulletin board. `board[i]` is a
    /// message published by i-th party. `board[i]` being `None` means that i-th
    /// party didn't manage to publish its message in time.
    pub board: Msgs<CommittedLocalPartySecret<E>>,

    /// $\text{took}_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase7ValidatedPartiesShares<E: Curve> {
    /// `tpk[i]` is a resulting public key evaluated by i-th party
    pub tpk: Vec<Point<E>>,
    /// `I[i]` is a set of parties who provided a valid commitment (from i-th party
    /// perspective)
    pub I: Vec<Vec<u16>>,

    /// $\text{took}_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

#[test]
fn shares_and_commits_local_secret() {
    let setup = KeygenSimulation::<Secp256k1>::setup(1, 3);

    let s = Scalar::random();
    let f = Polynomial::sample_exact_with_fixed_const_term(setup.t, s);

    let _encrypted_shares = share_local_secret(&setup[0], &f).unwrap();
}

#[test]
fn must_discard_polynomial_of_degree_more_than_t() {
    let setup = KeygenSimulation::<Secp256k1>::setup(1, 3);

    let s = Scalar::random();
    let f = Polynomial::sample_exact_with_fixed_const_term(setup.t + 1, s);

    let result = share_local_secret(&setup[0], &f);
    assert!(matches!(
        result,
        Err(ShareLocalSecretError::PolynomialDegreeTooBig {
            degree,
            expected_degree_at_most,
        }) if degree == setup.t+1 && expected_degree_at_most == setup.t
    ));
}

#[test]
fn decrypts_shares() {
    // Encryption setup
    let setup = KeygenSimulation::<Secp256k1>::setup(1, 3);
    // Generate parties' local secrets
    let phase0 = setup.phase0_generate_parties_local_secrets();
    // Share parties' local secrets
    let phase1 = setup.phase1_share_and_commit_shares(&phase0);
    // Decrypt published shares
    let phase2 = setup.phase2_decrypt_shares(&phase1);

    // Assert that decrypted shares are what parties have encrypted
    for i in 0..setup.n {
        let shares_expected = phase0
            .f
            .iter()
            .map(|f_i| f_i.evaluate_bigint(i + 1))
            .map(|σ_i| {
                Some(DecryptedSecretShare {
                    Ŝ: &setup.pk[usize::from(i)] * &σ_i,
                    S: Point::generator() * &σ_i,
                    σ: σ_i,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(phase2.decrypted_shares[usize::from(i)], shares_expected);
    }

    // All ciphertexts are valid, so we assert that no complaints were set, and no parties
    // got disqualified
    for i in 0..setup.n {
        assert!(
            phase2.disqualified[usize::from(i)].is_empty(),
            "party {} has marked some parties as disqualified",
            i
        );
        assert!(
            phase2.complaints[usize::from(i)].0.is_empty(),
            "party {} set complaints",
            i
        );
    }
}

#[test]
fn parties_complain_against_incorrect_proof() {
    // Encryption setup
    let setup = KeygenSimulation::<Secp256k1>::setup(1, 3);
    // Generate parties' local secrets
    let phase0 = setup.phase0_generate_parties_local_secrets();
    // Share parties' local secrets
    let mut phase1 = setup.phase1_share_and_commit_shares(&phase0);
    // Slightly modify a proof of party 1
    phase1.board[1].as_mut().unwrap().π.a.swap(0, 1);
    // Decrypt published shares
    let phase2 = setup.phase2_decrypt_shares(&phase1);

    // All the parties must complain against party 1
    let complaint_expected = vec![Complaint {
        against: 1,
        reason: ComplaintReason::LdeiProof,
    }];
    for i in 0..setup.n {
        assert_eq!(phase2.complaints[usize::from(i)].0, complaint_expected);

        assert!(
            phase2.disqualified[usize::from(i)].is_empty(),
            "party {} has marked some parties as disqualified",
            i
        );
    }
}

#[test]
fn parties_complain_against_invalid_encryption() {
    // Encryption setup
    let setup = KeygenSimulation::<Secp256k1>::setup(1, 3);
    // Generate parties' local secrets
    let phase0 = setup.phase0_generate_parties_local_secrets();
    // Share parties' local secrets
    let mut phase1 = setup.phase1_share_and_commit_shares(&phase0);
    // Change ciphertext sent from party 0 to party 1
    phase1.board[0].as_mut().unwrap().E[1] = BigInt::sample(256);
    // Decrypt published shares
    let phase2 = setup.phase2_decrypt_shares(&phase1);

    // Party 1 must complain against party 0 encryption, other parties should set
    // no complaints
    for i in 0..setup.n {
        if i == 1 {
            let complaints_expected = vec![Complaint {
                against: 0,
                reason: ComplaintReason::Encryption,
            }];
            assert_eq!(phase2.complaints[usize::from(i)].0, complaints_expected);
        } else {
            assert!(
                phase2.complaints[usize::from(i)].0.is_empty(),
                "party {} set complaints",
                i
            );
        }
        assert!(
            phase2.disqualified[usize::from(i)].is_empty(),
            "party {} has marked some parties as disqualified",
            i
        );
    }
}

/// We use this helper functions to generate dummy encryption materials if prior protocol steps
/// were omitted
fn generate_dummy_polynomials<E: Curve>(t: u16, n: u16) -> Vec<Polynomial<E>> {
    iter::repeat_with(|| Polynomial::sample_exact(t))
        .take(usize::from(n))
        .collect()
}

#[test]
fn parties_who_received_more_than_t_complaints_against_their_proof_must_be_disqualified() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);

    // We generate dummy polynomials that are not expected to be used anyway
    let f = generate_dummy_polynomials(keygen.t, keygen.n);

    // List of complaints "published" on board. We simulate that parties 2,5,8,9 set complaint against
    // party 1 proof. Thus, party 1 must get disqualified.
    let no_complaints = Complaints(vec![]);
    let complaint_against_1 = Complaints(vec![Complaint {
        against: 1,
        reason: ComplaintReason::LdeiProof,
    }]);
    let complaints = vec![
        Some(no_complaints.clone()),       // party 0
        Some(no_complaints.clone()),       // party 1
        Some(complaint_against_1.clone()), // party 2
        Some(no_complaints.clone()),       // party 3
        Some(no_complaints.clone()),       // party 4
        Some(complaint_against_1.clone()), // party 5
        Some(no_complaints.clone()),       // party 6
        None,                              // party 7
        Some(complaint_against_1.clone()), // party 8
        Some(complaint_against_1.clone()), // party 9
    ];

    let expected_disqualified =
        DisqualifiedParties::from_iter([(1, DisqualificationReason::InvalidLdeiProof)]);
    for (i, party_setup) in keygen.parties.iter().enumerate() {
        let mut disqualified = DisqualifiedParties::new();

        let (justification_msg, justification_required_for) =
            process_complaints(&party_setup, &f[i], &mut disqualified, &complaints).unwrap();

        assert_eq!(disqualified, expected_disqualified);
        assert!(justification_msg.revealed_σ.is_empty());
        assert!(justification_required_for.is_empty());
    }
}

#[test]
fn parties_who_received_at_most_t_complaints_against_their_proof_dont_get_disqualified() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);

    // We generate dummy polynomials that are not expected to be used anyway
    let f = generate_dummy_polynomials(keygen.t, keygen.n);

    // List of complaints "published" on board. We simulate that parties 2,5,8 set complaint against
    // party 1 proof. Thus, party 1 must get disqualified.
    let no_complaints = Complaints(vec![]);
    let complaint_against_1 = Complaints(vec![Complaint {
        against: 1,
        reason: ComplaintReason::LdeiProof,
    }]);
    let complaints = vec![
        Some(no_complaints.clone()),       // party 0
        Some(no_complaints.clone()),       // party 1
        Some(complaint_against_1.clone()), // party 2
        Some(no_complaints.clone()),       // party 3
        Some(no_complaints.clone()),       // party 4
        Some(complaint_against_1.clone()), // party 5
        Some(no_complaints.clone()),       // party 6
        None,                              // party 7
        Some(complaint_against_1.clone()), // party 8
        Some(no_complaints.clone()),       // party 9
    ];

    for (i, party_setup) in keygen.parties.iter().enumerate() {
        let mut disqualified = DisqualifiedParties::new();

        let (justification_msg, justification_required_for) =
            process_complaints(&party_setup, &f[i], &mut disqualified, &complaints).unwrap();

        assert!(disqualified.is_empty());
        assert!(justification_msg.revealed_σ.is_empty());
        assert!(justification_required_for.is_empty());
    }
}

#[test]
fn parties_who_received_complaint_against_their_encryption_must_reveal_encryption_materials() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);

    // We generate dummy polynomials that are not expected to be used anyway
    let f = generate_dummy_polynomials(keygen.t, keygen.n);

    // List of complaints "published" on board. We simulate that parties 4,7 set complaint against
    // party 2 encryption. Thus, party 2 must reveal encryption materials for these parties.
    let no_complaints = Complaints(vec![]);
    let complaint_against_2 = Complaints(vec![Complaint {
        against: 2,
        reason: ComplaintReason::Encryption,
    }]);
    let complaints = vec![
        Some(no_complaints.clone()),       // party 0
        Some(no_complaints.clone()),       // party 1
        Some(no_complaints.clone()),       // party 2
        Some(no_complaints.clone()),       // party 3
        Some(complaint_against_2.clone()), // party 4
        Some(no_complaints.clone()),       // party 5
        Some(no_complaints.clone()),       // party 6
        Some(complaint_against_2.clone()), // party 7
        Some(no_complaints.clone()),       // party 8
        Some(no_complaints.clone()),       // party 9
    ];

    let justification_required_for_expected =
        JustificationRequiredFor::from_iter([(2, vec![4, 7])]);

    for (i, party_setup) in keygen.parties.iter().enumerate() {
        let mut disqualified = DisqualifiedParties::new();

        let (justification_msg, justification_required_for) =
            process_complaints(&party_setup, &f[i], &mut disqualified, &complaints).unwrap();

        // No disqualifications are expected at this point
        assert!(disqualified.is_empty());
        // Party 2 is required to reveal its encryption materials
        assert_eq!(
            justification_required_for,
            justification_required_for_expected
        );
        if i == 2 {
            // Party 2 sends justification message revealing used encryption materials for parties
            // 4 and 7
            let justification_msg_expected = Justification {
                revealed_σ: vec![
                    f[2].evaluate_bigint(4 + 1).clone(),
                    f[2].evaluate_bigint(7 + 1).clone(),
                ],
            };
            assert_eq!(justification_msg, justification_msg_expected);
        } else {
            // Justification is not required for other parties
            assert!(justification_msg.revealed_σ.is_empty());
        }
    }
}

#[test]
fn complainer_get_disqualified_if_party_proofs_that_encryption_was_correct() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);
    let phase0 = keygen.phase0_generate_parties_local_secrets();
    let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
    let mut phase2 = keygen.phase2_decrypt_shares(&phase1);

    // Party 2 sets complaint against party 7 encryption
    phase2.board[2].as_mut().unwrap().0.push(Complaint {
        against: 7,
        reason: ComplaintReason::Encryption,
    });

    let phase3 = keygen.phase3_process_complaints_and_publish_justifications(&phase0, &phase2);
    let phase4 = keygen.phase4_process_justifications(&phase1, &phase3);

    let disqualified_expected =
        DisqualifiedParties::from_iter([(2, DisqualificationReason::LiedAboutInvalidEncryption)]);
    for (i, disqualified) in phase4.disqualified.iter().enumerate() {
        // Everyone should detect that 2nd party is lied about invalid encryption
        assert_eq!(
            disqualified, &disqualified_expected,
            "party {} has different list of disqualified parties",
            i
        );
    }
}

#[test]
fn party_gets_disqualified_if_it_incorrectly_encrypts_share() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);
    let phase0 = keygen.phase0_generate_parties_local_secrets();
    let mut phase1 = keygen.phase1_share_and_commit_shares(&phase0);

    // Party 2 sends an invalid share to party 7
    phase1.board[2].as_mut().unwrap().E[7] = BigInt::sample(256);

    let phase2 = keygen.phase2_decrypt_shares(&phase1);
    let phase3 = keygen.phase3_process_complaints_and_publish_justifications(&phase0, &phase2);
    let phase4 = keygen.phase4_process_justifications(&phase1, &phase3);

    let disqualified_expected =
        DisqualifiedParties::from_iter([(2, DisqualificationReason::InvalidEncryption)]);
    for (i, disqualified) in phase4.disqualified.iter().enumerate() {
        // Everyone should detect that party 2 sent invalid share
        assert_eq!(
            disqualified, &disqualified_expected,
            "party {} has different list of disqualified parties",
            i
        );
    }
}

#[test]
fn party_gets_disqualified_if_it_doesnt_publish_justification() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);
    let phase0 = keygen.phase0_generate_parties_local_secrets();
    let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
    let mut phase2 = keygen.phase2_decrypt_shares(&phase1);

    // Party 7 set complaint against party 2 encryption
    phase2.board[7].as_mut().unwrap().0.push(Complaint {
        against: 2,
        reason: ComplaintReason::Encryption,
    });

    let mut phase3 = keygen.phase3_process_complaints_and_publish_justifications(&phase0, &phase2);

    // Though party 2 correctly encrypted its share, it doesn't manage to publish justification
    // message on board in time
    phase3.board[2] = None;

    let phase4 = keygen.phase4_process_justifications(&phase1, &phase3);

    let disqualified_expected =
        DisqualifiedParties::from_iter([(2, DisqualificationReason::InvalidEncryption)]);
    for (i, disqualified) in phase4.disqualified.iter().enumerate() {
        // Everyone should believe that party 2 sent invalid share
        assert_eq!(
            disqualified, &disqualified_expected,
            "party {} has different list of disqualified parties",
            i
        );
    }
}

#[test]
fn protocol_terminates_with_no_adversaries() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);
    let phase0 = keygen.phase0_generate_parties_local_secrets();
    let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
    let phase2 = keygen.phase2_decrypt_shares(&phase1);
    keygen.phase3_skipped(&phase2);
    keygen.phase4_skipped(&phase2, None);
    let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, None, None);
    let phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);
    let phase7 = keygen.phase7_validate_shares_commitments(&phase5, &phase6);
    let (_tsk, _decryption, _tpk) = keygen.phase8_construct_elgamal_keys(&phase6, &phase7);
}

#[test]
fn protocol_terminates_with_t_adversaries_set_false_complaints_against_honest_parties_encryption() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);
    let phase0 = keygen.phase0_generate_parties_local_secrets();
    let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
    let mut phase2 = keygen.phase2_decrypt_shares(&phase1);

    // Parties 0-2 set complaints against encryptions of parties 3-9
    let false_complaints = Complaints(
        (3..10)
            .map(|i| Complaint {
                against: i,
                reason: ComplaintReason::Encryption,
            })
            .collect(),
    );
    for adversary_message in phase2.board.iter_mut().take(3) {
        *adversary_message = Some(false_complaints.clone())
    }

    let phase3 = keygen.phase3_process_complaints_and_publish_justifications(&phase0, &phase2);
    let phase4 = keygen.phase4_process_justifications(&phase1, &phase3);
    let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, Some(&phase3), Some(&phase4));
    let phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);
    let phase7 = keygen.phase7_validate_shares_commitments(&phase5, &phase6);
    let (_tsk, _decryption, _tpk) = keygen.phase8_construct_elgamal_keys(&phase6, &phase7);
}

#[test]
fn protocol_terminates_with_t_adversaries_sent_invalid_commit_of_their_local_secrets() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);
    let phase0 = keygen.phase0_generate_parties_local_secrets();
    let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
    let phase2 = keygen.phase2_decrypt_shares(&phase1);
    let phase3 = keygen.phase3_process_complaints_and_publish_justifications(&phase0, &phase2);
    let phase4 = keygen.phase4_process_justifications(&phase1, &phase3);
    let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, Some(&phase3), Some(&phase4));
    let mut phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);

    for adversary_message in phase6.board.iter_mut().take(3) {
        adversary_message.as_mut().unwrap().proof.e = Scalar::random();
    }

    let phase7 = keygen.phase7_validate_shares_commitments(&phase5, &phase6);
    let (_tsk, _decryption, _tpk) = keygen.phase8_construct_elgamal_keys(&phase6, &phase7);

    for i in 1..keygen.n {
        // Parties who provided invalid commitment are excluded from set I
        for adversary in 0..3 {
            assert!(!phase7.I[usize::from(i)].contains(&adversary))
        }
    }
}

struct ShuffleI2J(SmallRng);

impl ShuffleI2J {
    pub fn random_state() -> Self {
        Self(SeedableRng::from_entropy())
    }
}

impl I2J for ShuffleI2J {
    fn map_I_to_J<T: Clone>(&self, t: u16, I: &[T]) -> Vec<T> {
        I.choose_multiple(&mut self.0.clone(), usize::from(t) + 1)
            .cloned()
            .collect()
    }
}

#[test]
fn protocol_terminates_with_parties_choosing_randomly_set_J() {
    let keygen = KeygenSimulation::<Secp256k1>::setup(3, 10);
    let phase0 = keygen.phase0_generate_parties_local_secrets();
    let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
    let phase2 = keygen.phase2_decrypt_shares(&phase1);
    keygen.phase3_skipped(&phase2);
    keygen.phase4_skipped(&phase2, None);
    let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, None, None);
    let phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);

    let i2j = iter::repeat_with(|| ShuffleI2J::random_state())
        .take(usize::from(keygen.n))
        .collect::<Vec<_>>();
    let phase7 = keygen.phase7_validate_shares_commitments_with_i2j(&phase5, &phase6, &i2j);
    let (_tsk, _decryption, _tpk) = keygen.phase8_construct_elgamal_keys(&phase6, &phase7);
}

fn analyse_keygen_measurements<E: Curve>(
    name: String,
    phase0: &Phase0GeneratedLocalSecrets<E>,
    phase1: &Phase1SharedAndCommittedSecret<E>,
    phase2: &Phase2DecryptedShares<E>,
    phase3: Option<&Phase3PublishedJustifications<E>>,
    phase4: Option<&Phase4ProcessedJustifications>,
    phase5: &Phase5SetQ<E>,
    phase6: &Phase6ConstructedAndCommittedLocalSecret<E>,
) {
    use crate::utils::performance_analysis::*;

    analyse_measurements(
        name,
        &[
            PhaseMeasurement::Available(&phase0.took),
            PhaseMeasurement::Available(&phase1.took),
            PhaseMeasurement::Available(&phase2.took),
            phase3
                .map(|p| PhaseMeasurement::Available(&p.took))
                .unwrap_or(PhaseMeasurement::Skipped),
            phase4
                .map(|p| PhaseMeasurement::Available(&p.took))
                .unwrap_or(PhaseMeasurement::Skipped),
            PhaseMeasurement::Available(&phase5.took),
            PhaseMeasurement::Available(&phase6.took),
        ],
    )
}

#[test]
fn keygen_protocol_performance() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    for n in (5..=45).step_by(10) {
        let t = n / 3;

        let keygen = KeygenSimulation::<Secp256k1>::setup(t, n);
        let phase0 = keygen.phase0_generate_parties_local_secrets();
        let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
        let phase2 = keygen.phase2_decrypt_shares(&phase1);
        keygen.phase3_skipped(&phase2);
        keygen.phase4_skipped(&phase2, None);
        let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, None, None);
        let phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);
        let phase7 = keygen.phase7_validate_shares_commitments(&phase5, &phase6);
        let (_tsk, _decryption, _tpk) = keygen.phase8_construct_elgamal_keys(&phase6, &phase7);

        analyse_keygen_measurements(
            format!("DKG n={}, t={}", n, t),
            &phase0,
            &phase1,
            &phase2,
            None,
            None,
            &phase5,
            &phase6,
        )
    }
}

#[test]
fn bls_keygen_protocol_performance() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    for n in (5..=60).step_by(5) {
        let t = n / 3;

        let keygen = KeygenSimulation::<Bls12_381_2>::setup(t, n);
        let phase0 = keygen.phase0_generate_parties_local_secrets();
        let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
        let phase2 = keygen.phase2_decrypt_shares(&phase1);
        keygen.phase3_skipped(&phase2);
        keygen.phase4_skipped(&phase2, None);
        let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, None, None);
        let phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);
        let phase7 = keygen.phase7_validate_shares_commitments(&phase5, &phase6);
        let (_tsk, _decryption, _tpk) = keygen.phase8_construct_elgamal_keys(&phase6, &phase7);

        analyse_keygen_measurements(
            format!("DKG n={}, t={}", n, t),
            &phase0,
            &phase1,
            &phase2,
            None,
            None,
            &phase5,
            &phase6,
        )
    }
}

fn analyse_communication_size<E: Curve>(
    t: u16,
    n: u16,
    phase1: &Phase1SharedAndCommittedSecret<E>,
    phase2: Option<&Phase2DecryptedShares<E>>,
    phase3: Option<&Phase3PublishedJustifications<E>>,
    phase6: &Phase6ConstructedAndCommittedLocalSecret<E>,
) {
    let phase1_size = bincode::serialize(phase1.board[0].as_ref().unwrap())
        .unwrap()
        .len();
    let phase2_size = phase2.map(|p| {
        bincode::serialize(p.board[0].as_ref().unwrap())
            .unwrap()
            .len()
    });
    let phase3_size = phase3.map(|p| {
        bincode::serialize(p.board[0].as_ref().unwrap())
            .unwrap()
            .len()
    });
    let phase6_size = bincode::serialize(phase6.board[0].as_ref().unwrap())
        .unwrap()
        .len();

    println!("### n={}, t={}", n, t);
    println!();
    println!("Summary:");
    let send = phase1_size + phase2_size.unwrap_or(0) + phase3_size.unwrap_or(0) + phase6_size;
    let recv = (phase1_size + phase2_size.unwrap_or(0) + phase3_size.unwrap_or(0) + phase6_size)
        * usize::from(n);
    println!("- Totally: {} bytes", send + recv);
    println!("- Send: {} bytes", send);
    println!("- Recv: {} bytes", recv);
    println!();
    println!("Details:");
    println!();
    println!("- Phase1: {} bytes", phase1_size);
    println!("- Phase2: {:?} bytes", phase2_size);
    println!("- Phase3: {:?} bytes", phase3_size);
    println!("- Phase6: {} bytes", phase6_size);
    println!();
}

#[test]
fn keygen_protocol_communication_size() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    println!("# DKG");
    println!();
    println!("## Communication size");
    println!();
    for n in (5..=45).step_by(10) {
        let t = n / 3;

        let keygen = KeygenSimulation::<Secp256k1>::setup(t, n);
        let phase0 = keygen.phase0_generate_parties_local_secrets();
        let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
        let phase2 = keygen.phase2_decrypt_shares(&phase1);
        keygen.phase3_skipped(&phase2);
        keygen.phase4_skipped(&phase2, None);
        let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, None, None);
        let phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);
        let phase7 = keygen.phase7_validate_shares_commitments(&phase5, &phase6);
        let (_tsk, _decryption, _tpk) = keygen.phase8_construct_elgamal_keys(&phase6, &phase7);

        analyse_communication_size(t, n, &phase1, None, None, &phase6)
    }
}

#[test]
fn bls_keygen_protocol_communication_size() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    println!("# DKG");
    println!();
    println!("## Communication size");
    println!();
    for n in (5..=60).step_by(5) {
        let t = n / 3;

        let keygen = KeygenSimulation::<Bls12_381_2>::setup(t, n);
        let phase0 = keygen.phase0_generate_parties_local_secrets();
        let phase1 = keygen.phase1_share_and_commit_shares(&phase0);
        let phase2 = keygen.phase2_decrypt_shares(&phase1);
        keygen.phase3_skipped(&phase2);
        keygen.phase4_skipped(&phase2, None);
        let phase5 = keygen.phase5_deduce_set_Q(&phase1, &phase2, None, None);
        let phase6 = keygen.phase6_construct_and_commit_local_secret(&phase5);
        let phase7 = keygen.phase7_validate_shares_commitments(&phase5, &phase6);
        let (_tsk, _decryption, _tpk) = keygen.phase8_construct_elgamal_keys(&phase6, &phase7);

        analyse_communication_size(t, n, &phase1, None, None, &phase6)
    }
}
