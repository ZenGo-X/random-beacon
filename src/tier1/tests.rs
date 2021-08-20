use std::iter::{self, FromIterator};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use curv::cryptographic_primitives::secret_sharing::Polynomial;
use curv::elliptic::curves::*;

use crate::tier1::core::*;
use crate::utils::IteratorExt;

pub struct Tier1Simulation<E: Curve> {
    parties: Vec<ProtocolSetup<E>>,
    t: u16,
    l: u16,
    n: u16,
}

impl<E: Curve> Tier1Simulation<E> {
    pub fn setup(l: u16, t: u16, n: u16) -> Self {
        let α = Scalar::random();
        let M = ResilientMatrix::new(α, n - 2 * t, n - t);

        let sk = iter::repeat_with(Scalar::random)
            .take(usize::from(n))
            .collect::<Vec<_>>();
        let pk = sk
            .iter()
            .map(|sk_i| Point::generator() * sk_i)
            .collect::<Vec<_>>();

        let parties = sk
            .iter()
            .map(|sk_i| ProtocolSetup::new(sk_i.clone(), pk.clone(), t, l, M.clone()).unwrap())
            .collect();

        Self { parties, t, l, n }
    }

    pub fn phase0_generate_local_secrets(&self) -> Phase0GeneratedLocalSecrets<E> {
        let mut took = Vec::with_capacity(usize::from(self.n));
        let mut f = Vec::with_capacity(usize::from(self.n));

        for _ in 0..self.n {
            let start = Instant::now();
            f.push(Polynomial::<Secp256k1>::sample_exact(self.t + self.l - 1));
            took.push(start.elapsed());
        }

        Phase0GeneratedLocalSecrets {
            f: iter::repeat_with(|| Polynomial::sample_exact(self.t + self.l - 1))
                .take(usize::from(self.n))
                .collect(),
            took,
        }
    }

    pub fn phase1_commit_local_secret<F>(
        &self,
        phase0: &Phase0GeneratedLocalSecrets<E>,
    ) -> Phase1CommittedLocalSecret<E>
    where
        F: FilterOutTMessages<SharedSecret<E>>,
    {
        let mut shares = Vec::with_capacity(usize::from(self.n));
        let mut took = Vec::with_capacity(usize::from(self.n));

        for i in 0..self.n {
            let start = Instant::now();
            let shared_secret =
                sharing(&self.parties[usize::from(i)], &phase0.f[usize::from(i)]).unwrap();
            took.push(start.elapsed());

            // Ensure that every party agrees that this share is valid
            for j in 0..self.n {
                is_secret_correctly_shared(&self.parties[usize::from(j)], &shared_secret).unwrap();
            }

            shares.push(shared_secret)
        }

        let mut board = shares.iter().cloned().map(Some).collect();
        F::filter_out_t_messages(self.t, &mut board);

        Phase1CommittedLocalSecret {
            shares,
            board,
            took,
        }
    }

    pub fn phase2_reveal_secrets(
        &self,
        phase0: &Phase0GeneratedLocalSecrets<E>,
        phase1: &Phase1CommittedLocalSecret<E>,
    ) -> Phase2RevealedSecrets<E> {
        let mut revealed_secrets = vec![];

        for i in 0..self.n {
            revealed_secrets.push(
                Some(phase0.f[usize::from(i)].clone())
                    .filter(|_| phase1.board[usize::from(i)].is_some()),
            )
        }

        Phase2RevealedSecrets {
            secrets: revealed_secrets.clone(),
            board: revealed_secrets.clone(),
        }
    }

    pub fn phase3_process_revealed_secrets(
        &self,
        phase1: &Phase1CommittedLocalSecret<E>,
        phase2: &Phase2RevealedSecrets<E>,
    ) -> Phase3ProcessedRevealedSecrets<E> {
        let mut parties_who_didnt_open_their_secrets = None;
        let mut correctly_opened_secrets = None;
        let mut took = Vec::with_capacity(usize::from(self.n));

        for i in 0..self.n {
            let start = Instant::now();
            let mut correctly_opened_secrets_i = OpenedSecrets::new();
            let parties_who_didnt_open_their_secrets_i = validate_opened_secrets(
                &self.parties[usize::from(i)],
                &phase1.board,
                &phase2.board,
                &mut correctly_opened_secrets_i,
            )
            .unwrap();
            took.push(start.elapsed());

            if let Some(correctly_opened_secrets) = correctly_opened_secrets {
                assert_eq!(correctly_opened_secrets, correctly_opened_secrets_i);
            }
            if let Some(parties_who_didnt_open_their_secrets) = parties_who_didnt_open_their_secrets
            {
                assert_eq!(
                    parties_who_didnt_open_their_secrets,
                    parties_who_didnt_open_their_secrets_i
                );
            }
            correctly_opened_secrets = Some(correctly_opened_secrets_i);
            parties_who_didnt_open_their_secrets = Some(parties_who_didnt_open_their_secrets_i);
        }

        Phase3ProcessedRevealedSecrets {
            parties_who_didnt_open_their_secrets: parties_who_didnt_open_their_secrets.unwrap(),
            correctly_opened_secrets: correctly_opened_secrets.unwrap(),
            took,
        }
    }

    pub fn phase4_partially_open_secrets<S>(
        &self,
        phase1: &Phase1CommittedLocalSecret<E>,
        phase3: &Phase3ProcessedRevealedSecrets<E>,
    ) -> Phase4PartiallyOpenSecret<E>
    where
        S: ShuffleMessagesOrder,
    {
        let mut partially_opened_secrets = Vec::with_capacity(usize::from(self.n));
        let mut took = Vec::with_capacity(usize::from(self.n));

        for i in 0..self.n {
            let start = Instant::now();
            let mut partially_opened_secrets_i =
                Vec::with_capacity(phase3.parties_who_didnt_open_their_secrets.len());
            for &uncooperative_party in &phase3.parties_who_didnt_open_their_secrets {
                partially_opened_secrets_i.push(
                    partially_open_secret(
                        &self.parties[usize::from(i)],
                        phase1.board[usize::from(uncooperative_party)]
                            .as_ref()
                            .unwrap(),
                    )
                    .unwrap(),
                )
            }
            partially_opened_secrets.push(partially_opened_secrets_i);
            took.push(start.elapsed());
        }

        let mut board_order = partially_opened_secrets
            .iter()
            .enumerate_u16()
            .map(|(i, m)| (i, m.clone()))
            .collect();
        S::shuffle_messages_order(&mut board_order);

        Phase4PartiallyOpenSecret {
            partially_opened_secrets,
            board_order,
            took,
        }
    }

    pub fn phase4_skipped(&self, phase3: &Phase3ProcessedRevealedSecrets<E>) {
        assert!(phase3.parties_who_didnt_open_their_secrets.is_empty())
    }

    pub fn phase5_reconstruct_secrets(
        &self,
        phase1: &Phase1CommittedLocalSecret<E>,
        phase3: &Phase3ProcessedRevealedSecrets<E>,
        phase4: &Phase4PartiallyOpenSecret<E>,
    ) -> Phase5ReconstructedSecrets<E> {
        let mut reconstructed_secrets = None;
        let mut took = Vec::with_capacity(usize::from(self.n));

        for i in 0..self.n {
            let start = Instant::now();
            let mut reconstructed_secrets_i = OpenedSecrets::new();

            let mut partial_reconstructions =
                vec![(vec![], vec![]); phase3.parties_who_didnt_open_their_secrets.len()];
            let mut secrets_left = phase3.parties_who_didnt_open_their_secrets.len();

            for (sender, partials) in phase4.board_order.iter() {
                for ((uncooperative_party, reconstruction), partial) in phase3
                    .parties_who_didnt_open_their_secrets
                    .iter()
                    .zip(&mut partial_reconstructions)
                    .zip(partials)
                {
                    let shared_secret = phase1.board[usize::from(*uncooperative_party)]
                        .as_ref()
                        .unwrap();
                    let valid = validate_partially_opened_secret(
                        &self.parties[usize::from(i)],
                        *sender,
                        shared_secret,
                        partial,
                    )
                    .is_ok();

                    if valid {
                        reconstruction.0.push(*sender);
                        reconstruction.1.push(partial.clone());
                        if reconstruction.0.len() == usize::from(self.t + self.l) {
                            let reconstructed_secret = open_shared_secret(
                                &self.parties[usize::from(i)],
                                &reconstruction.0,
                                &reconstruction.1,
                            )
                            .unwrap();
                            reconstructed_secrets_i
                                .insert(*uncooperative_party, reconstructed_secret);
                            secrets_left -= 1;
                            if secrets_left == 0 {
                                break;
                            }
                        }
                    }
                }
            }
            took.push(start.elapsed());

            assert_eq!(secrets_left, 0);

            if let Some(reconstructed_secrets) = &reconstructed_secrets {
                assert_eq!(reconstructed_secrets, &reconstructed_secrets_i);
            }
            reconstructed_secrets = Some(reconstructed_secrets_i);
        }

        Phase5ReconstructedSecrets {
            reconstructed_secrets: reconstructed_secrets.unwrap(),
            took,
        }
    }

    pub fn phase5_skipped(&self, phase3: &Phase3ProcessedRevealedSecrets<E>) {
        assert!(phase3.parties_who_didnt_open_their_secrets.is_empty())
    }

    pub fn phase6_aggregation(
        &self,
        phase3: &Phase3ProcessedRevealedSecrets<E>,
        phase5: Option<&Phase5ReconstructedSecrets<E>>,
    ) -> Phase6Aggregation<E> {
        let mut correctly_opened_secrets = phase3.correctly_opened_secrets.clone();
        if let Some(phase5) = phase5 {
            correctly_opened_secrets.extend(
                phase5
                    .reconstructed_secrets
                    .iter()
                    .map(|(k, v)| (*k, v.clone())),
            )
        }

        let secrets_matrix = OpenedSecretsMatrix::from(correctly_opened_secrets);
        let mut randomness: Option<Vec<Point<_>>> = None;
        let mut took = Vec::with_capacity(usize::from(self.n));

        for setup in &self.parties {
            let start = Instant::now();
            let randomness_i = extract_randomness(setup, &secrets_matrix).unwrap();
            took.push(start.elapsed());

            if let Some(randomness) = &randomness {
                assert_eq!(*randomness, randomness_i);
            }
            randomness = Some(randomness_i)
        }

        Phase6Aggregation {
            randomness: randomness.unwrap(),
            took,
        }
    }
}

pub struct Phase0GeneratedLocalSecrets<E: Curve> {
    /// $f_i(x)$ is a polynomial that encodes secrets $s_j^{(i)} = f_i(-j), j\in\[0, \ell-1]$ of
    /// $\ith$ party
    pub f: Vec<Polynomial<E>>,

    /// $took_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase1CommittedLocalSecret<E: Curve> {
    /// $\text{shares}_i$ is a list of committed shares produced by $\ith$ party
    pub shares: Vec<SharedSecret<E>>,

    /// $\text{board}_i$ is a committed share published by $\ith$ party. Must contain exactly $n-t$
    /// **valid** shares that were published first
    ///
    /// By default, simulation chooses random $n-t$ shares
    pub board: Msgs<SharedSecret<E>>,

    /// $took_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase2RevealedSecrets<E: Curve> {
    /// $\text{secrets}_i$ is a secret revealed by $\ith$ party (`None` if this party is not required
    /// to reveal its secret)
    pub secrets: Vec<Option<Polynomial<E>>>,

    /// $\text{board}_i$ is a message revealing party secrets published by $\ith$ party (`None` if
    /// party is not required to reveal its secrets, or if party refuses to reveal it)
    pub board: Msgs<Polynomial<E>>,
}

pub struct Phase3ProcessedRevealedSecrets<E: Curve> {
    /// List of parties who didn't reveal their secrets or revealed incorrectly
    ///
    /// Since all parties see the same board, they must agree on the same list of uncooperative parties
    pub parties_who_didnt_open_their_secrets: PartiesWhoDidntOpenTheirSecrets,

    /// Set of secrets that were correctly opened by committed parties
    ///
    /// Since all parties see the same board, they must agree on the same set of opened secrets
    pub correctly_opened_secrets: OpenedSecrets<E>,

    /// $took_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase4PartiallyOpenSecret<E: Curve> {
    /// $\text{partially_opened_secrets}_i$ is a partial opening made by $\ith$ party
    pub partially_opened_secrets: Vec<Vec<PartiallyOpenedSecret<E>>>,

    /// `board_order` sets the order in which `partially_opened_secrets` were published on board.
    ///
    /// E.g. `board_order = vec![(2, msg2), (0, msg0), (1, msg1)]` states that party 2 published partial
    /// opening first, next arrived message on board is from party 0, and then party 1.
    ///
    /// By default, simulation chooses random order of messages
    pub board_order: Vec<(u16, Vec<PartiallyOpenedSecret<E>>)>,

    /// $took_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase5ReconstructedSecrets<E: Curve> {
    /// Set of secrets that were reconstructed from partially openings
    ///
    /// Since all parties see the same board, they must agree on the same set of opened secrets
    pub reconstructed_secrets: OpenedSecrets<E>,

    /// $took_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub struct Phase6Aggregation<E: Curve> {
    /// List of random $\ell \cdot \ellʹ$ points produced by the protocol
    pub randomness: Vec<Point<E>>,

    /// $took_i$ shows how much time it took for $\ith$ party to complete this phase
    pub took: Vec<Duration>,
}

pub trait FilterOutTMessages<M> {
    /// All messages in `msgs` are expected to be `Some(_)`, `t` must be `0 <= t <= msgs.len()`
    fn filter_out_t_messages(t: u16, msgs: &mut Msgs<M>);
}

pub struct FilterOutTRandomMessages<M>(PhantomData<M>);

impl<M> FilterOutTMessages<M> for FilterOutTRandomMessages<M> {
    fn filter_out_t_messages(t: u16, msgs: &mut Msgs<M>) {
        // we randomly choose t messages that were "published too late"
        let filtered_out_msgs =
            rand::seq::index::sample(&mut rand::rngs::OsRng, msgs.len(), usize::from(t));
        for i in filtered_out_msgs {
            msgs[i] = None
        }
    }
}

pub struct FilterOutTLastMessages<M>(PhantomData<M>);

impl<M> FilterOutTMessages<M> for FilterOutTLastMessages<M> {
    fn filter_out_t_messages(t: u16, msgs: &mut Msgs<M>) {
        let n = msgs.len();
        (&mut msgs[n - usize::from(t)..])
            .iter_mut()
            .for_each(|m| *m = None)
    }
}

pub trait ShuffleMessagesOrder {
    fn shuffle_messages_order<M>(msgs: &mut Vec<M>);
}

pub struct RandomlyShuffleMessagesOrder;
impl ShuffleMessagesOrder for RandomlyShuffleMessagesOrder {
    fn shuffle_messages_order<M>(msgs: &mut Vec<M>) {
        use rand::seq::SliceRandom;
        msgs.shuffle(&mut rand::rngs::OsRng)
    }
}

pub struct DontShuffleMessagesOrder;
impl ShuffleMessagesOrder for DontShuffleMessagesOrder {
    fn shuffle_messages_order<M>(_msgs: &mut Vec<M>) {}
}

#[test]
fn protocol_terminates_with_no_adversaries() {
    let tier1 = Tier1Simulation::<Secp256k1>::setup(2, 3, 10);
    let phase0 = tier1.phase0_generate_local_secrets();
    let phase1 = tier1.phase1_commit_local_secret::<FilterOutTRandomMessages<_>>(&phase0);
    let phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);
    let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
    tier1.phase4_skipped(&phase3);
    tier1.phase5_skipped(&phase3);
    let phase6 = tier1.phase6_aggregation(&phase3, None);
    assert_eq!(
        phase6.randomness.len(),
        usize::from(tier1.l * (tier1.n - 2 * tier1.t))
    );
}

#[test]
fn protocol_terminates_with_t_adversaries_not_revealing_secrets_and_sabotaging_reconstruction() {
    let tier1 = Tier1Simulation::<Secp256k1>::setup(2, 3, 10);
    let phase0 = tier1.phase0_generate_local_secrets();
    let phase1 = tier1.phase1_commit_local_secret::<FilterOutTLastMessages<_>>(&phase0);
    let mut phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);

    // Parties 0, 1, 2 refuse to open their secrets (or open wrong secrets)
    phase2.board[0] = None;
    phase2.board[1] = None;
    phase2.board[2] = Some(Polynomial::sample_exact(tier1.t + tier1.l - 1));

    let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
    let mut phase4 =
        tier1.phase4_partially_open_secrets::<DontShuffleMessagesOrder>(&phase1, &phase3);

    // Parties 0, 1, 2 provide wrong partial openings
    let modify_point = |p: &mut Point<_>| *p = &*p * Scalar::random();
    for adversary in 0..=2 {
        modify_point(&mut phase4.board_order[adversary].1[0].S);
        modify_point(&mut phase4.board_order[adversary].1[1].S);
        modify_point(&mut phase4.board_order[adversary].1[2].S);
    }

    let phase5 = tier1.phase5_reconstruct_secrets(&phase1, &phase3, &phase4);
    let phase6 = tier1.phase6_aggregation(&phase3, Some(&phase5));

    assert_eq!(
        phase6.randomness.len(),
        usize::from(tier1.l * (tier1.n - 2 * tier1.t))
    );

    // Now we carry out protocol like there were no adversaries to ensure that protocol output is the
    // same
    let phase2_no_adversaries = tier1.phase2_reveal_secrets(&phase0, &phase1);
    let phase3_no_adversaries =
        tier1.phase3_process_revealed_secrets(&phase1, &phase2_no_adversaries);
    tier1.phase4_skipped(&phase3_no_adversaries);
    tier1.phase5_skipped(&phase3_no_adversaries);
    let phase6_no_adversaries = tier1.phase6_aggregation(&phase3_no_adversaries, None);

    assert_eq!(phase6.randomness, phase6_no_adversaries.randomness);
}

#[test]
fn party_is_cooperative_if_opened_its_secrets() {
    let tier1 = Tier1Simulation::<Secp256k1>::setup(2, 3, 10);
    let phase0 = tier1.phase0_generate_local_secrets();
    let phase1 = tier1.phase1_commit_local_secret::<FilterOutTRandomMessages<_>>(&phase0);
    let phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);
    let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);

    assert_eq!(phase3.parties_who_didnt_open_their_secrets, vec![]);

    let mut expected_opened_secrets = OpenedSecrets::new();
    for i in 0..tier1.n {
        if phase1.board[usize::from(i)].is_some() {
            expected_opened_secrets.insert(
                i,
                phase0.f[usize::from(i)]
                    .evaluate_many_bigint(-i32::from(tier1.l - 1)..=0)
                    .map(|s| Point::generator() * s)
                    .collect(),
            );
        }
    }
    assert_eq!(
        phase3.correctly_opened_secrets.len(),
        expected_opened_secrets.len()
    );
    assert_eq!(phase3.correctly_opened_secrets, expected_opened_secrets);
}

#[test]
fn party_is_uncooperative_if_it_refuses_to_reveal_secret() {
    let tier1 = Tier1Simulation::<Secp256k1>::setup(2, 3, 10);
    let phase0 = tier1.phase0_generate_local_secrets();
    let phase1 = tier1.phase1_commit_local_secret::<FilterOutTLastMessages<_>>(&phase0);
    let mut phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);

    // Party 2 didn't open its secret
    phase2.board[2] = None;

    let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);

    assert_eq!(phase3.parties_who_didnt_open_their_secrets, vec![2]);
    assert!(!phase3.correctly_opened_secrets.contains_key(&2));
}

#[test]
fn party_is_uncooperative_if_it_reveals_wrong_secret() {
    let tier1 = Tier1Simulation::<Secp256k1>::setup(2, 3, 10);
    let phase0 = tier1.phase0_generate_local_secrets();
    let phase1 = tier1.phase1_commit_local_secret::<FilterOutTLastMessages<_>>(&phase0);
    let mut phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);

    // Party 2 opens different secret
    phase2.board[2] = Some(Polynomial::sample_exact(tier1.t + tier1.l - 1));

    let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);

    assert_eq!(phase3.parties_who_didnt_open_their_secrets, vec![2]);
    assert!(!phase3.correctly_opened_secrets.contains_key(&2));
}

#[test]
fn honest_majority_can_recover_unopened_secret() {
    let tier1 = Tier1Simulation::<Secp256k1>::setup(2, 3, 10);
    let phase0 = tier1.phase0_generate_local_secrets();
    let phase1 = tier1.phase1_commit_local_secret::<FilterOutTLastMessages<_>>(&phase0);
    let mut phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);

    // Party 2 didn't open its secret
    phase2.board[2] = None;

    let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
    let mut phase4 =
        tier1.phase4_partially_open_secrets::<DontShuffleMessagesOrder>(&phase1, &phase3);

    // Parties 1, 2, 5 provide wrong partial opening
    let modify_point = |p: &mut Point<_>| *p = &*p * Scalar::random();
    modify_point(&mut phase4.board_order[1].1[0].S);
    modify_point(&mut phase4.board_order[2].1[0].S);
    modify_point(&mut phase4.board_order[5].1[0].S);

    let phase5 = tier1.phase5_reconstruct_secrets(&phase1, &phase3, &phase4);

    let expected_reconstructed_secrets = OpenedSecrets::from_iter([(
        2,
        phase0.f[2]
            .evaluate_many_bigint(-i32::from(tier1.l - 1)..=0)
            .map(|s_i| Point::generator() * s_i)
            .collect::<Vec<_>>(),
    )]);
    assert_eq!(phase5.reconstructed_secrets, expected_reconstructed_secrets);
}

#[test]
fn honest_majority_can_recover_two_unopened_secret() {
    let tier1 = Tier1Simulation::<Secp256k1>::setup(2, 3, 10);
    let phase0 = tier1.phase0_generate_local_secrets();
    let phase1 = tier1.phase1_commit_local_secret::<FilterOutTLastMessages<_>>(&phase0);
    let mut phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);

    // Parties 2 and 3 didn't open its secret
    phase2.board[2] = None;
    phase2.board[3] = None;

    let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
    let mut phase4 =
        tier1.phase4_partially_open_secrets::<DontShuffleMessagesOrder>(&phase1, &phase3);

    // Parties 2, 3, 4 provide wrong partial opening of secret of party 2
    let modify_point = |p: &mut Point<_>| *p = &*p * Scalar::random();
    modify_point(&mut phase4.board_order[2].1[0].S);
    modify_point(&mut phase4.board_order[3].1[0].S);
    modify_point(&mut phase4.board_order[4].1[0].S);
    // Parties 1, 2, 3 provide wrong partial opening of secret of party 3
    let modify_point = |p: &mut Point<_>| *p = &*p * Scalar::random();
    modify_point(&mut phase4.board_order[1].1[1].S);
    modify_point(&mut phase4.board_order[2].1[1].S);
    modify_point(&mut phase4.board_order[3].1[1].S);

    let phase5 = tier1.phase5_reconstruct_secrets(&phase1, &phase3, &phase4);

    let expected_reconstructed_secrets = OpenedSecrets::from_iter([
        (
            2,
            phase0.f[2]
                .evaluate_many_bigint(-i32::from(tier1.l - 1)..=0)
                .map(|s_i| Point::generator() * s_i)
                .collect::<Vec<_>>(),
        ),
        (
            3,
            phase0.f[3]
                .evaluate_many_bigint(-i32::from(tier1.l - 1)..=0)
                .map(|s_i| Point::generator() * s_i)
                .collect::<Vec<_>>(),
        ),
    ]);
    assert_eq!(phase5.reconstructed_secrets, expected_reconstructed_secrets);
}

fn analyse_tier1_measurements<E: Curve>(
    name: String,
    phase0: &Phase0GeneratedLocalSecrets<E>,
    phase1: &Phase1CommittedLocalSecret<E>,
    phase3: &Phase3ProcessedRevealedSecrets<E>,
    phase4: Option<&Phase4PartiallyOpenSecret<E>>,
    phase5: Option<&Phase5ReconstructedSecrets<E>>,
    phase6: &Phase6Aggregation<E>,
) {
    use crate::utils::performance_analysis::*;

    analyse_measurements(
        name,
        &[
            PhaseMeasurement::Available(&phase0.took),
            PhaseMeasurement::Available(&phase1.took),
            PhaseMeasurement::Dust,
            PhaseMeasurement::Available(&phase3.took),
            phase4
                .map(|p| PhaseMeasurement::Available(&p.took))
                .unwrap_or(PhaseMeasurement::Skipped),
            phase5
                .map(|p| PhaseMeasurement::Available(&p.took))
                .unwrap_or(PhaseMeasurement::Skipped),
            PhaseMeasurement::Available(&phase6.took),
        ],
    )
}

#[test]
fn tier1_protocol_performance_with_no_adversaries() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    for n in (5..=45).step_by(10) {
        let t = n / 3;
        let tier1 = Tier1Simulation::<Bls12_381_1>::setup(1, t, n);
        let phase0 = tier1.phase0_generate_local_secrets();
        let phase1 = tier1.phase1_commit_local_secret::<FilterOutTRandomMessages<_>>(&phase0);
        let phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);
        let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
        tier1.phase4_skipped(&phase3);
        tier1.phase5_skipped(&phase3);
        let phase6 = tier1.phase6_aggregation(&phase3, None);

        analyse_tier1_measurements(
            format!("Tier1 n={}, t={}, adversaries=0", n, t),
            &phase0,
            &phase1,
            &phase3,
            None,
            None,
            &phase6,
        )
    }
}

#[test]
fn tier1_protocol_performance_with_a_adversaries() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    let (n, t) = (25, 25 / 3);
    for a in (0..=8).step_by(2) {
        // In this protocol, we have `a` adversaries not revealing their secrets and sabotaging reconstruction
        let tier1 = Tier1Simulation::<Secp256k1>::setup(1, t, n);
        let phase0 = tier1.phase0_generate_local_secrets();
        let phase1 = tier1.phase1_commit_local_secret::<FilterOutTLastMessages<_>>(&phase0);
        let mut phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);

        // Parties 0..a refuse to open their secrets
        for i in 0..a {
            phase2.board[i] = None
        }

        let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
        let mut phase4 =
            tier1.phase4_partially_open_secrets::<DontShuffleMessagesOrder>(&phase1, &phase3);

        // Parties 0..a provide wrong partial opening
        let modify_point = |p: &mut Point<_>| *p = &*p * Scalar::random();
        for i in 0..a {
            for j in 0..a {
                modify_point(&mut phase4.board_order[i].1[j].S);
            }
        }

        let phase5 = tier1.phase5_reconstruct_secrets(&phase1, &phase3, &phase4);
        let phase6 = tier1.phase6_aggregation(&phase3, Some(&phase5));

        analyse_tier1_measurements(
            format!("Tier1 n={}, adversaries={}", n, a),
            &phase0,
            &phase1,
            &phase3,
            Some(&phase4),
            Some(&phase5),
            &phase6,
        )
    }
}

#[test]
fn tier1_protocol_performance_with_no_adversaries_for_various_t() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    let n = 25;
    for t in (2..=8).step_by(2) {
        let tier1 = Tier1Simulation::<Secp256k1>::setup(1, t, n);
        let phase0 = tier1.phase0_generate_local_secrets();
        let phase1 = tier1.phase1_commit_local_secret::<FilterOutTRandomMessages<_>>(&phase0);
        let phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);
        let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
        tier1.phase4_skipped(&phase3);
        tier1.phase5_skipped(&phase3);
        let phase6 = tier1.phase6_aggregation(&phase3, None);

        analyse_tier1_measurements(
            format!("Tier1 n={}, t={}, adversaries=0", n, t),
            &phase0,
            &phase1,
            &phase3,
            None,
            None,
            &phase6,
        )
    }
}

#[test]
fn tier1_protocol_performance_with_no_adversaries_for_various_ell() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    let n = 25;
    let t = 8;
    for ell in (1..=9).step_by(2) {
        let tier1 = Tier1Simulation::<Secp256k1>::setup(ell, t, n);
        let phase0 = tier1.phase0_generate_local_secrets();
        let phase1 = tier1.phase1_commit_local_secret::<FilterOutTRandomMessages<_>>(&phase0);
        let phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);
        let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
        tier1.phase4_skipped(&phase3);
        tier1.phase5_skipped(&phase3);
        let phase6 = tier1.phase6_aggregation(&phase3, None);

        analyse_tier1_measurements(
            format!("Tier1 n={}, t={}, ell={} adversaries=0", n, t, ell),
            &phase0,
            &phase1,
            &phase3,
            None,
            None,
            &phase6,
        )
    }
}

#[test]
fn tier1_protocol_communication_size_with_no_adversaries() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    println!("# Communication size");
    println!();
    for n in (5..=45).step_by(10) {
        let t = n / 3;
        println!("## Tier1 n={}, t={}, a=0", n, t);
        println!();

        let t = n / 3;
        let tier1 = Tier1Simulation::<Secp256k1>::setup(1, t, n);
        let phase0 = tier1.phase0_generate_local_secrets();
        let phase1 = tier1.phase1_commit_local_secret::<FilterOutTLastMessages<_>>(&phase0);
        let phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);
        let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
        tier1.phase4_skipped(&phase3);
        tier1.phase5_skipped(&phase3);
        let _phase6 = tier1.phase6_aggregation(&phase3, None);

        let phase1_size = bincode::serialize(&phase1.board[0].as_ref().unwrap())
            .unwrap()
            .len();

        let phase2_size = bincode::serialize(&phase2.board[0].as_ref().unwrap())
            .unwrap()
            .len();

        let recv = (phase1_size + phase2_size) * usize::from(n - t);
        let send = phase1_size + phase2_size;

        println!("- Total: {}", recv + send);
        println!("- Send: {}", send);
        println!("- Recv: {}", recv);
        println!("- Phase1: {} bytes", phase1_size);
        println!("- Phase2: {} bytes", phase2_size);
        println!();
    }
}

#[test]
fn tier1_protocol_communication_with_adversaries() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    println!("# Communication size");
    println!();
    let (n, t) = (25, 25 / 3);
    for a in (2..=8).step_by(2) {
        println!("## Tier1 n={}, t={}, a={}", n, t, a);
        println!();

        // In this protocol, we have `a` adversaries not revealing their secrets and sabotaging reconstruction
        let tier1 = Tier1Simulation::<Secp256k1>::setup(1, t, n);
        let phase0 = tier1.phase0_generate_local_secrets();
        let phase1 = tier1.phase1_commit_local_secret::<FilterOutTLastMessages<_>>(&phase0);
        let mut phase2 = tier1.phase2_reveal_secrets(&phase0, &phase1);

        // Parties 0..a refuse to open their secrets
        for i in 0..a {
            phase2.board[i] = None
        }

        let phase3 = tier1.phase3_process_revealed_secrets(&phase1, &phase2);
        let mut phase4 =
            tier1.phase4_partially_open_secrets::<DontShuffleMessagesOrder>(&phase1, &phase3);

        // Parties 0..a provide wrong partial opening
        let modify_point = |p: &mut Point<_>| *p = &*p * Scalar::random();
        for i in 0..a {
            for j in 0..a {
                modify_point(&mut phase4.board_order[i].1[j].S);
            }
        }

        let phase5 = tier1.phase5_reconstruct_secrets(&phase1, &phase3, &phase4);
        let _phase6 = tier1.phase6_aggregation(&phase3, Some(&phase5));

        println!(
            "Phase4: {} bytes",
            bincode::serialize(&phase4.board_order[0].1).unwrap().len()
        );
        println!();
    }
}
