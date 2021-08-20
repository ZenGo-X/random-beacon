use std::time::{Duration, Instant};

use serde::Serialize;

use bls::threshold_bls::state_machine::keygen::Keygen;
use bls::threshold_bls::state_machine::sign::Sign;
use round_based::dev::Simulation;
use round_based::{Msg, StateMachine};

use crate::utils::IteratorExt;

#[derive(Debug)]
pub struct MeasureTool<S> {
    pub state: S,
    // Communication measurements
    pub recv_bytes: usize,
    pub send_bytes: usize,
    // Performance measurements
    pub took: Vec<Duration>,
}

impl<S: StateMachine> MeasureTool<S>
where
    S::MessageBody: Serialize,
{
    pub fn new(initial: S) -> Self {
        Self {
            state: initial,
            recv_bytes: 0,
            send_bytes: 0,
            took: vec![],
        }
    }

    fn hook_outgoing_before(&mut self) -> usize {
        self.state.message_queue().len()
    }

    fn hook_outgoing_after(&mut self, before: usize) {
        if before < self.state.message_queue().len() {
            self.send_bytes += self.message_queue()[before..]
                .iter()
                .map(|m| bincode::serialize(&m.body).unwrap().len())
                .sum::<usize>();
        }
    }

    fn hook_state_before(&self) -> (u16, Instant) {
        (self.current_round(), Instant::now())
    }

    fn hook_state_after(&mut self, (round_was, start): (u16, Instant)) {
        if round_was != self.current_round() {
            self.took.push(start.elapsed())
        }
    }
}

impl<S: StateMachine> StateMachine for MeasureTool<S>
where
    S::MessageBody: Serialize,
{
    type MessageBody = <S as StateMachine>::MessageBody;
    type Err = <S as StateMachine>::Err;
    type Output = <S as StateMachine>::Output;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
        self.recv_bytes += bincode::serialize(&msg.body).unwrap().len();
        let hook_outgoing = self.hook_outgoing_before();
        let hook_state = self.hook_state_before();

        let result = self.state.handle_incoming(msg);

        if result.is_ok() {
            self.hook_state_after(hook_state);
            self.hook_outgoing_after(hook_outgoing);
        }

        result
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        self.state.message_queue()
    }

    fn wants_to_proceed(&self) -> bool {
        self.state.wants_to_proceed()
    }

    fn proceed(&mut self) -> Result<(), Self::Err> {
        let hook_outgoing = self.hook_outgoing_before();
        let hook_state = self.hook_state_before();

        let result = self.state.proceed();

        self.hook_state_after(hook_state);
        self.hook_outgoing_after(hook_outgoing);

        result
    }

    fn round_timeout(&self) -> Option<Duration> {
        self.state.round_timeout()
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        self.state.round_timeout_reached()
    }

    fn is_finished(&self) -> bool {
        self.state.is_finished()
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>> {
        self.state.pick_output()
    }

    fn current_round(&self) -> u16 {
        self.state.current_round()
    }

    fn total_rounds(&self) -> Option<u16> {
        self.state.total_rounds()
    }

    fn party_ind(&self) -> u16 {
        self.state.party_ind()
    }

    fn parties(&self) -> u16 {
        self.state.parties()
    }
}

fn analyse_measurements<S>(name: String, measured: &[MeasureTool<S>]) {
    println!("{}", name);
    println!("=========");
    println!();
    println!("- Parties: {}", measured.len());
    println!("- Rounds: {}", measured[0].took.len());
    println!();
    println!("# Summary");
    println!();
    let send_total: usize = measured.iter().map(|m| m.send_bytes).sum();
    let send_average = (send_total as f64) / (measured.len() as f64);
    let recv_total: usize = measured.iter().map(|m| m.recv_bytes).sum();
    let recv_average = (recv_total as f64) / (measured.len() as f64);
    let total_time: Duration = measured
        .iter()
        .map(|m| m.took.iter().sum::<Duration>())
        .sum();
    let average_time = total_time / (measured.len() as u32);
    println!("- Av.Time = {:?}", average_time);
    println!("- Av.Comm = {} bytes", send_average + recv_average);
    println!("  - Av.Send = {} bytes", send_average);
    println!("  - Av.Recv = {} bytes", recv_average);
    println!();
    println!("# Dataset");
    println!();

    for (i, party) in measured.iter().enumerate_u16() {
        println!("## Party {}", i);
        println!();
        println!("Send = {} bytes", party.send_bytes);
        println!();
        println!("Recv = {} bytes", party.recv_bytes);
        println!();
        for (j, took) in party.took.iter().enumerate_u16() {
            if j != 0 {
                print!(" → ");
            }
            print!("{:?}", took);
        }
        println!();
        println!();
    }
    println!();
}

#[test]
fn measure_bls_signing() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    let mut simulations = vec![];

    for n in (5..=45).step_by(10) {
        let t = n / 3;

        let mut simulation = Simulation::new();
        for i in 1..=n {
            simulation.add_party(Keygen::new(i, t, n).unwrap());
        }
        let local_keys = simulation.run().unwrap();

        let mut simulation = Simulation::new();
        for (i, local_key) in (1..).zip(&local_keys) {
            simulation.add_party(MeasureTool::new(
                Sign::new(b"ZenGo rules".to_vec(), i, n, local_key.clone()).unwrap(),
            ));
        }
        let _ = simulation.run().unwrap();

        simulations.push((n, t, simulation.parties))
    }

    for (n, t, parties) in simulations {
        analyse_measurements(format!("BLS Signing n={} t={}", n, t), &parties);
    }
}

#[test]
fn measure_bls_signing_for_various_t() {
    if std::env::var_os("HEAVY_TESTS").is_none() {
        println!("Env variable isn't set — test skipped");
        return;
    }

    let mut simulations = vec![];

    let n = 25;
    for t in (2..=8).step_by(2) {
        let mut simulation = Simulation::new();
        for i in 1..=n {
            simulation.add_party(Keygen::new(i, t, n).unwrap());
        }
        let local_keys = simulation.run().unwrap();

        let mut simulation = Simulation::new();
        for (i, local_key) in (1..).zip(&local_keys) {
            simulation.add_party(MeasureTool::new(
                Sign::new(b"Nice hat".to_vec(), i, n, local_key.clone()).unwrap(),
            ));
        }
        let _ = simulation.run().unwrap();

        simulations.push((n, t, simulation.parties))
    }

    for (n, t, parties) in simulations {
        analyse_measurements(format!("BLS Keygen n={} t={}", n, t), &parties);
    }
}
