pub trait IteratorExt: Iterator {
    fn enumerate_u16(self) -> EnumerateU16<Self>
    where
        Self: Sized,
    {
        EnumerateU16(0, self)
    }

    fn position_u16<P>(&mut self, mut pred: P) -> Option<u16>
    where
        P: FnMut(Self::Item) -> bool,
    {
        for (i, el) in self.enumerate_u16() {
            if pred(el) {
                return Some(i);
            }
        }
        None
    }
}

impl<I> IteratorExt for I where I: Iterator {}

pub struct EnumerateU16<I>(u16, I);

impl<I> Iterator for EnumerateU16<I>
where
    I: Iterator,
{
    type Item = (u16, I::Item);
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.1.next()?;
        let i = self.0;
        self.0 = i.checked_add(1).expect("u16 index overflowed");
        Some((i, item))
    }
}

#[cfg(test)]
pub mod performance_analysis {
    use std::convert::TryFrom;
    use std::time::Duration;

    pub enum PhaseMeasurement<'m> {
        /// Phase is measured
        Available(&'m [Duration]),
        /// Phase were skipped thus not measured
        Skipped,
        /// Phase is too short to measure
        Dust,
    }

    pub fn analyse_measurements(name: String, measurements: &[PhaseMeasurement]) {
        println!("{}", name);
        println!("===========");
        println!();
        println!("# Protocol Performance Report");
        println!();
        let parties = measurements
            .iter()
            .find_map(|m| match m {
                PhaseMeasurement::Available(m) => Some(m.len()),
                _ => None,
            })
            .unwrap();
        println!("- Parties: {}", parties);
        let phases = measurements.len();
        let skipped = measurements
            .iter()
            .filter(|phase| matches!(phase, PhaseMeasurement::Skipped))
            .count();
        let dust = measurements
            .iter()
            .filter(|phase| matches!(phase, PhaseMeasurement::Dust))
            .count();
        println!("- Phases: {} (skipped {}, dust {})", phases, skipped, dust);
        println!();
        println!("## Dataset");
        println!();

        for party_i in 0..parties {
            println!("### Party {}", party_i);
            for phase_i in 0..phases {
                if phase_i > 0 {
                    print!(" → ");
                }
                match &measurements[phase_i] {
                    PhaseMeasurement::Available(m) => print!("{:?}", m[party_i]),
                    PhaseMeasurement::Skipped => print!("Skipped"),
                    PhaseMeasurement::Dust => print!("Dust"),
                }
            }
            println!();
            println!();
        }
        println!();

        println!("## Average phase duration");
        println!();
        for phase_i in 0..phases {
            let measurements = match &measurements[phase_i] {
                PhaseMeasurement::Available(m) => m,
                PhaseMeasurement::Skipped => {
                    println!("Phase {}: Skipped", phase_i);
                    println!();
                    continue;
                }
                PhaseMeasurement::Dust => {
                    println!("Phase {}: Dust", phase_i);
                    println!();
                    continue;
                }
            };
            let total: Duration = measurements.iter().sum();
            let average = total / u32::try_from(parties).unwrap();
            println!("Phase {}: {:?}", phase_i, average);
            println!();
        }
        println!();

        println!("## Protocol took (per party)");
        println!();
        let mut total_for_all_parties = Duration::default();
        for party_i in 0..parties {
            let total: Duration = measurements
                .iter()
                .flat_map(|m| match m {
                    PhaseMeasurement::Available(m) => Some(&m[party_i]),
                    _ => None,
                })
                .sum();
            total_for_all_parties += total;
            println!("- Party {}: {:?}", party_i, total);
        }
        println!();
        let average = total_for_all_parties / u32::try_from(parties).unwrap();
        println!("Average: {:?}", average);
        println!();
    }
}
