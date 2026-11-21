use crate::domain::models::{DoctorReport, XdgLayout};
use crate::domain::ports::SystemProbePort;

pub struct DoctorUseCase<'a> {
    probe: &'a dyn SystemProbePort,
}

impl<'a> DoctorUseCase<'a> {
    pub fn new(probe: &'a dyn SystemProbePort) -> Self {
        Self { probe }
    }

    pub fn execute(&self, layout: &XdgLayout) -> DoctorReport {
        self.probe.probe_environment(layout)
    }
}
