use std::time::Duration;

use crate::observation::{ObservationBoundary, ProcessObservation};

pub(crate) struct ExecutionReport {
    command: String,
    duration: Duration,
    exit_code: Option<i32>,
    termination_signal: Option<i32>,
    observation: ProcessObservation,
}

impl ExecutionReport {
    pub(crate) fn new(
        command: String,
        duration: Duration,
        exit_code: Option<i32>,
        termination_signal: Option<i32>,
        observation: ProcessObservation,
    ) -> Self {
        Self {
            command,
            duration,
            exit_code,
            termination_signal,
            observation,
        }
    }

    pub(crate) fn render<B: ObservationBoundary>(mut self, boundary: &B) {
        self.observation.print_report(
            boundary,
            &self.command,
            self.duration,
            self.exit_code,
            self.termination_signal,
        );
    }
}
