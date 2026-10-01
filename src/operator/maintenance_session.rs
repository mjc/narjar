use std::path::{Path, PathBuf};

use narjar::__private::{
    maintenance::{
        Mode as MaintenanceMode, Operation as MaintenanceOperation, Outcome as MaintenanceOutcome,
        Recorder as MaintenanceRecorder, RunValues as MaintenanceValues,
    },
    narinfo::TrustedPublicKeys,
    storage::{Directory, RecoveredStorage, RecoveryStatus, Storage, StorageBackend},
};

use crate::error::Error;

use super::runtime;

#[derive(Clone, Copy)]
pub(super) struct MaintenanceRecord {
    operation: MaintenanceOperation,
    mode: MaintenanceMode,
}

impl MaintenanceRecord {
    pub(super) const fn new(operation: MaintenanceOperation, mode: MaintenanceMode) -> Self {
        Self { operation, mode }
    }
}

pub(super) struct MaintenanceSession {
    data_dir: PathBuf,
    storage: Storage,
    trusted_keys: TrustedPublicKeys,
    record: Option<MaintenanceRecord>,
}

impl MaintenanceSession {
    pub(super) fn open(
        data_dir: &Path,
        backend: StorageBackend,
        record: Option<MaintenanceRecord>,
    ) -> Result<Self, Error> {
        let directory = Directory::open(data_dir).map_err(runtime)?;
        directory.validate_initialized().map_err(runtime)?;
        let storage = Storage::initialize(&directory, backend).map_err(runtime)?;
        let trusted_keys = TrustedPublicKeys::load(&directory).map_err(runtime)?;
        Ok(Self {
            data_dir: data_dir.to_owned(),
            storage,
            trusted_keys,
            record,
        })
    }

    pub(super) fn run_inspection<T>(
        self,
        operation: impl FnOnce(
            &Storage,
            &TrustedPublicKeys,
        ) -> Result<(T, MaintenanceOutcome, MaintenanceValues), Error>,
    ) -> Result<T, Error> {
        let recorder = self.start_recording();
        let result = operation(&self.storage, &self.trusted_keys);
        record_maintenance_result(recorder, result)
    }

    pub(super) fn run_mutation<T>(
        self,
        operation: impl FnOnce(
            &RecoveredStorage<'_>,
            &TrustedPublicKeys,
        ) -> Result<(T, MaintenanceOutcome, MaintenanceValues), Error>,
    ) -> Result<T, Error> {
        let recovered = self
            .storage
            .recover_for_mutation(&self.trusted_keys)
            .map_err(runtime)?;
        report_recovery_completion(recovered.recovery_status());
        let recorder = self.start_recording();
        let result = operation(&recovered, &self.trusted_keys);
        record_maintenance_result(recorder, result)
    }

    fn start_recording(&self) -> Option<MaintenanceRecorder> {
        self.record.and_then(|record| {
            match MaintenanceRecorder::begin(&self.data_dir, record.operation, record.mode) {
                Ok(recorder) => Some(recorder),
                Err(error) => {
                    eprintln!("could not record maintenance start: {error}");
                    None
                }
            }
        })
    }
}

fn report_recovery_completion(status: RecoveryStatus) {
    if let RecoveryStatus::Completed(checked) = status {
        eprintln!("narjar: maintenance recovery completed after checking {checked} narinfos");
    }
}

fn record_maintenance_result<T>(
    recorder: Option<MaintenanceRecorder>,
    result: Result<(T, MaintenanceOutcome, MaintenanceValues), Error>,
) -> Result<T, Error> {
    match result {
        Ok((value, outcome, values)) => {
            finish_maintenance(recorder, outcome, values);
            Ok(value)
        }
        Err(error) => {
            finish_maintenance(
                recorder,
                MaintenanceOutcome::Failure,
                MaintenanceValues::default(),
            );
            Err(error)
        }
    }
}

fn finish_maintenance(
    recorder: Option<MaintenanceRecorder>,
    outcome: MaintenanceOutcome,
    values: MaintenanceValues,
) {
    if let Some(recorder) = recorder
        && let Err(error) = recorder.finish(outcome, values)
    {
        eprintln!("could not record maintenance completion: {error}");
    }
}
