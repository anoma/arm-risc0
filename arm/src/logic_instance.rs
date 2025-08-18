#[cfg(feature = "nif")]
use rustler::NifStruct;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.LogicInstance")]
pub struct LogicInstance {
    pub tag: Vec<u32>,
    pub is_consumed: bool,
    pub root: Vec<u32>,
    pub app_data: AppData,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.AppData")]
pub struct AppData {
    pub resource_payload: Vec<ExpirableBlob>,
    pub discovery_payload: Vec<ExpirableBlob>,
    pub external_payload: Vec<ExpirableBlob>,
    pub application_payload: Vec<ExpirableBlob>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.ExpirableBlob")]
pub struct ExpirableBlob {
    pub blob: Vec<u32>,
    pub deletion_criterion: u8,
}

impl AppData {
    pub fn new() -> Self {
        AppData {
            resource_payload: Vec::new(),
            discovery_payload: Vec::new(),
            external_payload: Vec::new(),
            application_payload: Vec::new(),
        }
    }

    pub fn add_resource_payload(&mut self, blob: ExpirableBlob) {
        self.resource_payload.push(blob);
    }

    pub fn add_discovery_payload(&mut self, blob: ExpirableBlob) {
        self.discovery_payload.push(blob);
    }

    pub fn add_external_payload(&mut self, blob: ExpirableBlob) {
        self.external_payload.push(blob);
    }

    pub fn add_application_payload(&mut self, blob: ExpirableBlob) {
        self.application_payload.push(blob);
    }
}
