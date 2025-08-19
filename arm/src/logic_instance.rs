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
    pub cipher: Vec<u8>,
    pub app_data: Vec<ExpirableBlob>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "nif", derive(NifStruct))]
#[cfg_attr(feature = "nif", module = "Anoma.Arm.ExpirableBlob")]
pub struct ExpirableBlob {
    pub blob: Vec<u8>,
    pub deletion_criterion: u8,
}
