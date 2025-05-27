pub const COMPLIANCE_GUEST_ELF: &[u8] = include_bytes!("../elfs/compliance_elf.bin");
pub const PADDING_GUEST_ELF: &[u8] = include_bytes!("../elfs/padding_logic_elf.bin");
pub const TEST_GUEST_ELF: &[u8] = include_bytes!("../elfs/test_logic_elf.bin");

pub const COMPLIANCE_GUEST_ID: [u32; 8] = [
    2701349585, 2527110832, 1097996496, 2632817458, 249378437, 3823558497, 3512528456, 3033479435,
];

pub const PADDING_GUEST_ID: [u32; 8] = [
    3568301530, 3855691811, 2315865068, 3130072989, 1647038886, 2441233379, 1348193728, 1587710096,
];

pub const TEST_GUEST_ID: [u32; 8] = [
    1139820909, 997563335, 2353495433, 3120987745, 583364796, 1182468441, 3901448634, 2610842315,
];
