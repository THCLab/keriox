pub mod attached_signature_code;
pub mod basic;
pub mod group;
pub mod material_path_codes;
pub mod self_addressing;
pub mod self_signing;
pub mod serial_number;

pub trait DerivationCode {
    // hard (fixed) part of code size in chars
    fn hard_size(&self) -> usize;
    // soft (variable) part of code size in chars
    fn soft_size(&self) -> usize;
    // value size in chars
    fn value_size(&self) -> usize;

    fn code_size(&self) -> usize {
        self.hard_size() + self.soft_size()
    }
    // full size in chars of code prefixed to data
    fn full_size(&self) -> usize {
        self.code_size() + self.value_size()
    }
    fn to_str(&self) -> String;
}
