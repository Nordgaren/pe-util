#![allow(non_snake_case)]
use std::ptr::addr_of;

// I am not sure if I should do this for both structures, or just have to user add the size of `GRPICONDIR`
// to the pointer to `GRPICONDIR` get the pointer to `GRPICONDIRENTRY`.
#[derive(Default)]
#[repr(C, packed(2))]
pub struct GRPICONDIR {
    pub idReserved: u16,
    pub idType: u16,
    pub idCount: u16,
    pub idEntries: GRPICONDIRENTRY,
}
impl GRPICONDIR {
    pub fn get_entries(&self) -> &[GRPICONDIRENTRY] {
        unsafe { std::slice::from_raw_parts(addr_of!(self.idEntries), self.idCount as usize) }
    }
}
#[derive(Default)]
#[repr(C, packed(2))]
pub struct GRPICONDIRENTRY {
    pub bWidth: u8,
    pub bHeight: u8,
    pub bColorCount: u8,
    pub bReserved: u8,
    pub wPlanes: u16,
    pub wBitCount: u16,
    pub dwBytesInRes: u32,
    pub nId: u16,
}
