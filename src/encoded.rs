use crate::definitions::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32};
use encoded_pointer::encoded::EncodedPointer;
use std::ops::{Deref, DerefMut};
use std::ptr::addr_of;

#[repr(transparent)]
pub(crate) struct PeEncodedPointer(EncodedPointer);
const _: () = assert!(std::mem::size_of::<PeEncodedPointer>() == std::mem::size_of::<usize>());

impl Deref for PeEncodedPointer {
    type Target = EncodedPointer;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for PeEncodedPointer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PeEncodedPointer {
    #[inline(always)]
    pub fn new(pointer: EncodedPointer) -> Self {
        Self(pointer)
    }
    /// Returns the base address of the PE .
    #[inline(always)]
    pub fn base_address(&self) -> usize {
        self.get_address()
    }
    /// Returns true if the architecture for the PE is 64-bit, or false for any other architecture.
    #[inline(always)]
    pub fn is_64bit(&self) -> bool {
        let nt_headers = self.nt_headers_address() as *const IMAGE_NT_HEADERS32;
        matches!(
            unsafe { (*nt_headers).FileHeader.Machine },
            0x200 | 0x284 | 0x5064 | 0x6264 | 0x8664 | 0xAA64
        )
    }
    /// Returns true if the PE is mapped into memory, or false is in it's "on disk" state.
    #[inline(always)]
    pub fn is_mapped(&self) -> bool {
        self.get_bool_one()
    }
    /// Returns the `IMAGE_NT_HEADERS` address of the PE.
    #[inline(always)]
    pub fn nt_headers_address(&self) -> usize {
        let dos_header = self.get_pointer::<IMAGE_DOS_HEADER>();
        unsafe { self.base_address() + (*dos_header).e_lfanew as usize }
    }
    /// Returns the `IMAGE_OPTIONAL_HEADER` address of the PE.
    #[inline(always)]
    pub fn optional_header_address(&self) -> usize {
        let nt_headers = self.nt_headers_address() as *const IMAGE_NT_HEADERS32;
        unsafe { addr_of!((*nt_headers).OptionalHeader) as usize }
    }
}
