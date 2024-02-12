use crate::definitions::{IMAGE_FILE_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64};
use crate::dos_header::DosHeader;
use crate::optional_header::OptionalHeader;
use crate::{PeEncodedPointer, PE};
use encoded_pointer::encoded::EncodedPointer;
use std::marker::PhantomData;

/// Type that represents the `IMAGE_NT_HEADERS` portion of the PE file
#[repr(transparent)]
pub struct NtHeaders<'a> {
    pointer: PeEncodedPointer,
    _marker: PhantomData<&'a u8>,
}
const _: () = assert!(std::mem::size_of::<NtHeaders>() == std::mem::size_of::<usize>());

impl NtHeaders<'_> {
    #[inline(always)]
    fn nt_headers32(&self) -> &'_ IMAGE_NT_HEADERS32 {
        unsafe { &mut *(self.pointer.nt_headers_address() as *mut IMAGE_NT_HEADERS32) }
    }
    #[inline(always)]
    fn nt_headers64(&self) -> &'_ IMAGE_NT_HEADERS64 {
        unsafe { &mut *(self.pointer.nt_headers_address() as *mut IMAGE_NT_HEADERS64) }
    }
    #[inline(always)]
    pub fn signature(&self) -> u32 {
        self.nt_headers32().Signature
    }
    #[inline(always)]
    pub fn file_header(&self) -> &'_ IMAGE_FILE_HEADER {
        &self.nt_headers32().FileHeader
    }
    #[inline(always)]
    pub fn optional_header(&self) -> &OptionalHeader {
        unsafe { &*(self as *const NtHeaders as *const OptionalHeader) }
    }
    #[inline(always)]
    pub unsafe fn optional_header_mut(&mut self) -> &mut OptionalHeader {
        unsafe { &mut *(self as *mut NtHeaders as *mut OptionalHeader) }
    }
    #[inline(always)]
    pub fn size_of(&self) -> usize {
        if self.pointer.is_64bit() {
            std::mem::size_of::<IMAGE_NT_HEADERS64>()
        } else {
            std::mem::size_of::<IMAGE_NT_HEADERS32>()
        }
    }
}

impl NtHeaders<'_> {
    #[inline(always)]
    fn nt_headers32_mut(&mut self) -> &'_ mut IMAGE_NT_HEADERS32 {
        unsafe { &mut *(self.pointer.nt_headers_address() as *mut IMAGE_NT_HEADERS32) }
    }
    #[inline(always)]
    fn nt_headers64_mut(&mut self) -> &'_ mut IMAGE_NT_HEADERS64 {
        unsafe { &mut *(self.pointer.nt_headers_address() as *mut IMAGE_NT_HEADERS64) }
    }
    #[inline(always)]
    pub fn set_signature(&mut self, value: u32) {
        self.nt_headers32_mut().Signature = value
    }
    #[inline(always)]
    pub unsafe fn file_header_mut(&mut self) -> &'_ mut IMAGE_FILE_HEADER {
        &mut self.nt_headers32_mut().FileHeader
    }
}
