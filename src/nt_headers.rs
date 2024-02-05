use crate::definitions::{IMAGE_FILE_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64};
use crate::optional_header::{Const, ImageOptionalHeader, Mut};
use crate::PE;
use std::marker::PhantomData;
use std::mem;
use std::mem::size_of;
/// ZST that represents the IMAGE_NT_HEADERS portion of the PE file
#[derive(Copy, Clone)]
pub struct NtHeaders;

impl PE<'_, NtHeaders> {
    #[inline(always)]
    fn nt_headers32(&self) -> &'_ IMAGE_NT_HEADERS32 {
        unsafe { mem::transmute(self.nt_headers_address()) }
    }
    #[inline(always)]
    fn nt_headers64(&self) -> &'_ IMAGE_NT_HEADERS64 {
        unsafe { mem::transmute(self.nt_headers_address()) }
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
    pub fn optional_header(&self) -> PE<ImageOptionalHeader<Const>> {
        PE {
            pointer: self.pointer,
            _marker: PhantomData,
        }
    }
    #[inline(always)]
    pub fn optional_header_mut(&mut self) -> PE<ImageOptionalHeader<Mut>> {
        PE {
            pointer: self.pointer,
            _marker: PhantomData,
        }
    }
    #[inline(always)]
    pub fn size_of(self) -> usize {
        if self.is_64bit() {
            size_of::<IMAGE_NT_HEADERS64>()
        } else {
            size_of::<IMAGE_NT_HEADERS32>()
        }
    }
}

impl PE<'_, NtHeaders> {
    #[inline(always)]
    fn nt_headers32_mut(&mut self) -> &'_ mut IMAGE_NT_HEADERS32 {
        unsafe { mem::transmute(self.nt_headers_address()) }
    }
    #[inline(always)]
    fn nt_headers64_mut(&mut self) -> &'_ mut IMAGE_NT_HEADERS64 {
        unsafe { mem::transmute(self.nt_headers_address()) }
    }
    #[inline(always)]
    pub fn set_signature(&mut self, value: u32) {
        self.nt_headers32_mut().Signature = value
    }
    #[inline(always)]
    pub fn file_header_mut(&mut self) -> &'_ mut IMAGE_FILE_HEADER {
        &mut self.nt_headers32_mut().FileHeader
    }
}