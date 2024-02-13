use crate::definitions::{IMAGE_FILE_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64};
use crate::encoded::PeEncodedPointer;
use std::marker::PhantomData;

/// Type that represents the `IMAGE_FILE_HEADER` portion of the PE file
#[repr(transparent)]
pub struct FileHeader<'a> {
    pointer: PeEncodedPointer,
    _marker: PhantomData<&'a u8>,
}

const _: () =
    assert!(std::mem::size_of::<crate::nt_headers::NtHeaders>() == std::mem::size_of::<usize>());

impl FileHeader<'_> {
    /// Returns `IMAGE_FILE_HEADER` reference
    #[inline(always)]
    fn file_header(&self) -> &'_ IMAGE_FILE_HEADER {
        &unsafe { &mut *(self.pointer.nt_headers_address() as *mut IMAGE_NT_HEADERS32) }.FileHeader
    }
    #[inline(always)]
    pub fn machine(&self) -> u16 {
        self.file_header().Machine
    }
    #[inline(always)]
    pub fn number_of_sections(&self) -> u16 {
        self.file_header().NumberOfSections
    }
    #[inline(always)]
    pub fn time_date_stamp(&self) -> u32 {
        self.file_header().TimeDateStamp
    }
    #[inline(always)]
    pub fn pointer_to_symbol_table(&self) -> u32 {
        self.file_header().PointerToSymbolTable
    }
    #[inline(always)]
    pub fn number_of_symbols(&self) -> u32 {
        self.file_header().NumberOfSymbols
    }
    #[inline(always)]
    pub fn size_of_optional_header(&self) -> u16 {
        self.file_header().SizeOfOptionalHeader
    }
    #[inline(always)]
    pub fn characteristics(&self) -> u16 {
        self.file_header().Characteristics
    }

    #[inline(always)]
    pub fn size_of(&self) -> usize {
        std::mem::size_of::<IMAGE_FILE_HEADER>()
    }
}

impl FileHeader<'_> {
    /// Returns mutable `IMAGE_FILE_HEADER` reference
    #[inline(always)]
    fn file_header_mut(&mut self) -> &'_ mut IMAGE_FILE_HEADER {
        &mut unsafe { &mut *(self.pointer.nt_headers_address() as *mut IMAGE_NT_HEADERS32) }
            .FileHeader
    }
    #[inline(always)]
    pub fn get_machine(&mut self, value: u16) {
        self.file_header_mut().Machine = value;
    }
    #[inline(always)]
    pub fn get_number_of_sections(&mut self, value: u16) {
        self.file_header_mut().NumberOfSections = value;
    }
    #[inline(always)]
    pub fn get_time_date_stamp(&mut self, value: u32) {
        self.file_header_mut().TimeDateStamp = value;
    }
    #[inline(always)]
    pub fn get_pointer_to_symbol_table(&mut self, value: u32) {
        self.file_header_mut().PointerToSymbolTable = value;
    }
    #[inline(always)]
    pub fn get_number_of_symbols(&mut self, value: u32) {
        self.file_header_mut().NumberOfSymbols = value;
    }
    #[inline(always)]
    pub fn get_size_of_optional_header(&mut self, value: u16) {
        self.file_header_mut().SizeOfOptionalHeader = value;
    }
    #[inline(always)]
    pub fn get_characteristics(&mut self, value: u16) {
        self.file_header_mut().Characteristics = value;
    }
}
