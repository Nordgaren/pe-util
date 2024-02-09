use crate::consts::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_RESOURCE,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, MAX_SECTION_HEADER_LEN,
};
use crate::definitions::{
    IMAGE_DATA_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER, RESOURCE_DIRECTORY_TABLE,
};
use crate::encoded::PeEncodedPointer;
use crate::nt_headers::NtHeaders;
use crate::util::{case_insensitive_compare_strs_as_bytes, strlen};
use crate::{get_resource_data_entry, PE};
use encoded_pointer::encoded::EncodedPointer;
use std::cmp;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem::size_of;
use std::str::Utf8Error;

/// Type that represents the `IMAGE_DOS_HEADER` portion of the PE file.
pub struct DosHeader<'a> {
    pointer: PeEncodedPointer,
    _marker: PhantomData<&'a u8>,
}

impl DosHeader<'_> {
    /// Returns a reference to the start of the PE file as an `IMAGE_DOS_HEADER`.
    ///
    /// returns: `&'_ IMAGE_DOS_HEADER`
    #[inline(always)]
    fn dos_header(&self) -> &'_ IMAGE_DOS_HEADER {
        unsafe { &*self.pointer.get_pointer() }
    }
    /// Returns a reference to the start of the PE file as an `IMAGE_DOS_HEADER`.
    ///
    /// returns: `&'_ IMAGE_DOS_HEADER`
    #[inline(always)]
    fn dos_header_mut(&mut self) -> &'_ mut IMAGE_DOS_HEADER {
        unsafe { &mut *self.pointer.get_mut_pointer() }
    }
    #[inline(always)]
    pub fn e_magic(&self) -> u16 {
        self.dos_header().e_magic
    }
    #[inline(always)]
    pub fn e_lfanew(&self) -> i32 {
        self.dos_header().e_lfanew
    }
}
