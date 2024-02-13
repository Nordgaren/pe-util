use crate::consts::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_RESOURCE,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, MAX_SECTION_HEADER_LEN,
};
use crate::definitions::{
    IMAGE_DATA_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER, IMAGE_RESOURCE_DIRECTORY,
};
use crate::encoded::PeEncodedPointer;
use crate::nt_headers::NtHeaders;
use crate::util::{case_insensitive_compare_strs_as_bytes, strlen};
use crate::{get_resource_data_entry, PE};
use encoded_pointer::encoded::EncodedPointer;
use std::cmp;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::str::Utf8Error;

/// Type that represents the `IMAGE_DOS_HEADER` portion of the PE file.
#[repr(transparent)]
pub struct DosHeader<'a> {
    pointer: PeEncodedPointer,
    _marker: PhantomData<&'a u8>,
}

const _: () = assert!(std::mem::size_of::<DosHeader>() == std::mem::size_of::<usize>());

impl DosHeader<'_> {
    /// Returns a reference to the start of the PE file as an `IMAGE_DOS_HEADER`.
    #[inline(always)]
    fn dos_header(&self) -> &'_ IMAGE_DOS_HEADER {
        unsafe { &*self.pointer.get_pointer() }
    }
    /// Returns a reference to the start of the PE file as an `IMAGE_DOS_HEADER`.
    #[inline(always)]
    fn dos_header_mut(&mut self) -> &'_ mut IMAGE_DOS_HEADER {
        unsafe { &mut *self.pointer.get_mut_pointer() }
    }
    #[inline(always)]
    pub fn e_magic(&self) -> u16 {
        self.dos_header().e_magic
    }
    #[inline(always)]
    pub fn e_cblp(&self) -> u16 {
        self.dos_header().e_cblp
    }
    #[inline(always)]
    pub fn e_cp(&self) -> u16 {
        self.dos_header().e_cp
    }
    #[inline(always)]
    pub fn e_crlc(&self) -> u16 {
        self.dos_header().e_crlc
    }
    #[inline(always)]
    pub fn e_cparhdr(&self) -> u16 {
        self.dos_header().e_cparhdr
    }
    #[inline(always)]
    pub fn e_minalloc(&self) -> u16 {
        self.dos_header().e_minalloc
    }
    #[inline(always)]
    pub fn e_ss(&self) -> u16 {
        self.dos_header().e_ss
    }
    #[inline(always)]
    pub fn e_sp(&self) -> u16 {
        self.dos_header().e_sp
    }
    #[inline(always)]
    pub fn e_csum(&self) -> u16 {
        self.dos_header().e_csum
    }
    #[inline(always)]
    pub fn e_ip(&self) -> u16 {
        self.dos_header().e_ip
    }
    #[inline(always)]
    pub fn e_cs(&self) -> u16 {
        self.dos_header().e_cs
    }
    #[inline(always)]
    pub fn e_lfarlc(&self) -> u16 {
        self.dos_header().e_lfarlc
    }
    #[inline(always)]
    pub fn e_ovno(&self) -> u16 {
        self.dos_header().e_ovno
    }
    #[inline(always)]
    pub fn e_res(&self) -> [u16; 4] {
        self.dos_header().e_res
    }
    #[inline(always)]
    pub fn e_oemid(&self) -> u16 {
        self.dos_header().e_oemid
    }
    #[inline(always)]
    pub fn e_oeminfo(&self) -> u16 {
        self.dos_header().e_oeminfo
    }
    #[inline(always)]
    pub fn e_res2(&self) -> [u16; 10] {
        self.dos_header().e_res2
    }

    #[inline(always)]
    pub fn e_lfanew(&self) -> i32 {
        self.dos_header().e_lfanew
    }
}

impl DosHeader<'_> {
    #[inline(always)]
    pub fn set_e_magic(&mut self, value: u16) {
        self.dos_header_mut().e_magic = value;
    }
    #[inline(always)]
    pub fn set_e_cblp(&mut self, value: u16) {
        self.dos_header_mut().e_cblp = value;
    }
    #[inline(always)]
    pub fn set_e_cp(&mut self, value: u16) {
        self.dos_header_mut().e_cp = value;
    }
    #[inline(always)]
    pub fn set_e_crlc(&mut self, value: u16) {
        self.dos_header_mut().e_crlc = value;
    }
    #[inline(always)]
    pub fn set_e_cparhdr(&mut self, value: u16) {
        self.dos_header_mut().e_cparhdr = value;
    }
    #[inline(always)]
    pub fn set_e_minalloc(&mut self, value: u16) {
        self.dos_header_mut().e_minalloc = value;
    }
    #[inline(always)]
    pub fn set_e_ss(&mut self, value: u16) {
        self.dos_header_mut().e_ss = value;
    }
    #[inline(always)]
    pub fn set_e_sp(&mut self, value: u16) {
        self.dos_header_mut().e_sp = value;
    }
    #[inline(always)]
    pub fn set_e_csum(&mut self, value: u16) {
        self.dos_header_mut().e_csum = value;
    }
    #[inline(always)]
    pub fn set_e_ip(&mut self, value: u16) {
        self.dos_header_mut().e_ip = value;
    }
    #[inline(always)]
    pub fn set_e_cs(&mut self, value: u16) {
        self.dos_header_mut().e_cs = value;
    }
    #[inline(always)]
    pub fn set_e_lfarlc(&mut self, value: u16) {
        self.dos_header_mut().e_lfarlc = value;
    }
    #[inline(always)]
    pub fn set_e_ovno(&mut self, value: u16) {
        self.dos_header_mut().e_ovno = value;
    }
    #[inline(always)]
    pub fn set_e_res(&mut self, value: [u16; 4]) {
        self.dos_header_mut().e_res = value;
    }
    #[inline(always)]
    pub fn set_e_oemid(&mut self, value: u16) {
        self.dos_header_mut().e_oemid = value;
    }
    #[inline(always)]
    pub fn set_e_oeminfo(&mut self, value: u16) {
        self.dos_header_mut().e_oeminfo = value;
    }
    #[inline(always)]
    pub fn set_e_res2(&mut self, value: [u16; 10]) {
        self.dos_header_mut().e_res2 = value;
    }
    #[inline(always)]
    pub fn set_e_lfanew(&mut self, value: i32) {
        self.dos_header_mut().e_lfanew = value;
    }
}

