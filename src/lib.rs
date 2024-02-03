#![allow(unused)]

use crate::consts::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_RESOURCE,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, MAX_SECTION_HEADER_LEN,
};
use crate::definitions::{IMAGE_DATA_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_SECTION_HEADER, RESOURCE_DATA_ENTRY, RESOURCE_DIRECTORY_TABLE};
use crate::definitions::IMAGE_NT_HEADERS32;
use crate::util::{case_insensitive_compare_strs_as_bytes, strlen};
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::addr_of;
use core::{cmp, mem, slice};
use encoded_pointer::encoded::EncodedPointer;
use std::io::{Error, ErrorKind};

mod consts;
mod definitions;
mod resource;
mod tests;
mod util;
mod nt_headers;
mod optional_header;
mod dos_header;

/// A pointer sized type that allows the user to treat a buffer in memory as a Windows PE. Currently only supports 32-bit
/// and 64-bit PEs on x86 architectures, but, I plan on supporting more architectures in the future.
#[derive(Copy, Clone)]
pub struct PE<'a, S> {
    pointer: EncodedPointer,
    _marker: PhantomData<&'a S>,
}

impl<S> PE<'_, S> {
    /// Returns the base address of the PE .
    ///
    /// returns: usize
    #[inline(always)]
    pub fn base_address(self) -> usize {
        self.pointer.get_address()
    }
    /// Returns the `IMAGE_NT_HEADERS` address of the PE.
    ///
    /// returns: usize
    fn nt_headers_address(self) -> usize {
        let dos_header = self.pointer.get_pointer::<IMAGE_DOS_HEADER>();
        unsafe { self.base_address() + (*dos_header).e_lfanew as usize }
    }
    /// Returns the `IMAGE_OPTIONAL_HEADER` address of the PE.
    ///
    /// returns: usize
    fn optional_header_address(self) -> usize {
        let nt_headers = self.nt_headers_address() as *const IMAGE_NT_HEADERS32;
        unsafe { addr_of!((*nt_headers).OptionalHeader) as usize }
    }
    /// Returns true if the architecture for the PE is 64-bit, or false for any other architecture.
    ///
    /// returns: bool
    #[inline(always)]
    pub fn is_64bit(self) -> bool {
        let nt_headers = self.nt_headers_address() as *const IMAGE_NT_HEADERS32;
        match unsafe { (*nt_headers).FileHeader.Machine } {
            0x200 => true,
            0x284 => true,
            0x5064 => true,
            0x6264 => true,
            0x8664 => true,
            0xAA64 => true,
            _ => false,
        }
    }
    /// Returns true if the PE is mapped into memory, or false is in it's "on disk" state.
    ///
    /// returns: bool
    #[inline(always)]
    pub fn is_mapped(self) -> bool {
        self.pointer.get_bool_one()
    }
}

/// Returns a reference to the requested `RESOURCE_DATA_ENTRY` using the category and resource IDs provided. Assumes that
/// the first language in the lang table is the right entry to use.
///
/// # Arguments
///
/// * `resource_directory_table`: `&RESOURCE_DIRECTORY_TABLE`
/// * `category_id`: `u32`
/// * `resource_id`: `u32`
///
/// returns: `Option<&RESOURCE_DATA_ENTRY>`
fn get_resource_data_entry<'a>(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    category_id: u32,
    resource_id: u32,
) -> Option<&'a RESOURCE_DATA_ENTRY> {
    unsafe {
        let resource_directory_table_addr = addr_of!(*resource_directory_table) as usize;

        //level 1: Resource type directory
        let mut offset = get_entry_offset_by_id(resource_directory_table, category_id)?;
        offset &= 0x7FFFFFFF;

        //level 2: Resource Name/ID subdirectory
        let resource_directory_table_name_id: &RESOURCE_DIRECTORY_TABLE =
            mem::transmute(resource_directory_table_addr + offset as usize);
        let mut offset = get_entry_offset_by_id(resource_directory_table_name_id, resource_id)?;
        offset &= 0x7FFFFFFF;

        //level 3: language subdirectory - just use the first entry.
        let resource_directory_table_lang: &RESOURCE_DIRECTORY_TABLE =
            mem::transmute(resource_directory_table_addr + offset as usize);
        let resource_directory_table_lang_entries = addr_of!(*resource_directory_table_lang)
            as usize
            + size_of::<RESOURCE_DIRECTORY_TABLE>();
        let resource_directory_table_lang_entry: &IMAGE_RESOURCE_DIRECTORY_ENTRY =
            mem::transmute(resource_directory_table_lang_entries);
        let offset = resource_directory_table_lang_entry.OffsetToData;

        Some(mem::transmute(
            resource_directory_table_addr + offset as usize,
        ))
    }
}

unsafe fn get_entry_offset_by_id(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    category_id: u32,
) -> Option<u32> {
    // We have to skip the Name entries, here, to iterate over the entires by Id.
    let resource_entries_address = addr_of!(*resource_directory_table) as usize
        + size_of::<RESOURCE_DIRECTORY_TABLE>()
        + (size_of::<IMAGE_RESOURCE_DIRECTORY_ENTRY>()
        * resource_directory_table.NumberOfNameEntries as usize);
    let resource_directory_entries = slice::from_raw_parts(
        resource_entries_address as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        resource_directory_table.NumberOfIDEntries as usize,
    );

    for resource_directory_entry in resource_directory_entries {
        if resource_directory_entry.Id == category_id {
            return Some(resource_directory_entry.OffsetToData);
        }
    }

    None
}

unsafe fn get_entry_offset_by_name(
    resource_directory_table: &RESOURCE_DIRECTORY_TABLE,
    name: &[u8],
) -> Option<u32> {
    let resource_entries_address =
        addr_of!(*resource_directory_table) as usize + size_of::<RESOURCE_DIRECTORY_TABLE>();
    let resource_directory_entries = slice::from_raw_parts(
        resource_entries_address as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        resource_directory_table.NumberOfNameEntries as usize,
    );

    for resource_directory_entry in resource_directory_entries {
        let name_ptr =
            addr_of!(*resource_directory_table) as usize + resource_directory_entry.Id as usize;
        let resource_name =
            slice::from_raw_parts(name_ptr as *const u8, strlen(name_ptr as *const u8));
        if resource_name == name {
            return Some(resource_directory_entry.OffsetToData);
        }
    }

    None
}
