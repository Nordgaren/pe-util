#![allow(unused)]
#![doc = include_str!("../README.md")]

use crate::consts::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_RESOURCE,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, MAX_SECTION_HEADER_LEN,
};
use crate::definitions::IMAGE_NT_HEADERS32;
use crate::definitions::{
    IMAGE_DATA_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_HEADER,
    IMAGE_IMPORT_DESCRIPTOR, IMAGE_RESOURCE_DIRECTORY_ENTRY, IMAGE_SECTION_HEADER,
    IMAGE_RESOURCE_DATA_ENTRY, IMAGE_RESOURCE_DIRECTORY,
};
use crate::dos_header::DosHeader;
use crate::encoded::PeEncodedPointer;
use crate::nt_headers::NtHeaders;
use crate::util::{case_insensitive_compare_strs_as_bytes, strlen};
use crate::FunctionId::{Name, Ordinal};
use core::marker::PhantomData;
use core::ptr::addr_of;
use encoded_pointer::encoded::EncodedPointer;
use std::io::{Error, ErrorKind};
use std::ops::{Deref, DerefMut};

mod consts;
mod definitions;
mod dos_header;
mod encoded;
mod nt_headers;
mod optional_header;
mod resource;
mod tests;
mod util;

/// A pointer sized type that allows the user to read a buffer in memory as a Windows PE. Currently only supports 32-bit
/// and 64-bit PEs on x86 architectures, but, I plan on supporting more architectures in the future.
/// This type is indifferent to 32 or 64-bit architecture, as well as wether or not the file has been mapped into memory
/// for execution, or if the file is still in it's on disk stat.
///
/// # Example
/// ```rust
/// # use pe_util::PE;
/// fn example(slice: &[u8]) {
///     let pe = PE::from_slice(slice).expect("Could not validate that slice is a valid PE file.");
///     let exports = pe.get_exports().unwrap_or_default();
///
///     for export in exports {
///         let ord = pe.get_function_ordinal(export.as_bytes());
///         println!("Export: {export} Ordinal: {ord}");
///     }
///
///     let res = pe.get_pe_resource(10, 100).expect("Could not find PE resource");
///
///     println!("{}", res.len());
/// }
/// ```
#[repr(transparent)]
pub struct PE<'a> {
    pointer: PeEncodedPointer,
    _marker: PhantomData<&'a u8>,
}
const _: () = assert!(std::mem::size_of::<PE>() == std::mem::size_of::<usize>());

/// An enum that represents the various types of ways a function can be Imported or Exported in a PE
/// file.
pub enum FunctionId<'a> {
    Name(&'a str),
    Ordinal(u16),
}
// Factory methods
impl<'a> PE<'a> {
    /// Returns a `PE` from a slice that starts with a valid PE file. The returned `PE` shares the
    /// lifetime of the slice.
    /// Returns an `Error` with `ErrorKind::InvalidData` if the pe cannot be validated by magic bytes
    /// and header signature values.
    ///
    /// # Arguments
    ///
    /// * `slice`: `&'a [u8]`
    ///
    /// returns: `Result<PE<DosHeader>, Error>`
    #[inline(always)]
    pub fn from_slice(slice: &'a [u8]) -> std::io::Result<Self> {
        Self::from_address(slice.as_ptr() as usize)
    }
    /// Returns a `PE` from a slice that starts with a valid PE file. The returned `PE` shares the
    /// lifetime of the slice. Does not validate that the slice is a valid PE file.
    ///
    /// # Arguments
    ///
    /// * `slice`: `&'a [u8]`
    ///
    /// returns: `PE<DosHeader`
    ///
    /// # Safety
    ///
    /// This function does not check EncodedPointer compatability, mapped state, nor that the slice is a valid PE file.
    #[inline(always)]
    pub unsafe fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self::from_ptr_unchecked(slice.as_ptr())
    }
    /// Returns a `PE` from a slice that shares the lifetime of the slice. Assumes the mapped state of
    /// with the passed in `is_mapped` parameter, and does not validate that the slice is a valid
    /// PE file.
    ///
    /// # Arguments
    ///
    /// * `slice`: `&'a [u8]`
    /// * `is_mapped`: `bool`
    ///
    /// returns: `PE<DosHeader>`
    ///
    /// # Safety
    ///
    /// This function does not check `EncodedPointer` compatability, mapped state, nor that the slice is
    /// a valid PE file. The caller must specify the correct mapped state for `is_mapped`.
    #[inline(always)]
    pub unsafe fn from_slice_assume_mapped(slice: &'a [u8], is_mapped: bool) -> Self {
        unsafe { Self::from_ptr_assume_mapped(slice.as_ptr(), is_mapped) }
    }
    /// Returns a `PE` from a `*const u8` that points to the start of a valid PE file. There is no
    /// associated lifetime for the returned `PE`.
    /// Returns an `Error` with `ErrorKind::InvalidData` if the pe cannot be validated by magic bytes
    /// and header signature values.
    ///
    /// # Arguments
    ///
    /// * `ptr`: `*const u8`
    ///
    /// returns: `Result<PE<DosHeader>, Error>`
    #[inline(always)]
    pub unsafe fn from_ptr(ptr: *const u8) -> std::io::Result<Self> {
        Self::from_address(ptr as usize)
    }
    /// Returns a `PE` from a `*const u8` that points to the start of a valid PE file. There is no
    /// associated lifetime for the returned `PE`. Does not do any validation of the data at the pointer.
    ///
    /// # Arguments
    ///
    /// * `ptr`: `*const u8`
    ///
    /// returns: `DosHeader`
    ///
    /// # Safety
    ///
    /// This function does not check `EncodedPointer` compatability, mapped state, nor that the pointer
    /// points to a valid PE file.
    #[inline(always)]
    pub unsafe fn from_ptr_unchecked(ptr: *const u8) -> Self {
        Self::from_address_unchecked(ptr as usize)
    }
    /// Returns a `PE` from a `*const u8` that points to the start of a valid PE file. There is no
    /// associated lifetime for the returned `PE`. Assumes the mapped state of with the passed in
    /// `is_mapped` parameter, and does not validate that the slice is a valid PE file.
    ///
    /// # Arguments
    ///
    /// * `slice`: `&'a [u8]`
    /// * `is_mapped`: `bool`
    ///
    /// returns: `PE<DosHeader>`
    ///
    /// # Safety
    ///
    /// This function does not check `EncodedPointer` compatability, mapped state, nor that the slice is
    /// a valid PE file. The caller must specify the correct mapped state for `is_mapped`.
    #[inline(always)]
    pub unsafe fn from_ptr_assume_mapped(slice: *const u8, is_mapped: bool) -> Self {
        unsafe { Self::from_address_assume_mapped(slice as usize, is_mapped) }
    }
    /// Returns a PE from a `usize` with the value of the address of a valid PE file. There is no
    /// associated lifetime for the returned `PE`.
    /// Returns an `Error` with `ErrorKind::InvalidData` if the pe cannot be validated by magic bytes
    /// and header signature values.
    ///
    /// # Arguments
    ///
    /// * `base_address`: `usize`
    ///
    /// returns: `Result<PE<DosHeader>, Error>`
    fn from_address(base_address: usize) -> std::io::Result<Self> {
        let mut pe = PE {
            pointer: PeEncodedPointer::new(EncodedPointer::new(base_address, false, false)?),
            _marker: PhantomData,
        };

        if !pe.validate() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Magic bytes or signature did not match expected value: Dos Magic: {} Nt Signature: {}",
                    pe.dos_headers().e_magic(),
                    pe.nt_headers().signature(),
                ),
            ));
        }

        let is_mapped = unsafe { pe.check_mapped() }.unwrap_or(true);
        pe.pointer.set_bool_one(is_mapped);

        Ok(pe)
    }
    /// Returns a PE from a `usize` with the value of the address of a PE file. There is no associated
    /// lifetime for the returned `PE`. Does not do any validation of the data at the address.
    ///
    /// # Arguments
    ///
    /// * `base_address`: `usize`
    ///
    /// returns: `PE<DosHeader>`
    ///
    /// # Safety
    ///
    /// This function does not check `EncodedPointer` compatability, mapped state, nor that the address
    /// provided points to a valid PE file.
    unsafe fn from_address_unchecked(base_address: usize) -> Self {
        PE {
            pointer: PeEncodedPointer::new(EncodedPointer::from_value_unchecked(base_address)),
            _marker: PhantomData,
        }
    }
    /// Returns a `PE` from a `usize` with the value of the address of a PE file. There is no associated
    /// lifetime for the returned `PE`. Assumes the mapped state of with the passed in `is_mapped`
    /// parameter, and does not validate that the data at the address is a valid PE file.
    ///
    /// # Arguments
    ///
    /// * `base_address`: `usize`
    /// * `is_mapped`: `bool`
    ///
    /// returns: `PE<DosHeader>`
    ///
    /// # Safety
    ///
    /// This function does not check `EncodedPointer` compatability, mapped state, nor that the pointer
    /// points to a valid PE file. The caller must specify the correct mapped state for `is_mapped`.
    unsafe fn from_address_assume_mapped(base_address: usize, is_mapped: bool) -> Self {
        let value = EncodedPointer::encode(base_address, is_mapped, false);

        PE {
            pointer: PeEncodedPointer::new(EncodedPointer::from_value_unchecked(value)),
            _marker: PhantomData,
        }
    }
}

impl PE<'_> {
    /// Returns true if the architecture for the PE is 64-bit, or false for any other architecture.
    ///
    /// returns: bool
    #[inline(always)]
    pub fn is_64bit(&self) -> bool {
        self.pointer.is_64bit()
    }
    /// Returns true if the PE is mapped into memory, or false is in it's "on disk" state.
    ///
    /// returns: bool
    #[inline(always)]
    pub fn is_mapped(&self) -> bool {
        self.pointer.is_mapped()
    }
    /// Checks that the memory pointed to by `self.pointer` is a valid PE file.
    ///
    /// returns: `bool`
    #[inline(always)]
    pub fn validate(&self) -> bool {
        self.dos_headers().e_magic() == IMAGE_DOS_SIGNATURE
            && self.nt_headers().signature() == IMAGE_NT_SIGNATURE
    }
    /// Returns the NtHeaders variant of the PE structure.
    ///
    /// returns: `PE<NtHeaders>`
    #[inline(always)]
    pub fn dos_headers(&self) -> &DosHeader {
        unsafe { &*(self as *const PE as *const DosHeader) }
    }
    /// Returns the NtHeaders variant of the PE structure.
    ///
    /// returns: `PE<NtHeaders>`
    #[inline(always)]
    pub unsafe fn dos_headers_mut(&mut self) -> &mut DosHeader {
        unsafe { &mut *(self as *mut PE as *mut DosHeader) }
    }
    /// Returns the NtHeaders variant of the PE structure.
    ///
    /// returns: `PE<NtHeaders>`
    #[inline(always)]
    pub fn nt_headers(&self) -> &NtHeaders {
        unsafe { &*(self as *const PE as *const NtHeaders) }
    }
    /// Returns the NtHeaders variant of the PE structure.
    ///
    /// returns: `PE<NtHeaders>`
    #[inline(always)]
    pub unsafe fn nt_headers_mut(&mut self) -> &mut NtHeaders {
        unsafe { &mut *(self as *mut PE as *mut NtHeaders) }
    }
    /// Returns the section headers for the PE file as a slice.
    ///
    /// returns: `&'_ mut [IMAGE_SECTION_HEADER]`
    #[inline(always)]
    pub fn section_headers(&self) -> &'_ [IMAGE_SECTION_HEADER] {
        let section_headers_base = self.pointer.nt_headers_address() + self.nt_headers().size_of();
        unsafe {
            std::slice::from_raw_parts(
                section_headers_base as *mut IMAGE_SECTION_HEADER,
                std::cmp::min(
                    self.nt_headers()
                        .optional_header()
                        .number_of_rva_and_sizes(),
                    MAX_SECTION_HEADER_LEN,
                ) as usize,
            )
        }
    }
    /// Returns the section headers for the PE file as a mutable slice.
    ///
    /// returns: `&'_ mut [IMAGE_SECTION_HEADER]`
    #[inline(always)]
    pub fn section_headers_mut(&mut self) -> &'_ mut [IMAGE_SECTION_HEADER] {
        let section_headers_base = self.pointer.nt_headers_address() + self.nt_headers().size_of();
        unsafe {
            std::slice::from_raw_parts_mut(
                section_headers_base as *mut IMAGE_SECTION_HEADER,
                std::cmp::min(
                    self.nt_headers()
                        .optional_header()
                        .number_of_rva_and_sizes(),
                    MAX_SECTION_HEADER_LEN,
                ) as usize,
            )
        }
    }
    unsafe fn check_mapped(&self) -> Option<bool> {
        // Check as if the file is an image on disk. We should be able to read the entire import table (or export table, if the import table is empty),
        // as ascii strings, if it's a file on disk.
        let nt_headers = self.nt_headers();
        let optional_header = nt_headers.optional_header();
        let data_dir = optional_header.data_directory();
        let import_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
        if import_data_dir.Size == 0 {
            return self.check_mapped_export_dir(data_dir);
        }

        let import_table_addr =
            self.pointer.base_address() + self.rva_to_foa(import_data_dir.VirtualAddress)? as usize;
        let length = import_data_dir.Size as usize / std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();

        let import_descriptor_table = std::slice::from_raw_parts(
            import_table_addr as *const IMAGE_IMPORT_DESCRIPTOR,
            // The last entry is all 0s to denote the end of the table.
            length - 1,
        );

        for import_descriptor in import_descriptor_table {
            let string_foa = self.rva_to_foa(import_descriptor.Name)?;
            let string_addr = self.pointer.base_address() + string_foa as usize;
            let string = std::slice::from_raw_parts(
                string_addr as *const u8,
                strlen(string_addr as *const u8),
            );
            if !string.is_ascii() {
                return Some(true);
            }
        }

        Some(false)
    }
    unsafe fn check_mapped_export_dir(&self, data_dir: &[IMAGE_DATA_DIRECTORY]) -> Option<bool> {
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        if export_data_dir.Size == 0 {
            return self.check_mapped_by_section();
        }
        let export_table_addr = &*((self.pointer.base_address()
            + self.rva_to_foa(export_data_dir.VirtualAddress)? as usize)
            as *const IMAGE_EXPORT_DIRECTORY);

        let function_name_table = std::slice::from_raw_parts(
            (self.pointer.base_address()
                + self.rva_to_foa(export_table_addr.AddressOfNames)? as usize)
                as *const u32,
            export_table_addr.NumberOfNames as usize,
        );

        for rva in function_name_table {
            let string_foa = self.rva_to_foa(*rva)?;
            let string_addr = self.pointer.base_address() + string_foa as usize;
            let string = std::slice::from_raw_parts(
                string_addr as *const u8,
                strlen(string_addr as *const u8),
            );
            if !string.is_ascii() {
                return Some(true);
            }
        }

        Some(false)
    }
    fn check_mapped_by_section(&self) -> Option<bool> {
        let section_headers = self.section_headers();
        let first_section_header = &section_headers[0];
        let first_section_address =
            self.pointer.base_address() + first_section_header.PointerToRawData as usize;
        let ptr_to_zero = first_section_address as *const u64;

        unsafe { Some(*ptr_to_zero == 0) }
    }
    /// Takes the `Relative Virtual Address` and returns the `File Offset Address`. The return value
    /// is an offset.
    ///
    /// # Arguments
    ///
    /// * `rva`: `u32`
    ///
    /// returns: `Option<u32>`
    pub fn rva_to_foa(&self, rva: u32) -> Option<u32> {
        let section_headers = self.section_headers();

        if rva < section_headers[0].PointerToRawData {
            return Some(rva);
        }

        for section_header in section_headers {
            if (rva >= section_header.VirtualAddress)
                && (rva <= section_header.VirtualAddress + section_header.SizeOfRawData)
            {
                let foa = section_header.PointerToRawData + (rva - section_header.VirtualAddress);
                let end_of_pe = self.pointer.base_address()
                    + self.nt_headers().optional_header().size_of_image() as usize;

                // Not sure if we should break here or not. Probably should, or return None, but why not
                // search the other headers. Maybe someone is playing tricks.
                if end_of_pe < self.pointer.base_address() + foa as usize {
                    continue;
                }

                return Some(foa);
            }
        }

        None
    }
    /// Takes in a FunctionId and looks up the function in the Export Directory by Name or Ordinal.
    /// Returns None if the specified function name or ordinal cannot be found.
    ///
    /// # Arguments
    ///
    /// * `export`: `FunctionId`
    ///
    /// returns: `Option<u32>`
    pub fn get_export_rva(&self, export: FunctionId) -> Option<u32> {
        let nt_headers = self.nt_headers();
        let optional_header = nt_headers.optional_header();
        let data_dir = optional_header.data_directory();
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        let is_mapped = self.pointer.is_mapped();

        let mut export_directory_offset = export_data_dir.VirtualAddress;
        if !is_mapped {
            export_directory_offset = self.rva_to_foa(export_directory_offset)?;
        }

        let export_directory = unsafe {
            &*((self.pointer.base_address() + export_directory_offset as usize)
                as *const IMAGE_EXPORT_DIRECTORY)
        };

        let mut export_address_table_rva = export_directory.AddressOfFunctions;
        if !is_mapped {
            export_address_table_rva = self.rva_to_foa(export_address_table_rva)?;
        }
        let export_address_table_array = unsafe {
            std::slice::from_raw_parts(
                (self.pointer.base_address() + export_address_table_rva as usize) as *const u32,
                export_directory.NumberOfFunctions as usize,
            )
        };

        match export {
            Ordinal(ordinal) => {
                let ordinal = ordinal as u32;
                let base = export_directory.Base;

                if (ordinal < base) || (ordinal >= base + export_directory.NumberOfFunctions) {
                    return None;
                }

                return Some(export_address_table_array[(ordinal - base) as usize]);
            }
            Name(export_name) => {
                let mut name_table_offset = export_directory.AddressOfNames;
                if !is_mapped {
                    name_table_offset = self.rva_to_foa(name_table_offset)?;
                }

                let function_name_table_array = unsafe {
                    std::slice::from_raw_parts(
                        (self.pointer.base_address() + name_table_offset as usize) as *const u32,
                        export_directory.NumberOfNames as usize,
                    )
                };

                for i in 0..export_directory.NumberOfNames as usize {
                    let mut string_offset = function_name_table_array[i];
                    if !is_mapped {
                        string_offset = self.rva_to_foa(string_offset)?;
                    }

                    let string_address = self.pointer.base_address() + string_offset as usize;
                    let name = unsafe {
                        std::slice::from_raw_parts(
                            string_address as *const u8,
                            strlen(string_address as *const u8),
                        )
                    };

                    if case_insensitive_compare_strs_as_bytes(export_name.as_bytes(), name) {
                        let mut hints_table_offset = export_directory.AddressOfNameOrdinals;
                        if !is_mapped {
                            hints_table_offset = self.rva_to_foa(hints_table_offset)?;
                        }

                        let hints_table_array = unsafe {
                            std::slice::from_raw_parts(
                                (self.pointer.base_address() + hints_table_offset as usize)
                                    as *const u16,
                                export_directory.NumberOfNames as usize,
                            )
                        };

                        return Some(export_address_table_array[hints_table_array[i] as usize]);
                    }
                }
            }
        }
        None
    }
    /// Returns a `Vec<&str>` that contains the names all the functions that are exported by name for
    /// the PE. Returns None if it could not find the export directory.
    ///
    /// # Arguments
    ///
    /// * `export`: `FunctionId`
    ///
    /// returns: `Option<Vec<&'_ str>>`
    pub fn get_exports(&self) -> Option<Vec<&'_ str>> {
        let nt_headers = self.nt_headers();
        let optional_header = nt_headers.optional_header();
        let data_dir = optional_header.data_directory();
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        if export_data_dir.Size == 0 {
            return None;
        }

        let is_mapped = self.pointer.is_mapped();

        let mut export_directory_offset = export_data_dir.VirtualAddress;
        if !is_mapped {
            export_directory_offset = self.rva_to_foa(export_directory_offset)?;
        }

        let export_directory = unsafe {
            &*((self.pointer.base_address() + export_directory_offset as usize)
                as *const IMAGE_EXPORT_DIRECTORY)
        };

        let mut name_table_offset = export_directory.AddressOfNames;
        if !is_mapped {
            name_table_offset = self.rva_to_foa(name_table_offset)?;
        }

        let function_name_table_array = unsafe {
            std::slice::from_raw_parts(
                (self.pointer.base_address() + name_table_offset as usize) as *const u32,
                export_directory.NumberOfNames as usize,
            )
        };

        let mut names = vec![];
        for offset in function_name_table_array {
            let mut string_offset = *offset;
            if !is_mapped {
                string_offset = match self.rva_to_foa(string_offset) {
                    Some(o) => o,
                    None => continue,
                };
            }

            let string_address = self.pointer.base_address() + string_offset as usize;
            let name = unsafe {
                std::slice::from_raw_parts(
                    string_address as *const u8,
                    strlen(string_address as *const u8),
                )
            };
            let name = match std::str::from_utf8(name) {
                Ok(s) => s,
                _ => continue,
            };
            names.push(name)
        }
        Some(names)
    }
    /// Returns the name of the function with the given ordinal value. Returns `None` if the Export
    /// directory cannot be found, or the provided ordinal is not found.
    ///
    /// # Arguments
    ///
    /// * `ordinal`: `u16`
    ///
    /// returns: `Option<String>`
    pub fn get_export_name(&self, ordinal: u16) -> Option<String> {
        let nt_headers = self.nt_headers();
        let optional_header = nt_headers.optional_header();
        let data_dir = optional_header.data_directory();
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        if export_data_dir.Size == 0 {
            return None;
        }

        let is_mapped = self.pointer.is_mapped();

        let mut export_directory_offset = export_data_dir.VirtualAddress;
        if !is_mapped {
            export_directory_offset = self.rva_to_foa(export_directory_offset)?;
        }

        let export_directory = unsafe {
            &*((self.pointer.base_address() + export_directory_offset as usize)
                as *const IMAGE_EXPORT_DIRECTORY)
        };

        let mut name_table_offset = export_directory.AddressOfNames;
        if !is_mapped {
            name_table_offset = self.rva_to_foa(name_table_offset)?;
        }

        let function_name_table_array = unsafe {
            std::slice::from_raw_parts(
                (self.pointer.base_address() + name_table_offset as usize) as *const u32,
                export_directory.NumberOfNames as usize,
            )
        };

        for offset in function_name_table_array {
            let ordinal = ordinal as u32;
            let base = export_directory.Base;

            if (ordinal - base) != ordinal {
                continue;
            }

            let mut string_offset = *offset;
            if !is_mapped {
                string_offset = self.rva_to_foa(string_offset)?;
            }

            let string_address = self.pointer.base_address() + string_offset as usize;
            let name = unsafe {
                std::slice::from_raw_parts(
                    string_address as *const u8,
                    strlen(string_address as *const u8),
                )
            };
            return String::from_utf8(name.to_vec()).ok();
        }

        None
    }
    /// Returns the ordinal of the function with the given name provided as a slice of bytes. Returns
    /// `None` if the Export directory cannot be found, or the provided ordinal is not found.
    ///
    /// # Arguments
    ///
    /// * `function_name`: `&[u8]`
    ///
    /// returns: `u16`
    pub fn get_function_ordinal(&self, function_name: &[u8]) -> u16 {
        unsafe {
            let base_addr = self.pointer.base_address();
            let nt_headers = self.nt_headers();
            let optional_header = nt_headers.optional_header();

            let export_dir =
                &optional_header.data_directory()[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

            let image_export_directory = &*((base_addr + export_dir.VirtualAddress as usize)
                as *const IMAGE_EXPORT_DIRECTORY);

            let name_dir = std::slice::from_raw_parts(
                (base_addr + image_export_directory.AddressOfNames as usize) as *const u32,
                image_export_directory.NumberOfNames as usize,
            );
            let ordinal_dir = std::slice::from_raw_parts(
                (base_addr + image_export_directory.AddressOfNameOrdinals as usize) as *const u16,
                image_export_directory.NumberOfNames as usize,
            );

            for i in 0..name_dir.len() {
                let name = std::slice::from_raw_parts(
                    (base_addr + name_dir[i] as usize) as *const u8,
                    strlen((base_addr + name_dir[i] as usize) as *const u8),
                );

                if case_insensitive_compare_strs_as_bytes(name, function_name) {
                    return ordinal_dir[i] + image_export_directory.Base as u16;
                }
            }
        }

        0
    }
    /// Looks up the Resource entry with the provided category and resource id. Currently assumes
    /// the first directory in the language entries. Returns the resource as a `&[u8]`, or `None` if
    /// the resource directory or resource could not be found.
    ///
    /// # Arguments
    ///
    /// * `category_id`: `u32`
    /// * `resource_id`: `u32`
    ///
    /// returns: `Option<&[u8]>`
    pub fn get_pe_resource(&self, category_id: u32, resource_id: u32) -> Option<&'_ [u8]> {
        let nt_headers = self.nt_headers();
        let optional_header = nt_headers.optional_header();
        let resource_data_dir =
            &optional_header.data_directory()[IMAGE_DIRECTORY_ENTRY_RESOURCE as usize];

        if resource_data_dir.Size == 0 {
            return None;
        }

        let is_mapped = self.pointer.is_mapped();

        let mut resource_directory_table_offset = resource_data_dir.VirtualAddress;
        if !is_mapped {
            resource_directory_table_offset = self.rva_to_foa(resource_directory_table_offset)?
        }
        unsafe {
            let resource_directory_table = &*((self.pointer.base_address()
                + resource_directory_table_offset as usize)
                as *const IMAGE_RESOURCE_DIRECTORY);

            let resource_data_entry =
                get_resource_data_entry(resource_directory_table, category_id, resource_id)?;

            let mut data_offset = resource_data_entry.DataRVA;
            if !is_mapped {
                data_offset = self.rva_to_foa(data_offset)?
            }

            let data = self.pointer.base_address() + data_offset as usize;
            Some(std::slice::from_raw_parts(
                data as *const u8,
                resource_data_entry.DataSize as usize,
            ))
        }
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
    resource_directory_table: &IMAGE_RESOURCE_DIRECTORY,
    category_id: u32,
    resource_id: u32,
) -> Option<&'a IMAGE_RESOURCE_DATA_ENTRY> {
    unsafe {
        // SAFETY: Literally the same thing, one is just mut, and the Rust compiler won't implicitly
        // downgrade the mutability, for some reason.
        std::mem::transmute(get_resource_data_entry_mut(
            resource_directory_table,
            category_id,
            resource_id,
        ))
    }
}

/// Returns a mutable reference to the requested `RESOURCE_DATA_ENTRY` using the category and resource IDs provided. Assumes
/// that the first language in the lang table is the right entry to use.
///
/// # Arguments
///
/// * `resource_directory_table`: `&RESOURCE_DIRECTORY_TABLE`
/// * `category_id`: `u32`
/// * `resource_id`: `u32`
///
/// returns: `Option<&mut RESOURCE_DATA_ENTRY>`
fn get_resource_data_entry_mut<'a>(
    resource_directory_table: &IMAGE_RESOURCE_DIRECTORY,
    category_id: u32,
    resource_id: u32,
) -> Option<&'a mut IMAGE_RESOURCE_DATA_ENTRY> {
    unsafe {
        let resource_directory_table_addr = addr_of!(*resource_directory_table) as usize;

        //level 1: Resource type directory
        let mut offset = get_entry_offset_by_id(resource_directory_table, category_id)?;
        offset &= 0x7FFFFFFF;

        //level 2: Resource Name/ID subdirectory
        let resource_directory_table_name_id =
            &*((resource_directory_table_addr + offset as usize) as *const IMAGE_RESOURCE_DIRECTORY);
        let mut offset = get_entry_offset_by_id(resource_directory_table_name_id, resource_id)?;
        offset &= 0x7FFFFFFF;

        //level 3: language subdirectory - just use the first entry.
        let resource_directory_table_lang =
            &*((resource_directory_table_addr + offset as usize) as *const IMAGE_RESOURCE_DIRECTORY);
        let resource_directory_table_lang_entries = addr_of!(*resource_directory_table_lang)
            as usize
            + std::mem::size_of::<IMAGE_RESOURCE_DIRECTORY>();
        let resource_directory_table_lang_entry =
            &*((resource_directory_table_lang_entries) as *const IMAGE_RESOURCE_DIRECTORY_ENTRY);
        let offset = resource_directory_table_lang_entry.OffsetToData;

        Some(&mut *((resource_directory_table_addr + offset as usize) as *mut IMAGE_RESOURCE_DATA_ENTRY))
    }
}

unsafe fn get_entry_offset_by_id(
    resource_directory_table: &IMAGE_RESOURCE_DIRECTORY,
    category_id: u32,
) -> Option<u32> {
    // We have to skip the Name entries, here, to iterate over the entries by Id.
    let resource_entries_address = addr_of!(*resource_directory_table) as usize
        + std::mem::size_of::<IMAGE_RESOURCE_DIRECTORY>()
        + (std::mem::size_of::<IMAGE_RESOURCE_DIRECTORY_ENTRY>()
        * resource_directory_table.NumberOfNameEntries as usize);
    let resource_directory_entries = std::slice::from_raw_parts(
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
    resource_directory_table: &IMAGE_RESOURCE_DIRECTORY,
    name: &[u8],
) -> Option<u32> {
    let resource_entries_address = addr_of!(*resource_directory_table) as usize
        + std::mem::size_of::<IMAGE_RESOURCE_DIRECTORY>();
    let resource_directory_entries = std::slice::from_raw_parts(
        resource_entries_address as *const IMAGE_RESOURCE_DIRECTORY_ENTRY,
        resource_directory_table.NumberOfNameEntries as usize,
    );

    for resource_directory_entry in resource_directory_entries {
        let name_ptr =
            addr_of!(*resource_directory_table) as usize + resource_directory_entry.Id as usize;
        let resource_name =
            std::slice::from_raw_parts(name_ptr as *const u8, strlen(name_ptr as *const u8));
        if resource_name == name {
            return Some(resource_directory_entry.OffsetToData);
        }
    }

    None
}
