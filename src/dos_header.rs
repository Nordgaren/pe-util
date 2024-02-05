use crate::consts::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_RESOURCE,
    IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE, MAX_SECTION_HEADER_LEN,
};
use crate::definitions::{
    IMAGE_DATA_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER, RESOURCE_DIRECTORY_TABLE,
};
use crate::dos_header::FunctionId::{Name, Ordinal};
use crate::nt_headers::NtHeaders;
use crate::util::{case_insensitive_compare_strs_as_bytes, strlen};
use crate::{get_resource_data_entry, PE};
use encoded_pointer::encoded::EncodedPointer;
use std::io::{Error, ErrorKind};
use std::marker::PhantomData;
use std::mem::size_of;
use std::str::Utf8Error;
use std::{cmp, mem};

/// ZST that represents the IMAGE_DOS_HEADER portion of the PE file, as well as most of the base
/// functionality that shouldn't be shared with the other typestates.
#[derive(Copy, Clone)]
pub struct DosHeader;

/// An enum that represents the various types of ways a function can be Imported or Exported in a PE
/// file.
pub enum FunctionId<'a> {
    Name(&'a str),
    Ordinal(u16),
}

impl<'a> PE<'a, DosHeader> {
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
    /// a valid PE file.
    #[inline(always)]
    pub unsafe fn from_slice_assume_mapped(slice: &'a [u8], is_mapped: bool) -> Self {
        unsafe { Self::from_address_assume_mapped(slice.as_ptr() as usize, is_mapped) }
    }
}

impl PE<'_, DosHeader> {
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
    pub fn from_ptr(ptr: *const u8) -> std::io::Result<Self> {
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
    pub fn from_address(base_address: usize) -> std::io::Result<Self> {
        let mut pe = PE {
            pointer: EncodedPointer::new(base_address, false, false)?,
            _marker: PhantomData,
        };

        if !pe.validate() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Magic bytes or signature did not match expected value: Dos Magic: {} Nt Signature: {}", pe.dos_header().e_magic, pe.nt_headers().signature()),
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
    pub unsafe fn from_address_unchecked(base_address: usize) -> Self {
        PE {
            pointer: EncodedPointer::from_value_unchecked(base_address),
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
    /// points to a valid PE file.
    pub unsafe fn from_address_assume_mapped(base_address: usize, is_mapped: bool) -> Self {
        let value = EncodedPointer::encode(base_address, is_mapped, false);

        PE {
            pointer: EncodedPointer::from_value_unchecked(value),
            _marker: PhantomData,
        }
    }
    /// Checks that the memory pointed to by `self.pointer` is a valid PE file.
    ///
    /// returns: `bool`
    pub fn validate(self) -> bool {
        self.dos_header().e_magic == IMAGE_DOS_SIGNATURE
            && self.nt_headers().signature() == IMAGE_NT_SIGNATURE
    }

    unsafe fn check_mapped(self) -> Option<bool> {
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
            self.base_address() + self.rva_to_foa(import_data_dir.VirtualAddress)? as usize;
        let length = import_data_dir.Size as usize / size_of::<IMAGE_IMPORT_DESCRIPTOR>();

        let import_descriptor_table = std::slice::from_raw_parts(
            import_table_addr as *const IMAGE_IMPORT_DESCRIPTOR,
            // The last entry is all 0s to denote the end of the table.
            length - 1,
        );

        for import_descriptor in import_descriptor_table {
            let string_foa = self.rva_to_foa(import_descriptor.Name)?;
            let string_addr = self.base_address() + string_foa as usize;
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
    unsafe fn check_mapped_export_dir(self, data_dir: &[IMAGE_DATA_DIRECTORY]) -> Option<bool> {
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        if export_data_dir.Size == 0 {
            return self.check_mapped_by_section();
        }
        let export_table_addr: &IMAGE_EXPORT_DIRECTORY = mem::transmute(
            self.base_address() + self.rva_to_foa(export_data_dir.VirtualAddress)? as usize,
        );

        let function_name_table = std::slice::from_raw_parts(
            (self.base_address() + self.rva_to_foa(export_table_addr.AddressOfNames)? as usize)
                as *const u32,
            export_table_addr.NumberOfNames as usize,
        );

        for rva in function_name_table {
            let string_foa = self.rva_to_foa(*rva)?;
            let string_addr = self.base_address() + string_foa as usize;
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
    fn check_mapped_by_section(self) -> Option<bool> {
        let section_headers = self.section_headers();
        let first_section_header = &section_headers[0];
        let first_section_address =
            self.base_address() + first_section_header.PointerToRawData as usize;
        let ptr_to_zero = first_section_address as *const u64;

        unsafe { Some(*ptr_to_zero == 0) }
    }
    /// Returns a reference to the start of the PE file as an `IMAGE_DOS_HEADER`.
    ///
    /// returns: `&'_ IMAGE_DOS_HEADER`
    #[inline(always)]
    pub fn dos_header(&self) -> &'_ IMAGE_DOS_HEADER {
        unsafe { &*self.pointer.get_pointer() }

    }
    /// Returns a reference to the start of the PE file as an `IMAGE_DOS_HEADER`.
    ///
    /// returns: `&'_ IMAGE_DOS_HEADER`
    #[inline(always)]
    pub fn dos_header_mut(&mut self) -> &'_ mut IMAGE_DOS_HEADER {
        unsafe { &mut *self.pointer.get_mut_pointer() }
    }
    /// Returns the NtHeaders variant of the PE structure.
    ///
    /// returns: `PE<NtHeaders>`
    #[inline(always)]
    pub fn nt_headers(&self) -> PE<NtHeaders> {
        PE {
            pointer: self.pointer,
            _marker: PhantomData,
        }
    }
    /// Returns the section headers for the PE file as a slice.
    ///
    /// returns: `&'_ mut [IMAGE_SECTION_HEADER]`
    #[inline(always)]
    pub fn section_headers(&self) -> &'_ [IMAGE_SECTION_HEADER] {
        let section_headers_base = self.nt_headers_address() + self.nt_headers().size_of();
        unsafe {
            std::slice::from_raw_parts(
                section_headers_base as *mut IMAGE_SECTION_HEADER,
                cmp::min(
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
        let section_headers_base = self.nt_headers_address() + self.nt_headers().size_of();
        unsafe {
            std::slice::from_raw_parts_mut(
                section_headers_base as *mut IMAGE_SECTION_HEADER,
                cmp::min(
                    self.nt_headers()
                        .optional_header()
                        .number_of_rva_and_sizes(),
                    MAX_SECTION_HEADER_LEN,
                ) as usize,
            )
        }
    }
    /// Takes the `Relative Virtual Address` and returns the `File Offset Address`. The return value
    /// is an offset.
    ///
    /// # Arguments
    ///
    /// * `rva`: `u32`
    ///
    /// returns: `Option<u32>`
    pub fn rva_to_foa(self, rva: u32) -> Option<u32> {
        let section_headers = self.section_headers();

        if rva < section_headers[0].PointerToRawData {
            return Some(rva);
        }

        for section_header in section_headers {
            if (rva >= section_header.VirtualAddress)
                && (rva <= section_header.VirtualAddress + section_header.SizeOfRawData)
            {
                let foa = section_header.PointerToRawData + (rva - section_header.VirtualAddress);
                let end_of_pe = self.base_address()
                    + self.nt_headers().optional_header().size_of_image() as usize;

                // Not sure if we should break here or not. Probably should, or return None, but why not
                // search the other headers. Maybe someone is playing tricks.
                if end_of_pe < self.base_address() + foa as usize {
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
    pub fn get_export_rva(self, export: FunctionId) -> Option<u32> {
        let nt_headers = self.nt_headers();
        let optional_header = nt_headers.optional_header();
        let data_dir = optional_header.data_directory();
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        let is_mapped = self.is_mapped();

        let mut export_directory_offset = export_data_dir.VirtualAddress;
        if !is_mapped {
            export_directory_offset = self.rva_to_foa(export_directory_offset)?;
        }

        let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
            unsafe { mem::transmute(self.base_address() + export_directory_offset as usize) };

        let mut export_address_table_rva = export_directory.AddressOfFunctions;
        if !is_mapped {
            export_address_table_rva = self.rva_to_foa(export_address_table_rva)?;
        }
        let export_address_table_array = unsafe {
            std::slice::from_raw_parts(
                (self.base_address() + export_address_table_rva as usize) as *const u32,
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
                        (self.base_address() + name_table_offset as usize) as *const u32,
                        export_directory.NumberOfNames as usize,
                    )
                };

                for i in 0..export_directory.NumberOfNames as usize {
                    let mut string_offset = function_name_table_array[i];
                    if !is_mapped {
                        string_offset = self.rva_to_foa(string_offset)?;
                    }

                    let string_address = self.base_address() + string_offset as usize;
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
                                (self.base_address() + hints_table_offset as usize) as *const u16,
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

        let is_mapped = self.is_mapped();

        let mut export_directory_offset = export_data_dir.VirtualAddress;
        if !is_mapped {
            export_directory_offset = self.rva_to_foa(export_directory_offset)?;
        }

        let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
            unsafe { mem::transmute(self.base_address() + export_directory_offset as usize) };

        let mut name_table_offset = export_directory.AddressOfNames;
        if !is_mapped {
            name_table_offset = self.rva_to_foa(name_table_offset)?;
        }

        let function_name_table_array = unsafe {
            std::slice::from_raw_parts(
                (self.base_address() + name_table_offset as usize) as *const u32,
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

            let string_address = self.base_address() + string_offset as usize;
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
    pub fn get_export_name(self, ordinal: u16) -> Option<String> {
        let nt_headers = self.nt_headers();
        let optional_header = nt_headers.optional_header();
        let data_dir = optional_header.data_directory();
        let export_data_dir = &data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

        if export_data_dir.Size == 0 {
            return None;
        }

        let is_mapped = self.is_mapped();

        let mut export_directory_offset = export_data_dir.VirtualAddress;
        if !is_mapped {
            export_directory_offset = self.rva_to_foa(export_directory_offset)?;
        }

        let export_directory: &'static IMAGE_EXPORT_DIRECTORY =
            unsafe { mem::transmute(self.base_address() + export_directory_offset as usize) };

        let mut name_table_offset = export_directory.AddressOfNames;
        if !is_mapped {
            name_table_offset = self.rva_to_foa(name_table_offset)?;
        }

        let function_name_table_array = unsafe {
            std::slice::from_raw_parts(
                (self.base_address() + name_table_offset as usize) as *const u32,
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

            let string_address = self.base_address() + string_offset as usize;
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
    pub fn get_function_ordinal(self, function_name: &[u8]) -> u16 {
        unsafe {
            let base_addr = self.base_address();
            let nt_headers = self.nt_headers();
            let optional_header = nt_headers.optional_header();

            let export_dir =
                &optional_header.data_directory()[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];

            let image_export_directory: &IMAGE_EXPORT_DIRECTORY =
                mem::transmute(base_addr + export_dir.VirtualAddress as usize);

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

        let is_mapped = self.is_mapped();

        let mut resource_directory_table_offset = resource_data_dir.VirtualAddress;
        if !is_mapped {
            resource_directory_table_offset = self.rva_to_foa(resource_directory_table_offset)?
        }
        unsafe {
            let resource_directory_table: &RESOURCE_DIRECTORY_TABLE =
                mem::transmute(self.base_address() + resource_directory_table_offset as usize);

            let resource_data_entry =
                get_resource_data_entry(resource_directory_table, category_id, resource_id)?;

            let mut data_offset = resource_data_entry.DataRVA;
            if !is_mapped {
                data_offset = self.rva_to_foa(data_offset)?
            }

            let data = self.base_address() + data_offset as usize;
            Some(std::slice::from_raw_parts(
                data as *const u8,
                resource_data_entry.DataSize as usize,
            ))
        }
    }
}
