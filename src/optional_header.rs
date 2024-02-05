use crate::definitions::{IMAGE_DATA_DIRECTORY, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64};
use crate::PE;
use std::mem;
use std::mem::size_of;

/// ZST that represents the IMAGE_OPTIONAL_HEADER portion of the PE file
#[derive(Copy, Clone)]
pub struct ImageOptionalHeader;

impl PE<'_, ImageOptionalHeader> {
    #[inline(always)]
    fn optional_header32(&self) -> &'_ IMAGE_OPTIONAL_HEADER32 {
        unsafe { mem::transmute(self.optional_header_address()) }
    }
    #[inline(always)]
    fn optional_header64(&self) -> &'_ IMAGE_OPTIONAL_HEADER64 {
        unsafe { mem::transmute(self.optional_header_address()) }
    }
    #[inline(always)]
    pub fn magic(self) -> u16 {
        self.optional_header32().Magic
    }
    #[inline(always)]
    pub fn major_linker_version(self) -> u8 {
        self.optional_header32().MajorLinkerVersion
    }
    #[inline(always)]
    pub fn minor_linker_version(self) -> u8 {
        self.optional_header32().MinorLinkerVersion
    }
    #[inline(always)]
    pub fn size_of_code(self) -> u32 {
        self.optional_header32().SizeOfCode
    }
    #[inline(always)]
    pub fn size_of_initialized_data(self) -> u32 {
        self.optional_header32().SizeOfInitializedData
    }
    #[inline(always)]
    pub fn size_of_uninitialized_data(self) -> u32 {
        self.optional_header32().SizeOfUninitializedData
    }
    #[inline(always)]
    pub fn address_of_entry_point(self) -> u32 {
        self.optional_header32().AddressOfEntryPoint
    }
    #[inline(always)]
    pub fn base_of_code(self) -> u32 {
        self.optional_header32().BaseOfCode
    }
    #[inline(always)]
    pub fn image_base(self) -> u64 {
        if self.is_64bit() {
            self.optional_header64().ImageBase
        } else {
            self.optional_header32().ImageBase as u64
        }
    }
    #[inline(always)]
    pub fn section_alignment(self) -> u32 {
        if self.is_64bit() {
            self.optional_header64().SectionAlignment
        } else {
            self.optional_header32().SectionAlignment
        }
    }
    #[inline(always)]
    pub fn file_alignment(self) -> u32 {
        if self.is_64bit() {
            self.optional_header64().FileAlignment
        } else {
            self.optional_header32().FileAlignment
        }
    }
    #[inline(always)]
    pub fn major_operating_system_version(self) -> u16 {
        if self.is_64bit() {
            self.optional_header64().MajorOperatingSystemVersion
        } else {
            self.optional_header32().MajorOperatingSystemVersion
        }
    }
    #[inline(always)]
    pub fn minor_operating_system_version(self) -> u16 {
        if self.is_64bit() {
            self.optional_header64().MinorOperatingSystemVersion
        } else {
            self.optional_header32().MinorOperatingSystemVersion
        }
    }
    #[inline(always)]
    pub fn major_image_version(self) -> u16 {
        if self.is_64bit() {
            self.optional_header64().MajorImageVersion
        } else {
            self.optional_header32().MajorImageVersion
        }
    }
    #[inline(always)]
    pub fn minor_image_version(self) -> u16 {
        if self.is_64bit() {
            self.optional_header64().MinorImageVersion
        } else {
            self.optional_header32().MinorImageVersion
        }
    }
    #[inline(always)]
    pub fn major_subsystem_version(self) -> u16 {
        if self.is_64bit() {
            self.optional_header64().MajorSubsystemVersion
        } else {
            self.optional_header32().MajorSubsystemVersion
        }
    }
    #[inline(always)]
    pub fn minor_subsystem_version(self) -> u16 {
        if self.is_64bit() {
            self.optional_header64().MinorSubsystemVersion
        } else {
            self.optional_header32().MinorSubsystemVersion
        }
    }
    #[inline(always)]
    pub fn win32_version_value(self) -> u32 {
        if self.is_64bit() {
            self.optional_header64().Win32VersionValue
        } else {
            self.optional_header32().Win32VersionValue
        }
    }
    #[inline(always)]
    pub fn size_of_image(self) -> u32 {
        if self.is_64bit() {
            self.optional_header64().SizeOfImage
        } else {
            self.optional_header32().SizeOfImage
        }
    }
    #[inline(always)]
    pub fn size_of_headers(self) -> u32 {
        if self.is_64bit() {
            self.optional_header64().SizeOfHeaders
        } else {
            self.optional_header32().SizeOfHeaders
        }
    }
    #[inline(always)]
    pub fn check_sum(self) -> u32 {
        if self.is_64bit() {
            self.optional_header64().CheckSum
        } else {
            self.optional_header32().CheckSum
        }
    }
    #[inline(always)]
    pub fn subsystem(self) -> u16 {
        if self.is_64bit() {
            self.optional_header64().Subsystem
        } else {
            self.optional_header32().Subsystem
        }
    }
    #[inline(always)]
    pub fn dll_characteristics(self) -> u16 {
        if self.is_64bit() {
            self.optional_header64().DllCharacteristics
        } else {
            self.optional_header32().DllCharacteristics
        }
    }
    #[inline(always)]
    pub fn size_of_stack_reserve(self) -> u64 {
        if self.is_64bit() {
            self.optional_header64().SizeOfStackReserve
        } else {
            self.optional_header32().SizeOfStackReserve as u64
        }
    }
    #[inline(always)]
    pub fn size_of_stack_commit(self) -> u64 {
        if self.is_64bit() {
            self.optional_header64().SizeOfStackCommit
        } else {
            self.optional_header32().SizeOfStackCommit as u64
        }
    }
    #[inline(always)]
    pub fn size_of_heap_reserve(self) -> u64 {
        if self.is_64bit() {
            self.optional_header64().SizeOfHeapReserve
        } else {
            self.optional_header32().SizeOfHeapReserve as u64
        }
    }
    #[inline(always)]
    pub fn size_of_heap_commit(self) -> u64 {
        if self.is_64bit() {
            self.optional_header64().SizeOfHeapCommit
        } else {
            self.optional_header32().SizeOfHeapCommit as u64
        }
    }
    #[inline(always)]
    pub fn loader_flags(self) -> u32 {
        if self.is_64bit() {
            self.optional_header64().LoaderFlags
        } else {
            self.optional_header32().LoaderFlags
        }
    }
    #[inline(always)]
    pub fn number_of_rva_and_sizes(self) -> u32 {
        if self.is_64bit() {
            self.optional_header64().NumberOfRvaAndSizes
        } else {
            self.optional_header32().NumberOfRvaAndSizes
        }
    }
    #[inline(always)]
    pub fn data_directory(&self) -> &'_ [IMAGE_DATA_DIRECTORY] {
        if self.is_64bit() {
            &self.optional_header64().DataDirectory
        } else {
            &self.optional_header32().DataDirectory
        }
    }
    #[inline(always)]
    pub fn size_of(self) -> usize {
        if self.is_64bit() {
            size_of::<IMAGE_OPTIONAL_HEADER64>()
        } else {
            size_of::<IMAGE_OPTIONAL_HEADER32>()
        }
    }
}

impl PE<'_, ImageOptionalHeader> {
    #[inline(always)]
    fn optional_header32_mut(&mut self) -> &'_ mut IMAGE_OPTIONAL_HEADER32 {
        unsafe { mem::transmute(self.optional_header_address()) }
    }
    #[inline(always)]
    fn optional_header64_mut(&mut self) -> &'_ mut IMAGE_OPTIONAL_HEADER64 {
        unsafe { mem::transmute(self.optional_header_address()) }
    }
    #[inline(always)]
    pub fn set_magic(&mut self, value: u16) {
        self.optional_header32_mut().Magic = value
    }
    #[inline(always)]
    pub fn set_major_linker_version(&mut self, value: u8) {
        self.optional_header32_mut().MajorLinkerVersion = value
    }
    #[inline(always)]
    pub fn set_minor_linker_version(&mut self, value: u8) {
        self.optional_header32_mut().MinorLinkerVersion = value
    }
    #[inline(always)]
    pub fn set_size_of_code(&mut self, value: u32) {
        self.optional_header32_mut().SizeOfCode = value
    }
    #[inline(always)]
    pub fn set_size_of_initialized_data(&mut self, value: u32) {
        self.optional_header32_mut().SizeOfInitializedData = value
    }
    #[inline(always)]
    pub fn set_size_of_uninitialized_data(&mut self, value: u32) {
        self.optional_header32_mut().SizeOfUninitializedData = value
    }
    #[inline(always)]
    pub fn set_address_of_entry_point(&mut self, value: u32) {
        self.optional_header32_mut().AddressOfEntryPoint = value
    }
    #[inline(always)]
    pub fn set_base_of_code(&mut self, value: u32) {
        self.optional_header32_mut().BaseOfCode = value
    }
    #[inline(always)]
    pub fn set_image_base(&mut self, value: u64) {
        if self.is_64bit() {
            self.optional_header64_mut().ImageBase = value
        } else {
            self.optional_header32_mut().ImageBase = value as u32
        }
    }
    #[inline(always)]
    pub fn set_section_alignment(&mut self, value: u32) {
        if self.is_64bit() {
            self.optional_header64_mut().SectionAlignment = value
        } else {
            self.optional_header32_mut().SectionAlignment = value
        }
    }
    #[inline(always)]
    pub fn set_file_alignment(&mut self, value: u32) {
        if self.is_64bit() {
            self.optional_header64_mut().FileAlignment = value
        } else {
            self.optional_header32_mut().FileAlignment = value
        }
    }
    #[inline(always)]
    pub fn set_major_operating_system_version(&mut self, value: u16) {
        if self.is_64bit() {
            self.optional_header64_mut().MajorOperatingSystemVersion = value
        } else {
            self.optional_header32_mut().MajorOperatingSystemVersion = value
        }
    }
    #[inline(always)]
    pub fn set_minor_operating_system_version(&mut self, value: u16) {
        if self.is_64bit() {
            self.optional_header64_mut().MinorOperatingSystemVersion = value
        } else {
            self.optional_header32_mut().MinorOperatingSystemVersion = value
        }
    }
    #[inline(always)]
    pub fn set_major_image_version(&mut self, value: u16) {
        if self.is_64bit() {
            self.optional_header64_mut().MajorImageVersion = value
        } else {
            self.optional_header32_mut().MajorImageVersion = value
        }
    }
    #[inline(always)]
    pub fn set_minor_image_version(&mut self, value: u16) {
        if self.is_64bit() {
            self.optional_header64_mut().MinorImageVersion = value
        } else {
            self.optional_header32_mut().MinorImageVersion = value
        }
    }
    #[inline(always)]
    pub fn set_major_subsystem_version(&mut self, value: u16) {
        if self.is_64bit() {
            self.optional_header64_mut().MajorSubsystemVersion = value
        } else {
            self.optional_header32_mut().MajorSubsystemVersion = value
        }
    }
    #[inline(always)]
    pub fn set_minor_subsystem_version(&mut self, value: u16) {
        if self.is_64bit() {
            self.optional_header64_mut().MinorSubsystemVersion = value
        } else {
            self.optional_header32_mut().MinorSubsystemVersion = value
        }
    }
    #[inline(always)]
    pub fn set_win32_version_value(&mut self, value: u32) {
        if self.is_64bit() {
            self.optional_header64_mut().Win32VersionValue = value
        } else {
            self.optional_header32_mut().Win32VersionValue = value
        }
    }
    #[inline(always)]
    pub fn set_size_of_image(&mut self, value: u32) {
        if self.is_64bit() {
            self.optional_header64_mut().SizeOfImage = value
        } else {
            self.optional_header32_mut().SizeOfImage = value
        }
    }
    #[inline(always)]
    pub fn set_size_of_headers(&mut self, value: u32) {
        if self.is_64bit() {
            self.optional_header64_mut().SizeOfHeaders = value
        } else {
            self.optional_header32_mut().SizeOfHeaders = value
        }
    }
    #[inline(always)]
    pub fn set_check_sum(&mut self, value: u32) {
        if self.is_64bit() {
            self.optional_header64_mut().CheckSum = value
        } else {
            self.optional_header32_mut().CheckSum = value
        }
    }
    #[inline(always)]
    pub fn set_subsystem(&mut self, value: u16) {
        if self.is_64bit() {
            self.optional_header64_mut().Subsystem = value
        } else {
            self.optional_header32_mut().Subsystem = value
        }
    }
    #[inline(always)]
    pub fn set_dll_characteristics(&mut self, value: u16) {
        if self.is_64bit() {
            self.optional_header64_mut().DllCharacteristics = value
        } else {
            self.optional_header32_mut().DllCharacteristics = value
        }
    }
    #[inline(always)]
    pub fn set_size_of_stack_reserve(&mut self, value: u64) {
        if self.is_64bit() {
            self.optional_header64_mut().SizeOfStackReserve = value
        } else {
            self.optional_header32_mut().SizeOfStackReserve = value as u32
        }
    }
    #[inline(always)]
    pub fn set_size_of_stack_commit(&mut self, value: u64) {
        if self.is_64bit() {
            self.optional_header64_mut().SizeOfStackCommit = value
        } else {
            self.optional_header32_mut().SizeOfStackCommit = value as u32
        }
    }
    #[inline(always)]
    pub fn set_size_of_heap_reserve(&mut self, value: u64) {
        if self.is_64bit() {
            self.optional_header64_mut().SizeOfHeapReserve = value
        } else {
            self.optional_header32_mut().SizeOfHeapReserve = value as u32
        }
    }
    #[inline(always)]
    pub fn set_size_of_heap_commit(&mut self, value: u64) {
        if self.is_64bit() {
            self.optional_header64_mut().SizeOfHeapCommit = value
        } else {
            self.optional_header32_mut().SizeOfHeapCommit = value as u32
        }
    }
    #[inline(always)]
    pub fn set_loader_flags(&mut self, value: u32) {
        if self.is_64bit() {
            self.optional_header64_mut().LoaderFlags = value
        } else {
            self.optional_header32_mut().LoaderFlags = value
        }
    }
    #[inline(always)]
    pub fn set_number_of_rva_and_sizes(&mut self, value: u32) {
        if self.is_64bit() {
            self.optional_header64_mut().NumberOfRvaAndSizes = value
        } else {
            self.optional_header32_mut().NumberOfRvaAndSizes = value
        }
    }
    #[inline(always)]
    pub fn data_directory_mut(&mut self) -> &'_ mut [IMAGE_DATA_DIRECTORY] {
        if self.is_64bit() {
            &mut self.optional_header64_mut().DataDirectory
        } else {
            &mut self.optional_header32_mut().DataDirectory
        }
    }
}
