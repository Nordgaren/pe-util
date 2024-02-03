use std::mem;
use std::mem::size_of;
use crate::PE;
use crate::definitions::{IMAGE_DATA_DIRECTORY, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64};
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