#![cfg(test)]

extern crate alloc;

use crate::definitions::{GRPICONDIR, GRPICONDIRENTRY};
use crate::ExportType::*;
use crate::PE;
use std::fs;
use std::mem::size_of;
use util::get_system_dir;
use crate::consts::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_FLAG, IMAGE_FILE_MACHINE_I386};

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    fn GetModuleHandleA(module_name: *const u8) -> usize;
    fn GetProcAddress(module_handle: usize, proc_name: *const u8) -> usize;
}

#[test]
fn pe_from_memory_address() {
    unsafe {
        let addr = GetModuleHandleA(std::ptr::null());
        let pe = PE::from_address(addr).unwrap();
        assert_eq!(pe.nt_headers().file_header().Machine, IMAGE_FILE_MACHINE_FLAG);
    }
}
#[test]
fn pe_from_file_32() {
    let path = get_system_dir().expect("Could not get system directory");
    let path = path.as_str();
    let file = fs::read(format!("{path}\\..\\SysWOW64\\notepad.exe")).unwrap();
    let pe = PE::from_slice(file.as_slice()).unwrap();
    assert_eq!(pe.nt_headers().file_header().Machine, IMAGE_FILE_MACHINE_I386)
}
#[test]
fn pe_from_file_64() {
    let path = get_system_dir().expect("Could not get system directory");
    let path = path.as_str();
    #[cfg(any(target_arch = "x86_64"))]
    let file = fs::read(format!("{path}\\notepad.exe")).unwrap();
    #[cfg(any(target_arch = "x86"))]
    let file = fs::read(format!("{path}\\..\\Sysnative\\notepad.exe").as_bytes()).unwrap();
    let pe = PE::from_slice(file.as_slice()).unwrap();
    assert_eq!(pe.nt_headers().file_header().Machine, IMAGE_FILE_MACHINE_AMD64)
}
#[test]
fn get_rva_by_ordinal() {
    unsafe {
        let kernel_32_addr = GetModuleHandleA("kernel32.dll\0".as_ptr());
        let pe = PE::from_address(kernel_32_addr).unwrap();

        let ordinal = pe.get_function_ordinal("LoadLibraryA".as_bytes());

        let load_library_a_address_ordinal_offset = pe.get_export_rva(Ordinal(ordinal)).unwrap();

        let load_library_a_address = GetProcAddress(kernel_32_addr, ordinal as *const u8);
        assert_eq!(
            load_library_a_address_ordinal_offset as usize,
            load_library_a_address - kernel_32_addr
        );
    }
}
#[test]
fn get_rva() {
    unsafe {
        let kernel_32_addr = GetModuleHandleA("kernel32.dll\0".as_ptr());
        let load_library_a_address_offset = PE::from_address(kernel_32_addr)
            .unwrap()
            .get_export_rva(Name("LoadLibraryA"))
            .unwrap();

        let load_library_a_address = GetProcAddress(kernel_32_addr, "LoadLibraryA\0".as_ptr());
        assert_eq!(
            load_library_a_address_offset as usize,
            load_library_a_address - kernel_32_addr
        );
    }
}
#[test]
fn rva_to_foa() {
    unsafe {
        let path = get_system_dir().expect("UFT-8 error from get_system_dir helper function.");
        let file = fs::read(format!("{path}/kernel32.dll")).unwrap();
        let pe = PE::from_slice(&file[..]).unwrap();
        let load_library_a_address_offset = pe.get_export_rva(Name("LoadLibraryA")).unwrap();

        let rva = pe.rva_to_foa(load_library_a_address_offset).unwrap();

        assert_ne!(rva, 0);
    }
}
#[test]
fn unmapped_pe_resource() {
    unsafe {
        let path = get_system_dir().expect("UFT-8 error from get_system_dir helper function.");
        let file = fs::read(format!("{path}/notepad.exe")).unwrap();
        let pe = PE::from_slice(&file[..]).unwrap();
        let group_resource = pe
            .get_pe_resource(14, 2)
            .expect("Could not find RT_GROUP_ICON");
        let group_header = group_resource.as_ptr() as *const GRPICONDIR;
        let count = (*group_header).idCount as usize;
        let resources_ptr = &(*group_header).iconDirEntry;
        let icon_dir_entries =
            std::slice::from_raw_parts(resources_ptr as *const GRPICONDIRENTRY, count);
        let mut icon_id = u32::MAX;
        for entry in icon_dir_entries {
            if entry.bWidth == 0 && entry.bHeight == 0 {
                icon_id = entry.nId as u32;
                break;
            }
        }

        let png = pe
            .get_pe_resource(3, icon_id)
            .expect("Could not find RT_ICON");

        assert_eq!(png[..8], [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    }
}
#[test]
fn get_rva_by_ordinal_on_disk() {
    unsafe {
        let kernel_32_addr = GetModuleHandleA("kernel32.dll\0".as_ptr());
        let pe = PE::from_address(kernel_32_addr).unwrap();

        let ordinal = pe.get_function_ordinal("LoadLibraryA".as_bytes());

        let load_library_a_address_ordinal_offset = pe.get_export_rva(Ordinal(ordinal)).unwrap();

        let load_library_a_address = GetProcAddress(kernel_32_addr, ordinal as *const u8);

        assert_eq!(
            load_library_a_address_ordinal_offset as usize,
            load_library_a_address - kernel_32_addr
        );
    }
}
#[test]
fn get_rva_on_disk() {
    unsafe {
        let path = get_system_dir().expect("UTF8 error on get_system_dir");
        let path = path.as_str();
        let kernel32_file = fs::read(format!("{path}/kernel32.dll")).unwrap();
        let load_library_a_address_offset = PE::from_slice(kernel32_file.as_slice())
            .unwrap()
            .get_export_rva(Name("LoadLibraryA"))
            .unwrap();

        let kernel_32_addr = GetModuleHandleA("kernel32.dll\0".as_ptr());
        let load_library_a_address = GetProcAddress(kernel_32_addr, "LoadLibraryA\0".as_ptr());

        assert_eq!(
            load_library_a_address_offset as usize,
            load_library_a_address - kernel_32_addr
        );
    }
}
#[test]
fn get_exports() {
    unsafe {
        let path = get_system_dir().expect("UTF8 error on get_system_dir");
        let path = path.as_str();
        let kernel32_file = fs::read(format!("{path}/kernel32.dll")).unwrap();
        let kernel32_dll = PE::from_slice(kernel32_file.as_slice()).unwrap();

        let exports = kernel32_dll.get_exports().expect("Could not get exports");
        println!("{:?}", exports);

        assert_ne!(exports.len(), 0)
    }
}

// This test should not compile.
//     |
// 184 |                 pe = PE::from_slice(file.as_slice()).unwrap();
//     |                                     ^^^^^^^^^^^^^^^ borrowed value does not live long enough
// 185 |             }
//     |             - `file` dropped here while still borrowed
// 186 |             assert_ne!(pe.nt_headers().file_header().Machine, 0x8664)
//     |                        --------------- borrow later used here
// #[test]
// fn pe_from_file_lifetime_fail() {
//     unsafe {
//         let mut buffer = [0; MAX_PATH + 1];
//         GetSystemDirectoryA(buffer.as_mut_ptr(), buffer.len() as u32);
//         let pe;
//         let path = String::from_utf8(buffer[..strlen(buffer.as_ptr())].to_vec()).unwrap();
//         {
//             let file = fs::read(format!("{path}\\notepad.exe").as_bytes()).unwrap();
//             pe = PE::from_slice(file.as_slice()).unwrap();
//         }
//         assert_ne!(pe.nt_headers().file_header().Machine, 0x8664)
//     }
// }

mod util {
    use std::string::FromUtf8Error;

    #[link(name = "kernel32", kind = "raw-dylib")]
    extern "system" {
        fn GetSystemDirectoryA(buffer: *mut u8, buffer_len: u32) -> u32;
    }

    pub fn get_system_dir() -> Result<String, FromUtf8Error> {
        unsafe {
            let mut buffer = Vec::new();
            buffer.resize(crate::consts::MAX_PATH + 1, 0);
            let len = GetSystemDirectoryA(buffer.as_mut_ptr(), buffer.len() as u32);
            buffer.set_len(len as usize);
            String::from_utf8(buffer)
        }
    }
}
