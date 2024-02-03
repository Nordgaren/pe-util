# pe-util
A pointer sized type that allows the user to read a buffer in memory as a Windows PE. Currently only supports 32-bit
and 64-bit PEs on x86 architectures, but, I plan on supporting more architectures in the future.

## Usage
Construct the type with a slice, *const u8 or usize with the value of the memory address where the PE file lies in 
memory. You can get data about the PE regardless of it's state as a mapped PE, ready to be executed, or as a file on disk.
Pe-util is also neutral to wether or not the file is a 32-bit or 64-bit executable.

## Example
```rust
use pe_util::PE;
fn example(slice: &[u8]) {
    let pe = PE::from_slice(slice).expect("Could not validate that slice is a valid PE file.");
    let exports = pe.get_exports();

    for export in exports {
        let ord = pe.get_function_ordinal(export.as_bytes());
        println!("Export: {export} Ordinal: {ord}");
    }

    let res = pe.get_pe_resource(10, 100).expect("Could not find PE resource");
    
    println!("{}", res.len());
}
```