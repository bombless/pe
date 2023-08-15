#[repr(packed)]
struct DosHeader {
    magic: u16,
    cblp: u16,
    cp: u16,
    crlc: u16,
    cparhdr: u16,
    minalloc: u16,
    maxalloc: u16,
    ss: u16,
    sp: u16,
    csum: u16,
    ip: u16,
    cs: u16,
    lfarlc: u16,
    ovno: u16,
    res: [u16; 4],
    oemid: u16,
    oeminfo: u16,
    res2: [u16; 10],
    lfanew: u32,
}

#[repr(packed)]
#[derive(Debug)]
struct ImageFileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[repr(packed)]
#[derive(Debug)]
struct ImageOptionalHeader {
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    size_of_image: u32,
    size_of_headers: u32,
}

#[repr(packed)]
#[derive(Debug)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

use std::mem::{size_of, transmute};

fn main() {
    let bytes = include_bytes!("../pe.exe");
    let mut buf_dos_header = [0u8; size_of::<DosHeader>()];

    buf_dos_header.copy_from_slice(&bytes[0 .. size_of::<DosHeader>()]);

    let buf_dos_header: &DosHeader = unsafe { transmute(&buf_dos_header) };

    let size_dos_header = buf_dos_header.lfanew;
    
    let mut buf_image_file_header = [0u8; size_of::<ImageFileHeader>()];

    let offset_pe_header = size_dos_header as usize;
    let offset_image_file_header = offset_pe_header + 4;

    buf_image_file_header.copy_from_slice(&bytes[offset_image_file_header .. offset_image_file_header + size_of::<ImageFileHeader>()]);

    let buf_image_file_header: &ImageFileHeader = unsafe { transmute(&buf_image_file_header) };

    println!("{buf_image_file_header:?}");
    let machine = buf_image_file_header.machine;
    println!("machine {machine:04x}");
    let size_of_optional_header = buf_image_file_header.size_of_optional_header;
    println!("size_of_optional_header {size_of_optional_header:04x}, expect {:04x}", size_of::<ImageOptionalHeader>());

    println!("nt header {:x}", size_of::<ImageFileHeader>() + size_of::<ImageOptionalHeader>() + 4);


}
