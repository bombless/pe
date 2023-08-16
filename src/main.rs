use std::fmt;

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
struct ImageOptionalHeader {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,
    image_base: u32,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,

    export_table: ImageDataDirectory,
    import_table: ImageDataDirectory,
    resource_table: ImageDataDirectory,
    exception_table: ImageDataDirectory,
    certificate_table: ImageDataDirectory,
    base_relocation_table: ImageDataDirectory,
    debug: ImageDataDirectory,
    architecture: ImageDataDirectory,
    global_ptr: ImageDataDirectory,
    tls_table: ImageDataDirectory,
    load_config_table: ImageDataDirectory,
    bound_import: ImageDataDirectory,
    iat: ImageDataDirectory,
    delay_import_descriptor: ImageDataDirectory,
    clr_runtime_header: ImageDataDirectory,
    reserved: ImageDataDirectory,
}

#[repr(packed)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

impl fmt::Debug for ImageDataDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let virtual_address = self.virtual_address;
        let size = self.size;
        write!(f, "ImageDataDirectory {{ virtual_address: 0x{virtual_address:08x}, size: 0x{size:08x} }}")
    }
}


#[repr(packed)]
struct ImageSectionHeader {
    name: [u8; 8],
    address: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

impl fmt::Debug for ImageSectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let address = self.address;
        let virtual_address = self.virtual_address;
        let size_of_raw_data = self.size_of_raw_data;
        let pointer_to_raw_data = self.pointer_to_raw_data;
        
        let name = self.name;
        let mut buf_name = String::new();
        for i in 0 .. 8 {
            if name[i] == 0 {
                break;
            }
            buf_name.push(name[i] as char);
        }
        write!(f, "ImageSectionHeader {{")?;
        write!(f, " name: {buf_name}, address: 0x{address:08x}, virtual_address: 0x{virtual_address:08x}, size_of_raw_data: 0x{size_of_raw_data:08x}, pointer_to_raw_data: 0x{pointer_to_raw_data:08x}")?;
        write!(f, " }}")
    }
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

    let offset_image_optional_header = offset_image_file_header + size_of::<ImageFileHeader>();

    buf_image_file_header.copy_from_slice(&bytes[offset_image_file_header .. offset_image_optional_header]);

    let buf_image_file_header: &ImageFileHeader = unsafe { transmute(&buf_image_file_header) };

    println!("{buf_image_file_header:?}");
    let machine = buf_image_file_header.machine;
    println!("machine {machine:04x}");

    let size_of_optional_header = buf_image_file_header.size_of_optional_header;
    println!("size_of_optional_header {size_of_optional_header:04x}, expect {:04x}", size_of::<ImageOptionalHeader>());

    let mut buf_image_optional_header = [0u8; size_of::<ImageOptionalHeader>()];
    buf_image_optional_header.copy_from_slice(&bytes[offset_image_optional_header .. offset_image_optional_header + size_of::<ImageOptionalHeader>()]);

    let buf_image_optional_header: &ImageOptionalHeader = unsafe { transmute(&buf_image_optional_header) };

    println!("export_table {:?}", buf_image_optional_header.export_table);
    println!("import_table {:?}", buf_image_optional_header.import_table);

    let mut offset = offset_image_optional_header + size_of::<ImageOptionalHeader>();

    for _ in 0 .. buf_image_file_header.number_of_sections {
        let mut buf_section_header = [0u8; size_of::<ImageSectionHeader>()];

        buf_section_header.copy_from_slice(&bytes[offset..offset+size_of::<ImageSectionHeader>()]);

        let buf_section_header: &ImageSectionHeader = unsafe { transmute(&buf_section_header) };
        println!("{buf_section_header:?}");
        offset += size_of::<ImageSectionHeader>();
    }


}
