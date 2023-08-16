use std::fmt;
use std::ops::Range;
use std::mem::{size_of, transmute};

#[repr(packed)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

impl ImageSectionHeader {
    fn virtual_address_range(&self) -> Range<u32> {
        self.virtual_address .. self.virtual_address + self.size_of_raw_data
    }
    fn in_range(&self, val: u32) -> bool {
        val >= self.virtual_address && val < self.virtual_address + self.size_of_raw_data
    }
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
        write!(f, "ImageSectionHeader")?;
        let from = pointer_to_raw_data;
        let to = from + size_of_raw_data;
        let map_from = virtual_address;
        let map_to = map_from + size_of_raw_data;
        write!(f, "(0x{from:08x}..0x{to:08x} => 0x{map_from:08x}..{map_to:08x})")?;
        write!(f, " {{ ")?;
        write!(f, "name: {buf_name:?}")?;
        write!(f, ", address: 0x{address:08x}, virtual_address: 0x{virtual_address:08x}, size_of_raw_data: 0x{size_of_raw_data:08x}, pointer_to_raw_data: 0x{pointer_to_raw_data:08x}")?;
        write!(f, " }}")
    }
}

#[repr(packed)]
struct ImageImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name: u32,
    first_thunk: u32,
}

impl fmt::Debug for ImageImportDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let original_first_thunk = self.original_first_thunk;
        let time_date_stamp = self.time_date_stamp;
        let forwarder_chain = self.forwarder_chain;
        let name = self.name;
        let first_thunk = self.first_thunk;
        write!(f, "ImageImportDescriptor")?;
        write!(f, " {{ ")?;
        write!(f, "original_first_thunk: 0x{original_first_thunk:08x}, time_date_stamp: 0x{time_date_stamp:08x}, forwarder_chain: 0x{forwarder_chain:08x}, name: 0x{name:08x}, first_thunk: 0x{first_thunk:08x}")?;
        write!(f, " }}")
    }
}

#[repr(packed)]
struct ImageImportByName {
    hint: u16,
    name: [u8],
}

fn show_image_import_by_name(ptr: &[u8]) {
    let ptr: &ImageImportByName = unsafe { transmute(ptr) };
    let mut buf_name = String::new();
    let name = &ptr.name;
    // print!("name [");
    // for i in 0 .. 32 {
    //     if i > 0 {
    //         print!(", ");
    //     }
    //     print!("0x{:02x}", name[i]);
    // }
    // println!("]");
    for &c in name {
        if c > 0 {
            buf_name.push(c as char);
        } else {
            break;
        }
    }
    if buf_name.is_empty() {
        let hint = ptr.hint;
        println!("hint 0x{hint:04x} ({}, {})", hint % 256, hint / 256);
    } else {
        println!("+ {buf_name:?}");
    }
}

fn main() {
    dump(include_bytes!("../7-zip.dll"));
    dump(include_bytes!("../unzip.dll"));
}

fn dump(bytes: &[u8]) {
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

    let machine = buf_image_file_header.machine;
    println!("machine {machine:04x}");

    let size_of_optional_header = buf_image_file_header.size_of_optional_header;
    println!("size_of_optional_header {size_of_optional_header:04x}, expect {:04x}", size_of::<ImageOptionalHeader>());

    let mut buf_image_optional_header = [0u8; size_of::<ImageOptionalHeader>()];
    buf_image_optional_header.copy_from_slice(&bytes[offset_image_optional_header .. offset_image_optional_header + size_of::<ImageOptionalHeader>()]);

    let buf_image_optional_header: &ImageOptionalHeader = unsafe { transmute(&buf_image_optional_header) };

    println!("export_table {:?}", buf_image_optional_header.export_table);
    println!("import_table {:?}", buf_image_optional_header.import_table);
    let image_base = buf_image_optional_header.image_base;
    println!("image_base 0x{image_base:08x}");

    let mut offset = offset_image_optional_header + size_of::<ImageOptionalHeader>();

    for _ in 0 .. buf_image_file_header.number_of_sections {
        let mut buf_section_header = [0u8; size_of::<ImageSectionHeader>()];

        buf_section_header.copy_from_slice(&bytes[offset..offset+size_of::<ImageSectionHeader>()]);

        let buf_section_header: &ImageSectionHeader = unsafe { transmute(&buf_section_header) };
        println!("{buf_section_header:?}");
        let pointer_to_raw_data = buf_section_header.pointer_to_raw_data;
        let virtual_address = buf_section_header.virtual_address;
        let range = buf_section_header.virtual_address_range();
        let import_table_address = buf_image_optional_header.import_table.virtual_address;
        if import_table_address >= range.start && import_table_address < range.end {
            let import_table_size = buf_image_optional_header.import_table.size as usize;
            println!("import table found (size 0x{import_table_size:08x})");
            println!("struct size 0x{:08x} remaining 0x{:08x}", size_of::<ImageImportDescriptor>(), import_table_size % size_of::<ImageImportDescriptor>());
            let base = (import_table_address - virtual_address + pointer_to_raw_data) as usize;
            println!("base 0x{base:08x}");
            let import_table = &bytes[base.. base + import_table_size];
            for offset in (0 .. import_table_size).step_by(size_of::<ImageImportDescriptor>()) {
                let import_descriptor: &ImageImportDescriptor = unsafe { transmute(import_table[offset..].as_ptr()) };
                println!("{import_descriptor:?}");
                let name = import_descriptor.name;
                // println!("name 0x{:08x}", name);
                if name >= range.start && name < range.end {
                    let ptr = (name - virtual_address + pointer_to_raw_data) as usize;
                    let section_size = buf_section_header.size_of_raw_data;
                    let range_end = (name - virtual_address + pointer_to_raw_data + section_size) as usize;
                    let mut buf_name = String::new();
                    for offset in ptr .. range_end{
                        let c = bytes[offset];
                        if c > 0 {
                            buf_name.push(c as char);
                        } else {
                            break;
                        }
                    }
                    println!("dll name {buf_name:?}");
                } else {
                    break;
                }
                // let original_first_thunk = import_descriptor.original_first_thunk;
                // if buf_section_header.in_range(original_first_thunk) {
                //     let file_offset = (original_first_thunk - virtual_address + pointer_to_raw_data) as usize;
                //     println!("Try original_first_thunk 0x{original_first_thunk:08x} offset 0x{file_offset:08x}");
                //     // show_image_import_by_name(&bytes[file_offset..]);
                //     for ptr in (file_offset ..).step_by(4) {
                //         let ptr: &u32 = unsafe { transmute(bytes[ptr..].as_ptr()) };
                //         if *ptr > 0 {
                //             show_image_import_by_name(&bytes[(*ptr - virtual_address + pointer_to_raw_data) as usize..]);
                //         } else {
                //             break;
                //         }
                //     }
                // } else {
                //     println!("original_first_thunk 0x{original_first_thunk:08x} missing");
                // }
                let first_thunk = import_descriptor.first_thunk;
                if buf_section_header.in_range(first_thunk) {
                    let file_offset = (first_thunk - virtual_address + pointer_to_raw_data) as usize;
                    // println!("Try first_thunk 0x{first_thunk:08x} offset 0x{file_offset:08x}");
                    // show_image_import_by_name(&bytes[file_offset..]);
                    for ptr in (file_offset ..).step_by(4) {
                        let ptr: &u32 = unsafe { transmute(bytes[ptr..].as_ptr()) };
                        if *ptr > 0 {
                            // println!("ptr 0x{:08x}", *ptr);
                            let offset = (*ptr - virtual_address + pointer_to_raw_data) as usize;
                            if bytes.len() <= offset {
                                println!("offset 0x{offset:08x}");
                                println!("offset in the wild");
                                continue;
                            }
                            show_image_import_by_name(&bytes[offset..]);
                        } else {
                            break;
                        }
                    }
                } else {
                    println!("first_thunk 0x{first_thunk:08x} missing");
                }
            }

        }
        // println!("raw 0x{:08x}", virtual_address + pointer_to_raw_data - image_base);
        offset += size_of::<ImageSectionHeader>();
    }


}
