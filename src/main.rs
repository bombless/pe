use std::fmt;
use std::ops::Range;
use std::mem::{size_of, transmute};
use std::collections::{HashMap, HashSet};

#[allow(unused)]
struct Pe<'a> {
    bytes: &'a [u8],
    sections: Vec<ImageSectionHeader>,
    imported: HashMap<&'a str, HashSet<Fun<'a>>>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
enum Fun<'a> {
    Name(&'a str),
    Hint(u32),
}

impl<'a> Pe<'a> {
    fn load(bytes: &'a [u8]) -> Self {
        let mut buf_dos_header = [0u8; size_of::<DosHeader>()];

        buf_dos_header.copy_from_slice(&bytes[0 .. size_of::<DosHeader>()]);
    
        let buf_dos_header: &DosHeader = unsafe { transmute(&buf_dos_header) };
    
        let size_dos_header = buf_dos_header.lfanew;
    
        let offset_pe_header = size_dos_header as usize;
        let offset_image_file_header = offset_pe_header + 4;
    
        let offset_image_optional_header = offset_image_file_header + size_of::<ImageFileHeader>();
    
        let ptr_image_file_header: &ImageFileHeader = unsafe { transmute(bytes[offset_image_file_header .. offset_image_optional_header].as_ptr()) };
    
        let machine = ptr_image_file_header.machine;
        println!("machine {machine:04x}");

        let ref_image_optional_header: &dyn ImageOptionalHeaderTrait;
    
        let size_of_optional_header = ptr_image_file_header.size_of_optional_header as usize;
        if size_of_optional_header == size_of::<ImageOptionalHeader>() {
            let ptr_image_optional_header: &ImageOptionalHeader = unsafe { transmute(bytes[offset_image_optional_header .. offset_image_optional_header + size_of_optional_header].as_ptr()) };
            ref_image_optional_header = ptr_image_optional_header;
        }
        else if size_of_optional_header == size_of::<ImageOptionalHeader64>() {
            let ptr_image_optional_header: &ImageOptionalHeader64 = unsafe { transmute(bytes[offset_image_optional_header .. offset_image_optional_header + size_of_optional_header].as_ptr()) };
            ref_image_optional_header = ptr_image_optional_header;
        }
        else {
            panic!("unknown size of optional header");
        }

        let size_of_headers = ref_image_optional_header.size_of_headers();
        println!("size_of_headers 0x{size_of_headers:08x}");

        let import_table_address = ref_image_optional_header.import_table().virtual_address;
        println!("import_table_address 0x{import_table_address:08x}");

        let mut sections = Vec::new();
        let mut imported = HashMap::new();
    
        let mut offset = offset_image_optional_header + size_of_optional_header;
    
        for _ in 0 .. ptr_image_file_header.number_of_sections {
            let mut buf_section_header = [0u8; size_of::<ImageSectionHeader>()];
    
            buf_section_header.copy_from_slice(&bytes[offset..offset+size_of::<ImageSectionHeader>()]);
    
            let buf_section_header: &ImageSectionHeader = unsafe { transmute(&buf_section_header) };
            sections.push(buf_section_header.clone());
            println!("{buf_section_header:?}");
            if buf_section_header.virtual_address == 0 {
                offset += size_of::<ImageSectionHeader>();
                continue;
            }
            let pointer_to_raw_data = buf_section_header.pointer_to_raw_data;
            let virtual_address = buf_section_header.virtual_address;
            let range = buf_section_header.virtual_address_range();
            
            if import_table_address >= range.start && import_table_address < range.end {
                let import_table_size = ref_image_optional_header.import_table().size as usize;
                let base = (import_table_address - virtual_address + pointer_to_raw_data) as usize;
                let import_table = &bytes[base.. base + import_table_size];
                for offset in (0 .. import_table_size).step_by(size_of::<ImageImportDescriptor>()) {
                    let import_descriptor: &ImageImportDescriptor = unsafe { transmute(import_table[offset..].as_ptr()) };
                    println!("{import_descriptor:?}");
                    let name = import_descriptor.name;
                    let dll_name;
                    if name >= range.start && name < range.end {
                        let ptr = (name - virtual_address + pointer_to_raw_data) as usize;
                        let section_size = buf_section_header.size_of_raw_data;
                        let range_end = (pointer_to_raw_data + section_size) as usize;
                        println!("0x{ptr:08x} to 0x:{range_end:08x} section_size 0x{section_size:08x}");
                        dll_name = get_str(&bytes[ptr .. ]);
                    } else {
                        break;
                    }
                    let first_thunk = import_descriptor.first_thunk;
                    if buf_section_header.in_range(first_thunk) {
                        let file_offset = (first_thunk - virtual_address + pointer_to_raw_data) as usize;
                        let mut entries = HashSet::new();
                        for ptr in (file_offset ..).step_by(4) {
                            let ptr: &u32 = unsafe { transmute(bytes[ptr..].as_ptr()) };
                            if *ptr & (1 << 31) > 0 {
                                entries.insert(Fun::Hint(*ptr & !(1 << 31)));
                            }
                            if *ptr > 0 {
                                let offset = (*ptr - virtual_address + pointer_to_raw_data) as usize;
                                if bytes.len() <= offset {
                                    continue;
                                }
                                let entry = read_image_import_by_name(&bytes[offset..]);
                                entries.insert(Fun::Name(entry));
                            } else {
                                break;
                            }
                        }
                        imported.insert(dll_name, entries);
                    }
                }
    
            }
            // println!("raw 0x{:08x}", virtual_address + pointer_to_raw_data - image_base);
            offset += size_of::<ImageSectionHeader>();
        }
        Self {
            sections,
            bytes,
            imported
        }
    }
}


fn get_str<'a>(bytes: &'a [u8]) -> &'a str {
    let mut i = 0;
    while bytes[i] > 0 {
        i += 1;
    }
    unsafe {
        transmute(&bytes[..i])
    }
}

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
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
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
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
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

trait ImageOptionalHeaderTrait {
    fn import_table<'a>(&'a self) -> &'a ImageDataDirectory;
    fn size_of_headers(&self) -> u32;
}

impl ImageOptionalHeaderTrait for ImageOptionalHeader {
    fn import_table<'a>(&'a self) -> &'a ImageDataDirectory {
        &self.import_table
    }
    fn size_of_headers(&self) -> u32 {
        self.size_of_headers
    }
}

impl ImageOptionalHeaderTrait for ImageOptionalHeader64 {
    fn import_table<'a>(&'a self) -> &'a ImageDataDirectory {
        &self.import_table
    }
    fn size_of_headers(&self) -> u32 {
        self.size_of_headers
    }
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
#[derive(Clone)]
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
        println!("map_to = 0x{map_from:08x} + 0x{size_of_raw_data:08x}");
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
#[allow(unused)]
struct ImageImportByName {
    hint: u16,
    name: [u8],
}

fn read_image_import_by_name(ptr: &[u8]) -> &str {
    let ptr: &ImageImportByName = unsafe { transmute(ptr) };
    get_str(&ptr.name)
}

fn main() {
    dump(include_bytes!("../hello.exe"));
    // dump(include_bytes!("../7-zip.dll"));
    // dump(include_bytes!("../unzip.dll"));
}

fn dump(bytes: &[u8]) {
    let pe = Pe::load(bytes);
    for (dll, functions)  in pe.imported {
        println!("{dll:?}");
        for f in functions {
            println!("+ {f:?}");
        }
    }
}
