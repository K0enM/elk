use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};
use std::error::Error;
use std::mem::transmute;
use std::ptr::copy_nonoverlapping;
use std::{env, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = env::args().nth(1).expect("usage: elk FILE");
    let input = fs::read(&input_path)?;

    println!("Analyzing {:?}...", input_path);

    let file = match delf::File::parse_or_print_error(&input[..]) {
        Some(f) => f,
        None => std::process::exit(1),
    };
    println!("{:#?}", file);

    let rela_entries = file.read_rela_entries().unwrap_or_else(|e| {
        println!("Could not read relocations: {:?}", e);
        Default::default()
    });
    println!("Found {} rela entries", rela_entries.len());
    for entry in rela_entries.iter() {
        println!("{:?}", entry);
    }

    if let Some(dynseg) = file.segment_of_type(delf::SegmentType::Dynamic) {
        if let delf::SegmentContents::Dynamic(ref dyntab) = dynseg.contents {
            println!("Dynamic table entries:");
            for e in dyntab {
                println!("{:?}", e);
                match e.tag {
                    delf::DynamicTag::Needed | delf::DynamicTag::RPath => {
                        println!(" => {:?}", file.get_string(e.addr)?)
                    }
                    _ => {}
                }
            }
        }
    }

    let syms = file.read_syms().unwrap();
    println!(
        "Symbol table @ {:?} contains {} entries",
        file.dynamic_entry(delf::DynamicTag::SymTab).unwrap(),
        syms.len()
    );

    println!(
        "  {:6}{:12}{:10}{:16}{:16}{:12}{:12}",
        "Num", "Value", "Size", "Type", "Bind", "Ndx", "Name"
    );
    for (num, s) in syms.iter().enumerate() {
        println!(
            "  {:6}{:12}{:10}{:16}{:16}{:12}{:12}",
            format!("{}", num),
            format!("{:?}", s.value),
            format!("{:?}", s.size),
            format!("{:?}", s.r#type),
            format!("{:?}", s.bind),
            format!("{:?}", s.shndx),
            format!("{}", file.get_string(s.name).unwrap_or_default()),
        );
    }

    let msg = syms
        .iter()
        .find(|sym| file.get_string(sym.name).unwrap_or_default() == "msg")
        .expect("should find msg in symbol table");
    let msg_slice = file.slice_at(msg.value).expect("should find msg in memory");
    let msg_slice = &msg_slice[..msg.size as usize];
    println!("msg contents: {:?}", String::from_utf8_lossy(msg_slice));

    let base = 0x400000_usize;

    println!("Loading with base address @ 0x{:x}", base);

    let non_empty_load_segments = file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
        .filter(|ph| ph.mem_range().end > ph.mem_range().start);

    let mut mappings = Vec::new();
    for ph in non_empty_load_segments {
        println!("Mapping {:?} - {:?}", ph.mem_range(), ph.flags);
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start: usize = mem_range.start.0 as usize + base;
        let aligned_start: usize = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding;

        let addr: *mut u8 = unsafe { std::mem::transmute(aligned_start) };

        if padding > 0 {
            println!("(With 0x{:x} bytes of padding at the start)", padding);
        }

        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        unsafe {
            copy_nonoverlapping(ph.data.as_ptr(), addr.add(padding), len);
        }

        let mut num_relocs = 0;
        for reloc in &rela_entries {
            if mem_range.contains(&reloc.offset) {
                unsafe {
                    let real_segment_start = addr.add(padding);
                    let offset_into_segment = reloc.offset - mem_range.start;
                    let reloc_addr = real_segment_start.add(offset_into_segment.into());
                    match reloc.r#type {
                        delf::RelType::Known(t) => {
                            match t {
                                delf::KnownRelType::Relative => {
                                    let reloc_addr: *mut u64 = transmute(reloc_addr);
                                    let reloc_value = reloc.addend + delf::Addr(base as u64);
                                    std::ptr::write_unaligned(reloc_addr, reloc_value.0);
                                }
                                t => {
                                    panic!("Unsupported relocation type {:?}", t);
                                }
                            }
                            num_relocs += 1;
                        }
                        delf::RelType::Unknown(_) => {}
                    }
                }
            }
        }

        if num_relocs > 0 {
            println!("(Applied {} relocations)", num_relocs);
        }

        let mut protection = Protection::NONE;
        for flag in ph.flags.iter() {
            protection |= match flag {
                delf::SegmentFlag::Execute => Protection::READ,
                delf::SegmentFlag::Write => Protection::WRITE,
                delf::SegmentFlag::Read => Protection::EXECUTE,
            }
        }
        unsafe {
            protect(addr, len, protection)?;
        }
        mappings.push(map);
    }

    println!("Jumping to entry point @ {:?}...", file.entry_point);

    unsafe {
        jmp((file.entry_point.0 as usize + base) as _);
    }
    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

fn align_lo(x: usize) -> usize {
    x & !0xFFF
}
