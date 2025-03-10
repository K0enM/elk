use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};
use std::error::Error;
use std::io::Write;
use std::process::{Command, Stdio};
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

    // println!("Disassembling {:?}", input_path);
    // let code_ph = file
    //     .program_headers
    //     .iter()
    //     .find(|ph| ph.mem_range().contains(&file.entry_point))
    //     .expect("segment with entry point not found.");

    // ndisasm(&code_ph.data[..], file.entry_point)?;

    let base = 0x400000_usize;

    println!("Mapping {:?} in memory...", input_path);

    let mut mappings = Vec::new();

    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
        .filter(|ph| ph.mem_range().end > ph.mem_range().start)
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);

        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();
        let start: usize = mem_range.start.0 as usize + base;
        let aligned_start: usize = align_lo(start);

        let padding = start - aligned_start;
        let len = len + padding;

        let addr: *mut u8 = aligned_start as _;

        println!("Addr: {:p}, Padding: {:08x}", addr, padding);

        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;

        println!("Copying segment data...");
        {
            let dst = unsafe { std::slice::from_raw_parts_mut(addr.add(padding), ph.data.len()) };

            dst.copy_from_slice(&ph.data[..]);
        }

        println!("Adjusting permissions...");
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
    pause("jmp")?;

    unsafe {
        jmp((file.entry_point.0 as usize + base) as _);
    }
    Ok(())
}

fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o")
        .arg(format!("{}", origin.0))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(code)?;
    let output = child.wait_with_output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

unsafe fn jmp(addr: *const u8) {
    let fn_ptr: fn() = std::mem::transmute(addr);
    fn_ptr();
}

fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
    println!("Press Enter to {}...", reason);
    {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
    }
    Ok(())
}

fn align_lo(x: usize) -> usize {
    x & !0xFFF
}
