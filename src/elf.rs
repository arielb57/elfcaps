//! A zero-dependency ELF reader for the parts of an object that matter to a
//! dynamic-linking audit: headers, the dynamic section, `.dynsym`, GNU symbol
//! versioning and read-only string data.
//!
//! Every read goes through [`Reader`], which bounds-checks with checked
//! arithmetic, so malformed input yields an [`ElfError`] instead of a panic.
//! Table sizes are validated against the file length before anything is
//! allocated, which keeps hostile header counts from exhausting memory.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;

pub const SHT_PROGBITS: u32 = 1;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

pub const SHF_WRITE: u64 = 1;
pub const SHF_ALLOC: u64 = 2;
pub const SHF_EXECINSTR: u64 = 4;

pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_RUNPATH: u64 = 29;

const SHN_UNDEF: u16 = 0;
const SHN_XINDEX: u16 = 0xffff;
const PN_XNUM: u16 = 0xffff;
const VERSYM_HIDDEN: u16 = 0x8000;
const VERSYM_INDEX: u16 = 0x7fff;

/// Shortest run of printable bytes kept from read-only data.
const MIN_STRING_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    /// The input does not start with the ELF magic bytes.
    NotElf,
    UnsupportedClass(u8),
    UnsupportedEncoding(u8),
    /// A structure extends past the end of the file (or its offset overflows).
    Truncated {
        what: &'static str,
        offset: u64,
        len: u64,
    },
    /// A header declares an entry size smaller than the structure it describes.
    BadEntrySize {
        what: &'static str,
        size: u64,
    },
    /// A section index (sh_link, e_shstrndx) points at a section that does not exist.
    BadSectionIndex {
        what: &'static str,
        index: u64,
    },
    /// A string-table offset has no terminating NUL inside its table.
    UnterminatedString {
        what: &'static str,
        offset: u64,
    },
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::NotElf => write!(f, "not an ELF file"),
            ElfError::UnsupportedClass(c) => write!(f, "unsupported ELF class {c}"),
            ElfError::UnsupportedEncoding(e) => write!(f, "unsupported ELF data encoding {e}"),
            ElfError::Truncated { what, offset, len } => {
                write!(
                    f,
                    "{what} at offset {offset:#x} (+{len:#x}) is out of bounds"
                )
            }
            ElfError::BadEntrySize { what, size } => {
                write!(f, "{what} has invalid entry size {size}")
            }
            ElfError::BadSectionIndex { what, index } => {
                write!(f, "{what} refers to missing section {index}")
            }
            ElfError::UnterminatedString { what, offset } => {
                write!(
                    f,
                    "{what} string at offset {offset:#x} is not NUL-terminated"
                )
            }
        }
    }
}

impl std::error::Error for ElfError {}

pub type Result<T> = std::result::Result<T, ElfError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    Local,
    Global,
    Weak,
    GnuUnique,
    Other(u8),
}

impl Binding {
    fn from_raw(v: u8) -> Binding {
        match v {
            0 => Binding::Local,
            1 => Binding::Global,
            2 => Binding::Weak,
            10 => Binding::GnuUnique,
            other => Binding::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    NoType,
    Object,
    Func,
    Section,
    File,
    Common,
    Tls,
    GnuIfunc,
    Other(u8),
}

impl SymbolType {
    fn from_raw(v: u8) -> SymbolType {
        match v {
            0 => SymbolType::NoType,
            1 => SymbolType::Object,
            2 => SymbolType::Func,
            3 => SymbolType::Section,
            4 => SymbolType::File,
            5 => SymbolType::Common,
            6 => SymbolType::Tls,
            10 => SymbolType::GnuIfunc,
            other => SymbolType::Other(other),
        }
    }
}

/// A GNU symbol version attached to a `.dynsym` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolVersion {
    pub name: String,
    /// For imports (`.gnu.version_r`), the library expected to provide the version.
    /// `None` for versions this object defines (`.gnu.version_d`).
    pub file: Option<String>,
    /// Set when the versym entry has the hidden bit (`sym@VER` rather than `sym@@VER`).
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub binding: Binding,
    pub kind: SymbolType,
    pub section_index: u16,
    pub value: u64,
    pub size: u64,
    pub version: Option<SymbolVersion>,
}

impl Symbol {
    /// True for symbols this object expects some other object to provide.
    pub fn is_undefined(&self) -> bool {
        self.section_index == SHN_UNDEF
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub kind: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub entsize: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfFile {
    pub class: Class,
    pub endian: Endian,
    pub file_type: u16,
    pub machine: u16,
    pub interpreter: Option<String>,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    /// `.dynsym` entries, without the reserved null symbol at index 0.
    pub symbols: Vec<Symbol>,
    /// NUL-terminated printable strings from read-only, non-executable data
    /// sections, sorted and de-duplicated.
    pub rodata_strings: Vec<String>,
}

impl ElfFile {
    /// Parse an ELF32 or ELF64 image of either byte order.
    pub fn parse(data: &[u8]) -> Result<ElfFile> {
        parse(data)
    }

    /// Executables are what ld.so starts from: `ET_EXEC`, or a PIE (`ET_DYN`
    /// that requests an interpreter).
    pub fn is_executable(&self) -> bool {
        self.file_type == ET_EXEC
            || (self.file_type == ET_DYN && self.segments.iter().any(|s| s.kind == PT_INTERP))
    }

    pub fn imports(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.is_undefined() && !s.name.is_empty())
    }

    pub fn class_name(&self) -> &'static str {
        match (self.class, self.endian) {
            (Class::Elf32, Endian::Little) => "ELF32-LE",
            (Class::Elf32, Endian::Big) => "ELF32-BE",
            (Class::Elf64, Endian::Little) => "ELF64-LE",
            (Class::Elf64, Endian::Big) => "ELF64-BE",
        }
    }
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    data: &'a [u8],
    endian: Endian,
    class: Class,
}

fn add(a: u64, b: u64, what: &'static str) -> Result<u64> {
    a.checked_add(b).ok_or(ElfError::Truncated {
        what,
        offset: a,
        len: b,
    })
}

fn mul(a: u64, b: u64, what: &'static str) -> Result<u64> {
    a.checked_mul(b).ok_or(ElfError::Truncated {
        what,
        offset: a,
        len: b,
    })
}

impl<'a> Reader<'a> {
    fn with_data(self, data: &'a [u8]) -> Reader<'a> {
        Reader { data, ..self }
    }

    fn word_size(&self) -> u64 {
        match self.class {
            Class::Elf32 => 4,
            Class::Elf64 => 8,
        }
    }

    fn bytes(&self, offset: u64, len: u64, what: &'static str) -> Result<&'a [u8]> {
        let err = ElfError::Truncated { what, offset, len };
        let start = usize::try_from(offset).map_err(|_| err.clone())?;
        let count = usize::try_from(len).map_err(|_| err.clone())?;
        let end = start.checked_add(count).ok_or_else(|| err.clone())?;
        self.data.get(start..end).ok_or(err)
    }

    fn array<const N: usize>(&self, offset: u64, what: &'static str) -> Result<[u8; N]> {
        let slice = self.bytes(offset, N as u64, what)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn u8(&self, offset: u64, what: &'static str) -> Result<u8> {
        Ok(self.array::<1>(offset, what)?[0])
    }

    fn u16(&self, offset: u64, what: &'static str) -> Result<u16> {
        let b = self.array(offset, what)?;
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(b),
            Endian::Big => u16::from_be_bytes(b),
        })
    }

    fn u32(&self, offset: u64, what: &'static str) -> Result<u32> {
        let b = self.array(offset, what)?;
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        })
    }

    fn u64(&self, offset: u64, what: &'static str) -> Result<u64> {
        let b = self.array(offset, what)?;
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        })
    }

    /// An address-sized field: 4 bytes in ELF32, 8 in ELF64.
    fn word(&self, offset: u64, what: &'static str) -> Result<u64> {
        match self.class {
            Class::Elf32 => self.u32(offset, what).map(u64::from),
            Class::Elf64 => self.u64(offset, what),
        }
    }
}

fn cstr(table: &[u8], offset: u32, what: &'static str) -> Result<String> {
    let err = ElfError::UnterminatedString {
        what,
        offset: u64::from(offset),
    };
    let start = usize::try_from(offset).map_err(|_| err.clone())?;
    let tail = table.get(start..).ok_or_else(|| err.clone())?;
    let end = tail.iter().position(|&b| b == 0).ok_or(err)?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn parse(data: &[u8]) -> Result<ElfFile> {
    if data.len() < 4 || &data[..4] != b"\x7fELF" {
        return Err(ElfError::NotElf);
    }
    let ident = data.get(..16).ok_or(ElfError::Truncated {
        what: "e_ident",
        offset: 0,
        len: 16,
    })?;
    let class = match ident[4] {
        1 => Class::Elf32,
        2 => Class::Elf64,
        other => return Err(ElfError::UnsupportedClass(other)),
    };
    let endian = match ident[5] {
        1 => Endian::Little,
        2 => Endian::Big,
        other => return Err(ElfError::UnsupportedEncoding(other)),
    };
    let r = Reader {
        data,
        endian,
        class,
    };
    let w = r.word_size();
    let header_size = 16 + 36 + 3 * (w - 4);
    r.bytes(0, header_size, "ELF header")?;

    let file_type = r.u16(16, "e_type")?;
    let machine = r.u16(18, "e_machine")?;
    let phoff = r.word(24 + w, "e_phoff")?;
    let shoff = r.word(24 + 2 * w, "e_shoff")?;
    let phentsize = u64::from(r.u16(30 + 3 * w, "e_phentsize")?);
    let phnum_raw = r.u16(32 + 3 * w, "e_phnum")?;
    let shentsize = u64::from(r.u16(34 + 3 * w, "e_shentsize")?);
    let shnum_raw = r.u16(36 + 3 * w, "e_shnum")?;
    let shstrndx_raw = r.u16(38 + 3 * w, "e_shstrndx")?;

    let section_header_size = 16 + 6 * w;
    let mut raw_sections = Vec::new();
    let mut section_zero: Option<Section> = None;
    if shoff != 0 {
        if shentsize < section_header_size {
            return Err(ElfError::BadEntrySize {
                what: "section header",
                size: shentsize,
            });
        }
        let (_, zero) = read_section_header(&r, shoff)?;
        // With more than 0xff00 sections the real count lives in section 0.
        let count = if shnum_raw == 0 {
            zero.size
        } else {
            u64::from(shnum_raw)
        };
        let table_len = mul(count, shentsize, "section header table")?;
        r.bytes(shoff, table_len, "section header table")?;
        for i in 0..count {
            let off = add(shoff, i * shentsize, "section header")?;
            raw_sections.push(read_section_header(&r, off)?);
        }
        section_zero = Some(zero);
    }

    let phnum = if phnum_raw == PN_XNUM {
        section_zero.as_ref().map_or(0, |s| u64::from(s.info))
    } else {
        u64::from(phnum_raw)
    };
    let program_header_size = if class == Class::Elf32 { 32 } else { 56 };
    let mut segments = Vec::new();
    if phnum != 0 && phoff != 0 {
        if phentsize < program_header_size {
            return Err(ElfError::BadEntrySize {
                what: "program header",
                size: phentsize,
            });
        }
        let table_len = mul(phnum, phentsize, "program header table")?;
        r.bytes(phoff, table_len, "program header table")?;
        for i in 0..phnum {
            let off = add(phoff, i * phentsize, "program header")?;
            segments.push(read_program_header(&r, off)?);
        }
    }

    if !raw_sections.is_empty() {
        let shstrndx = if shstrndx_raw == SHN_XINDEX {
            section_zero.as_ref().map_or(0, |s| u64::from(s.link))
        } else {
            u64::from(shstrndx_raw)
        };
        if shstrndx != 0 {
            let strtab_section = usize::try_from(shstrndx)
                .ok()
                .and_then(|i| raw_sections.get(i))
                .map(|(_, s)| s.clone())
                .ok_or(ElfError::BadSectionIndex {
                    what: "e_shstrndx",
                    index: shstrndx,
                })?;
            let names = section_data(&r, &strtab_section, "section name table")?;
            for (name_offset, s) in raw_sections.iter_mut() {
                s.name = cstr(names, *name_offset, "section name")?;
            }
        }
    }
    let sections: Vec<Section> = raw_sections.into_iter().map(|(_, s)| s).collect();

    let mut interpreter = None;
    if let Some(seg) = segments.iter().find(|s| s.kind == PT_INTERP) {
        let bytes = r.bytes(seg.offset, seg.filesz, "PT_INTERP")?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        interpreter = Some(String::from_utf8_lossy(&bytes[..end]).into_owned());
    }

    let mut elf = ElfFile {
        class,
        endian,
        file_type,
        machine,
        interpreter,
        segments,
        sections: Vec::new(),
        needed: Vec::new(),
        soname: None,
        rpath: None,
        runpath: None,
        symbols: Vec::new(),
        rodata_strings: Vec::new(),
    };

    parse_dynamic(&r, &sections, &mut elf)?;
    elf.symbols = parse_dynsym(&r, &sections)?;
    elf.rodata_strings = collect_rodata_strings(&r, &sections)?;
    elf.sections = sections;
    Ok(elf)
}

/// Returns the raw sh_name offset alongside the section; names are resolved
/// once the whole table, and so the name table's location, is known.
fn read_section_header(r: &Reader, off: u64) -> Result<(u32, Section)> {
    let w = r.word_size();
    let name_offset = r.u32(off, "sh_name")?;
    let section = Section {
        name: String::new(),
        kind: r.u32(add(off, 4, "sh_type")?, "sh_type")?,
        flags: r.word(add(off, 8, "sh_flags")?, "sh_flags")?,
        addr: r.word(add(off, 8 + w, "sh_addr")?, "sh_addr")?,
        offset: r.word(add(off, 8 + 2 * w, "sh_offset")?, "sh_offset")?,
        size: r.word(add(off, 8 + 3 * w, "sh_size")?, "sh_size")?,
        link: r.u32(add(off, 8 + 4 * w, "sh_link")?, "sh_link")?,
        info: r.u32(add(off, 12 + 4 * w, "sh_info")?, "sh_info")?,
        entsize: r.word(add(off, 16 + 5 * w, "sh_entsize")?, "sh_entsize")?,
    };
    Ok((name_offset, section))
}

fn read_program_header(r: &Reader, off: u64) -> Result<Segment> {
    let field = |delta: u64| add(off, delta, "program header");
    match r.class {
        Class::Elf32 => Ok(Segment {
            kind: r.u32(field(0)?, "p_type")?,
            offset: u64::from(r.u32(field(4)?, "p_offset")?),
            vaddr: u64::from(r.u32(field(8)?, "p_vaddr")?),
            filesz: u64::from(r.u32(field(16)?, "p_filesz")?),
            memsz: u64::from(r.u32(field(20)?, "p_memsz")?),
            flags: r.u32(field(24)?, "p_flags")?,
        }),
        Class::Elf64 => Ok(Segment {
            kind: r.u32(field(0)?, "p_type")?,
            flags: r.u32(field(4)?, "p_flags")?,
            offset: r.u64(field(8)?, "p_offset")?,
            vaddr: r.u64(field(16)?, "p_vaddr")?,
            filesz: r.u64(field(32)?, "p_filesz")?,
            memsz: r.u64(field(40)?, "p_memsz")?,
        }),
    }
}

fn section_at<'s>(sections: &'s [Section], index: u64, what: &'static str) -> Result<&'s Section> {
    usize::try_from(index)
        .ok()
        .and_then(|i| sections.get(i))
        .ok_or(ElfError::BadSectionIndex { what, index })
}

fn section_data<'a>(r: &Reader<'a>, s: &Section, what: &'static str) -> Result<&'a [u8]> {
    if s.kind == SHT_NOBITS {
        return Ok(&[]);
    }
    r.bytes(s.offset, s.size, what)
}

fn parse_dynamic(r: &Reader, sections: &[Section], elf: &mut ElfFile) -> Result<()> {
    let Some(dynamic) = sections.iter().find(|s| s.kind == SHT_DYNAMIC) else {
        return Ok(());
    };
    let data = section_data(r, dynamic, ".dynamic")?;
    let strtab_section = section_at(sections, u64::from(dynamic.link), ".dynamic sh_link")?;
    let strtab = section_data(r, strtab_section, ".dynamic string table")?;
    let d = r.with_data(data);
    let w = d.word_size();
    let count = data.len() as u64 / (2 * w);
    for i in 0..count {
        let tag = d.word(i * 2 * w, "d_tag")?;
        let val = d.word(i * 2 * w + w, "d_val")?;
        let string = |what| {
            u32::try_from(val)
                .map_err(|_| ElfError::UnterminatedString { what, offset: val })
                .and_then(|off| cstr(strtab, off, what))
        };
        match tag {
            DT_NULL => break,
            DT_NEEDED => elf.needed.push(string("DT_NEEDED")?),
            DT_SONAME => elf.soname = Some(string("DT_SONAME")?),
            DT_RPATH => elf.rpath = Some(string("DT_RPATH")?),
            DT_RUNPATH => elf.runpath = Some(string("DT_RUNPATH")?),
            _ => {}
        }
    }
    Ok(())
}

/// Version index -> (version name, providing file for imports).
type VersionTable = HashMap<u16, (String, Option<String>)>;

fn parse_dynsym(r: &Reader, sections: &[Section]) -> Result<Vec<Symbol>> {
    let Some(symtab) = sections.iter().find(|s| s.kind == SHT_DYNSYM) else {
        return Ok(Vec::new());
    };
    let data = section_data(r, symtab, ".dynsym")?;
    let strtab_section = section_at(sections, u64::from(symtab.link), ".dynsym sh_link")?;
    let strtab = section_data(r, strtab_section, ".dynsym string table")?;

    let versym = match sections.iter().find(|s| s.kind == SHT_GNU_VERSYM) {
        Some(s) => Some(section_data(r, s, ".gnu.version")?),
        None => None,
    };
    let mut versions = VersionTable::new();
    for s in sections {
        if s.kind == SHT_GNU_VERNEED || s.kind == SHT_GNU_VERDEF {
            let body = section_data(r, s, "version section")?;
            let names_section = section_at(sections, u64::from(s.link), "version sh_link")?;
            let names = section_data(r, names_section, "version string table")?;
            if s.kind == SHT_GNU_VERNEED {
                parse_verneed(&r.with_data(body), s.info, names, &mut versions)?;
            } else {
                parse_verdef(&r.with_data(body), s.info, names, &mut versions)?;
            }
        }
    }

    let d = r.with_data(data);
    let entsize: u64 = match r.class {
        Class::Elf32 => 16,
        Class::Elf64 => 24,
    };
    let count = data.len() as u64 / entsize;
    let mut symbols = Vec::with_capacity(count.saturating_sub(1) as usize);
    for i in 1..count {
        let off = i * entsize;
        let (name_off, value, size, info, shndx) = match r.class {
            Class::Elf32 => (
                d.u32(off, "st_name")?,
                u64::from(d.u32(off + 4, "st_value")?),
                u64::from(d.u32(off + 8, "st_size")?),
                d.u8(off + 12, "st_info")?,
                d.u16(off + 14, "st_shndx")?,
            ),
            Class::Elf64 => (
                d.u32(off, "st_name")?,
                d.u64(off + 8, "st_value")?,
                d.u64(off + 16, "st_size")?,
                d.u8(off + 4, "st_info")?,
                d.u16(off + 6, "st_shndx")?,
            ),
        };
        let version = match versym {
            Some(table) if (i + 1) * 2 <= table.len() as u64 => {
                let raw = r.with_data(table).u16(i * 2, ".gnu.version entry")?;
                let index = raw & VERSYM_INDEX;
                // Indices 0 and 1 mean "local" and "global, unversioned".
                if index >= 2 {
                    versions.get(&index).map(|(name, file)| SymbolVersion {
                        name: name.clone(),
                        file: file.clone(),
                        hidden: raw & VERSYM_HIDDEN != 0,
                    })
                } else {
                    None
                }
            }
            _ => None,
        };
        symbols.push(Symbol {
            name: cstr(strtab, name_off, "symbol name")?,
            binding: Binding::from_raw(info >> 4),
            kind: SymbolType::from_raw(info & 0xf),
            section_index: shndx,
            value,
            size,
            version,
        });
    }
    Ok(symbols)
}

fn parse_verneed(d: &Reader, count: u32, names: &[u8], out: &mut VersionTable) -> Result<()> {
    // Each record is at least 16 bytes, so this caps the walk even when the
    // vn_next chain is crafted to revisit the section.
    let limit = d.data.len() as u64 / 16 + 1;
    let mut off = 0u64;
    for _ in 0..u64::from(count).min(limit) {
        let aux_count = d.u16(add(off, 2, "vn_cnt")?, "vn_cnt")?;
        let file = cstr(names, d.u32(add(off, 4, "vn_file")?, "vn_file")?, "vn_file")?;
        let aux_off = d.u32(add(off, 8, "vn_aux")?, "vn_aux")?;
        let next = d.u32(add(off, 12, "vn_next")?, "vn_next")?;
        let mut aux = add(off, u64::from(aux_off), "vn_aux")?;
        for _ in 0..u64::from(aux_count).min(limit) {
            let other = d.u16(add(aux, 6, "vna_other")?, "vna_other")?;
            let name_off = d.u32(add(aux, 8, "vna_name")?, "vna_name")?;
            let aux_next = d.u32(add(aux, 12, "vna_next")?, "vna_next")?;
            let name = cstr(names, name_off, "vna_name")?;
            out.insert(other & VERSYM_INDEX, (name, Some(file.clone())));
            if aux_next == 0 {
                break;
            }
            aux = add(aux, u64::from(aux_next), "vna_next")?;
        }
        if next == 0 {
            break;
        }
        off = add(off, u64::from(next), "vn_next")?;
    }
    Ok(())
}

fn parse_verdef(d: &Reader, count: u32, names: &[u8], out: &mut VersionTable) -> Result<()> {
    let limit = d.data.len() as u64 / 20 + 1;
    let mut off = 0u64;
    for _ in 0..u64::from(count).min(limit) {
        let index = d.u16(add(off, 4, "vd_ndx")?, "vd_ndx")?;
        let aux_count = d.u16(add(off, 6, "vd_cnt")?, "vd_cnt")?;
        let aux_off = d.u32(add(off, 12, "vd_aux")?, "vd_aux")?;
        let next = d.u32(add(off, 16, "vd_next")?, "vd_next")?;
        // The first verdaux names the version; later ones name its parents.
        if aux_count > 0 {
            let aux = add(off, u64::from(aux_off), "vd_aux")?;
            let name_off = d.u32(aux, "vda_name")?;
            let name = cstr(names, name_off, "vda_name")?;
            out.insert(index & VERSYM_INDEX, (name, None));
        }
        if next == 0 {
            break;
        }
        off = add(off, u64::from(next), "vd_next")?;
    }
    Ok(())
}

fn collect_rodata_strings(r: &Reader, sections: &[Section]) -> Result<Vec<String>> {
    let mut found = BTreeSet::new();
    for s in sections {
        let read_only_data = s.kind == SHT_PROGBITS
            && s.flags & SHF_ALLOC != 0
            && s.flags & (SHF_WRITE | SHF_EXECINSTR) == 0;
        if !read_only_data {
            continue;
        }
        let data = section_data(r, s, "read-only data section")?;
        let mut pieces: Vec<&[u8]> = data.split(|&b| b == 0).collect();
        // The final piece has no NUL after it, so it is not a C string.
        pieces.pop();
        for piece in pieces {
            if piece.len() >= MIN_STRING_LEN && piece.iter().all(|&b| (0x20..0x7f).contains(&b)) {
                found.insert(String::from_utf8_lossy(piece).into_owned());
            }
        }
    }
    Ok(found.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstr_requires_terminator_inside_table() {
        let table = b"\0abc\0de";
        assert_eq!(cstr(table, 1, "t").unwrap(), "abc");
        assert_eq!(cstr(table, 0, "t").unwrap(), "");
        assert!(matches!(
            cstr(table, 5, "t"),
            Err(ElfError::UnterminatedString { .. })
        ));
        assert!(matches!(
            cstr(table, 100, "t"),
            Err(ElfError::UnterminatedString { .. })
        ));
    }

    #[test]
    fn reader_rejects_overflowing_ranges() {
        let data = [0u8; 8];
        let r = Reader {
            data: &data,
            endian: Endian::Big,
            class: Class::Elf64,
        };
        assert!(r.bytes(u64::MAX, 2, "x").is_err());
        assert!(r.bytes(4, u64::MAX, "x").is_err());
        assert!(r.u64(1, "x").is_err());
        assert_eq!(r.u64(0, "x").unwrap(), 0);
    }

    #[test]
    fn short_and_foreign_inputs_are_typed_errors() {
        assert_eq!(ElfFile::parse(b""), Err(ElfError::NotElf));
        assert_eq!(ElfFile::parse(b"MZ\x90\0"), Err(ElfError::NotElf));
        assert!(matches!(
            ElfFile::parse(b"\x7fELF\x02\x01"),
            Err(ElfError::Truncated { .. })
        ));
        let mut ident = *b"\x7fELF\x03\x01\x01\0\0\0\0\0\0\0\0\0";
        assert_eq!(ElfFile::parse(&ident), Err(ElfError::UnsupportedClass(3)));
        ident[4] = 1;
        ident[5] = 9;
        assert_eq!(
            ElfFile::parse(&ident),
            Err(ElfError::UnsupportedEncoding(9))
        );
    }
}
