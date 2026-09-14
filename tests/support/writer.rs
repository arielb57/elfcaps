//! Test-only ELF writer. Builds small but structurally real shared objects and
//! executables byte by byte: ELF header, program headers (PT_INTERP, PT_LOAD,
//! PT_DYNAMIC), `.dynsym`/`.dynstr`, `.gnu.version`, `.gnu.version_d`,
//! `.gnu.version_r`, `.text`, `.rodata`, `.dynamic` and `.shstrtab`.
//!
//! It deliberately shares no code or types with the parser, so a round trip
//! checks the parser against an independent reading of the ELF specification.

#![allow(dead_code)]

use std::collections::BTreeMap;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_TLS: u8 = 6;
pub const STT_GNU_IFUNC: u8 = 10;

pub const EM_386: u16 = 3;
pub const EM_PPC64: u16 = 21;
pub const EM_X86_64: u16 = 62;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bits {
    B32,
    B64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Version {
    /// Imported from `file` with version `name` (`.gnu.version_r`).
    Needed { file: String, name: String },
    /// Defined by this object (`.gnu.version_d`).
    Defined(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymSpec {
    pub name: String,
    pub bind: u8,
    pub kind: u8,
    pub defined: bool,
    pub version: Option<Version>,
    pub hidden: bool,
}

#[derive(Debug, Clone)]
pub struct ElfSpec {
    pub bits: Bits,
    pub order: Order,
    pub e_type: u16,
    pub machine: u16,
    pub interp: Option<String>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub symbols: Vec<SymSpec>,
    pub rodata: Vec<String>,
}

impl ElfSpec {
    pub fn new(bits: Bits, order: Order) -> ElfSpec {
        let machine = match (bits, order) {
            (Bits::B32, _) => EM_386,
            (Bits::B64, Order::Little) => EM_X86_64,
            (Bits::B64, Order::Big) => EM_PPC64,
        };
        ElfSpec {
            bits,
            order,
            e_type: 3,
            machine,
            interp: None,
            needed: Vec::new(),
            soname: None,
            rpath: None,
            runpath: None,
            symbols: Vec::new(),
            rodata: Vec::new(),
        }
    }

    /// A 64-bit little-endian shared library.
    pub fn lib(soname: &str) -> ElfSpec {
        ElfSpec::new(Bits::B64, Order::Little).soname(soname)
    }

    /// A 64-bit little-endian PIE executable with an interpreter.
    pub fn exe() -> ElfSpec {
        let mut spec = ElfSpec::new(Bits::B64, Order::Little);
        spec.interp = Some("/lib64/ld-linux-x86-64.so.2".into());
        spec
    }

    pub fn soname(mut self, name: &str) -> Self {
        self.soname = Some(name.into());
        self
    }

    pub fn needed(mut self, name: &str) -> Self {
        self.needed.push(name.into());
        self
    }

    pub fn rpath(mut self, path: &str) -> Self {
        self.rpath = Some(path.into());
        self
    }

    pub fn runpath(mut self, path: &str) -> Self {
        self.runpath = Some(path.into());
        self
    }

    pub fn import(self, name: &str) -> Self {
        self.symbol(SymSpec {
            name: name.into(),
            bind: STB_GLOBAL,
            kind: STT_FUNC,
            defined: false,
            version: None,
            hidden: false,
        })
    }

    pub fn import_versioned(self, name: &str, file: &str, version: &str) -> Self {
        self.symbol(SymSpec {
            name: name.into(),
            bind: STB_GLOBAL,
            kind: STT_FUNC,
            defined: false,
            version: Some(Version::Needed {
                file: file.into(),
                name: version.into(),
            }),
            hidden: false,
        })
    }

    pub fn export(self, name: &str) -> Self {
        self.symbol(SymSpec {
            name: name.into(),
            bind: STB_GLOBAL,
            kind: STT_FUNC,
            defined: true,
            version: None,
            hidden: false,
        })
    }

    pub fn symbol(mut self, sym: SymSpec) -> Self {
        self.symbols.push(sym);
        self
    }

    pub fn rodata(mut self, s: &str) -> Self {
        self.rodata.push(s.into());
        self
    }

    pub fn build(&self) -> Vec<u8> {
        Builder::new(self).build()
    }
}

pub fn elf_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for b in name.bytes() {
        h = (h << 4).wrapping_add(u32::from(b));
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

struct Out {
    buf: Vec<u8>,
    bits: Bits,
    order: Order,
}

impl Out {
    fn new(bits: Bits, order: Order) -> Out {
        Out {
            buf: Vec::new(),
            bits,
            order,
        }
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        match self.order {
            Order::Little => self.buf.extend_from_slice(&v.to_le_bytes()),
            Order::Big => self.buf.extend_from_slice(&v.to_be_bytes()),
        }
    }
    fn u32(&mut self, v: u32) {
        match self.order {
            Order::Little => self.buf.extend_from_slice(&v.to_le_bytes()),
            Order::Big => self.buf.extend_from_slice(&v.to_be_bytes()),
        }
    }
    fn u64(&mut self, v: u64) {
        match self.order {
            Order::Little => self.buf.extend_from_slice(&v.to_le_bytes()),
            Order::Big => self.buf.extend_from_slice(&v.to_be_bytes()),
        }
    }
    fn word(&mut self, v: u64) {
        match self.bits {
            Bits::B32 => self.u32(u32::try_from(v).expect("value fits ELF32 word")),
            Bits::B64 => self.u64(v),
        }
    }
}

#[derive(Default)]
struct StrTab {
    bytes: Vec<u8>,
    offsets: BTreeMap<String, u32>,
}

impl StrTab {
    fn new() -> StrTab {
        StrTab {
            bytes: vec![0],
            offsets: BTreeMap::new(),
        }
    }
    fn add(&mut self, s: &str) -> u32 {
        if s.is_empty() {
            return 0;
        }
        if let Some(&off) = self.offsets.get(s) {
            return off;
        }
        let off = self.bytes.len() as u32;
        self.bytes.extend_from_slice(s.as_bytes());
        self.bytes.push(0);
        self.offsets.insert(s.to_string(), off);
        off
    }
}

struct SectionOut {
    name: String,
    kind: u32,
    flags: u64,
    data: Vec<u8>,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
    offset: u64,
}

struct Builder<'a> {
    spec: &'a ElfSpec,
    w: u64,
}

const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;
const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;

impl<'a> Builder<'a> {
    fn new(spec: &'a ElfSpec) -> Builder<'a> {
        let w = match spec.bits {
            Bits::B32 => 4,
            Bits::B64 => 8,
        };
        Builder { spec, w }
    }

    fn out(&self) -> Out {
        Out::new(self.spec.bits, self.spec.order)
    }

    fn build(&self) -> Vec<u8> {
        let spec = self.spec;
        let mut dynstr = StrTab::new();

        // Version indices: 1 is the base definition, then defined versions,
        // then needed versions grouped by file, as binutils lays them out.
        let mut def_names: Vec<String> = Vec::new();
        let mut need_files: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for sym in &spec.symbols {
            match &sym.version {
                Some(Version::Defined(name)) if !def_names.contains(name) => {
                    def_names.push(name.clone())
                }
                Some(Version::Needed { file, name }) => {
                    let names = need_files.entry(file.clone()).or_default();
                    if !names.contains(name) {
                        names.push(name.clone());
                    }
                }
                _ => {}
            }
        }
        let mut index_of: BTreeMap<(Option<String>, String), u16> = BTreeMap::new();
        let mut next_index = 2u16;
        for name in &def_names {
            index_of.insert((None, name.clone()), next_index);
            next_index += 1;
        }
        for (file, names) in &need_files {
            for name in names {
                index_of.insert((Some(file.clone()), name.clone()), next_index);
                next_index += 1;
            }
        }
        let versioned = !index_of.is_empty();

        for n in &spec.needed {
            dynstr.add(n);
        }
        for s in [&spec.soname, &spec.rpath, &spec.runpath]
            .into_iter()
            .flatten()
        {
            dynstr.add(s);
        }
        let base_name = spec.soname.clone().unwrap_or_else(|| "base".into());

        // Section list; indices are fixed before contents reference them.
        let mut names: Vec<&str> = vec![""];
        if spec.interp.is_some() {
            names.push(".interp");
        }
        names.push(".dynsym");
        names.push(".dynstr");
        if versioned {
            names.push(".gnu.version");
        }
        if !def_names.is_empty() {
            names.push(".gnu.version_d");
        }
        if !need_files.is_empty() {
            names.push(".gnu.version_r");
        }
        names.extend([".text", ".rodata", ".dynamic", ".shstrtab"]);
        let idx = |n: &str| names.iter().position(|x| *x == n).unwrap() as u32;

        // .dynsym
        let mut dynsym = self.out();
        let symsize = if self.w == 4 { 16 } else { 24 };
        dynsym.buf.resize(symsize, 0);
        let text_idx = idx(".text") as u16;
        let mut versym = self.out();
        versym.u16(0);
        let local_count = 1 + spec.symbols.iter().filter(|s| s.bind == STB_LOCAL).count();
        for (i, sym) in spec.symbols.iter().enumerate() {
            let name = dynstr.add(&sym.name);
            let info = (sym.bind << 4) | sym.kind;
            let shndx = if sym.defined { text_idx } else { 0 };
            let value = if sym.defined {
                0x1000 + i as u64 * 4
            } else {
                0
            };
            let size = if sym.defined { 4 } else { 0 };
            match spec.bits {
                Bits::B32 => {
                    dynsym.u32(name);
                    dynsym.u32(value as u32);
                    dynsym.u32(size);
                    dynsym.u8(info);
                    dynsym.u8(0);
                    dynsym.u16(shndx);
                }
                Bits::B64 => {
                    dynsym.u32(name);
                    dynsym.u8(info);
                    dynsym.u8(0);
                    dynsym.u16(shndx);
                    dynsym.u64(value);
                    dynsym.u64(u64::from(size));
                }
            }
            let v = match &sym.version {
                None if sym.bind == STB_LOCAL => 0,
                None => 1,
                Some(Version::Defined(n)) => index_of[&(None, n.clone())],
                Some(Version::Needed { file, name }) => {
                    index_of[&(Some(file.clone()), name.clone())]
                }
            };
            versym.u16(if sym.hidden { v | 0x8000 } else { v });
        }

        // .gnu.version_d: base entry plus one per defined version.
        let mut verdef = self.out();
        if !def_names.is_empty() {
            let mut entries = vec![(1u16, 1u16, base_name.clone())];
            for name in &def_names {
                entries.push((0, index_of[&(None, name.clone())], name.clone()));
            }
            let count = entries.len();
            for (i, (flags, ndx, name)) in entries.into_iter().enumerate() {
                let name_off = dynstr.add(&name);
                verdef.u16(1);
                verdef.u16(flags);
                verdef.u16(ndx);
                verdef.u16(1);
                verdef.u32(elf_hash(&name));
                verdef.u32(20);
                verdef.u32(if i + 1 == count { 0 } else { 28 });
                verdef.u32(name_off);
                verdef.u32(0);
            }
        }

        // .gnu.version_r
        let mut verneed = self.out();
        let file_count = need_files.len();
        for (i, (file, names_for_file)) in need_files.iter().enumerate() {
            let file_off = dynstr.add(file);
            let cnt = names_for_file.len();
            verneed.u16(1);
            verneed.u16(cnt as u16);
            verneed.u32(file_off);
            verneed.u32(16);
            verneed.u32(if i + 1 == file_count {
                0
            } else {
                16 + 16 * cnt as u32
            });
            for (j, name) in names_for_file.iter().enumerate() {
                let name_off = dynstr.add(name);
                verneed.u32(elf_hash(name));
                verneed.u16(0);
                verneed.u16(index_of[&(Some(file.clone()), name.clone())]);
                verneed.u32(name_off);
                verneed.u32(if j + 1 == cnt { 0 } else { 16 });
            }
        }

        let mut rodata = Vec::new();
        for s in &spec.rodata {
            rodata.extend_from_slice(s.as_bytes());
            rodata.push(0);
        }

        let mut shstrtab = StrTab::new();
        for name in &names {
            shstrtab.add(name);
        }

        let mut sections: Vec<SectionOut> = Vec::new();
        let mut push = |name: &str, kind, flags, data, link, info, align, entsize| {
            sections.push(SectionOut {
                name: name.to_string(),
                kind,
                flags,
                data,
                link,
                info,
                align,
                entsize,
                offset: 0,
            })
        };
        let dynstr_idx = idx(".dynstr");
        push("", 0, 0, Vec::new(), 0, 0, 0, 0);
        if let Some(interp) = &spec.interp {
            let mut data = interp.as_bytes().to_vec();
            data.push(0);
            push(".interp", SHT_PROGBITS, 2, data, 0, 0, 1, 0);
        }
        push(
            ".dynsym",
            SHT_DYNSYM,
            2,
            dynsym.buf,
            dynstr_idx,
            local_count as u32,
            self.w,
            symsize as u64,
        );
        // Every string (symbols, versions, dynamic entries) is already in .dynstr.
        push(".dynstr", SHT_STRTAB, 2, dynstr.bytes.clone(), 0, 0, 1, 0);
        if versioned {
            push(
                ".gnu.version",
                SHT_GNU_VERSYM,
                2,
                versym.buf,
                idx(".dynsym"),
                0,
                2,
                2,
            );
        }
        if !def_names.is_empty() {
            push(
                ".gnu.version_d",
                SHT_GNU_VERDEF,
                2,
                verdef.buf,
                dynstr_idx,
                def_names.len() as u32 + 1,
                self.w,
                0,
            );
        }
        if !need_files.is_empty() {
            push(
                ".gnu.version_r",
                SHT_GNU_VERNEED,
                2,
                verneed.buf,
                dynstr_idx,
                file_count as u32,
                self.w,
                0,
            );
        }
        push(".text", SHT_PROGBITS, 6, vec![0xc3; 64], 0, 0, 16, 0);
        push(".rodata", SHT_PROGBITS, 2, rodata, 0, 0, 1, 0);
        let dyn_entries = spec.needed.len()
            + [&spec.soname, &spec.rpath, &spec.runpath]
                .iter()
                .filter(|s| s.is_some())
                .count()
            + 5;
        push(
            ".dynamic",
            SHT_DYNAMIC,
            3,
            vec![0; dyn_entries * 2 * self.w as usize],
            dynstr_idx,
            0,
            self.w,
            2 * self.w,
        );
        push(
            ".shstrtab",
            SHT_STRTAB,
            0,
            shstrtab.bytes.clone(),
            0,
            0,
            1,
            0,
        );

        // Layout: headers, then contents in order, then the section table.
        let ehsize = if self.w == 4 { 52 } else { 64 };
        let phentsize = if self.w == 4 { 32 } else { 56 };
        let phnum = 2 + u64::from(spec.interp.is_some());
        let mut cursor = ehsize + phnum * phentsize;
        for s in sections.iter_mut().skip(1) {
            let align = s.align.max(1);
            cursor = cursor.div_ceil(align) * align;
            s.offset = cursor;
            cursor += s.data.len() as u64;
        }
        let shoff = cursor.div_ceil(self.w) * self.w;

        // Fill .dynamic now that addresses (== file offsets) are known.
        let dynstr_addr = sections[idx(".dynstr") as usize].offset;
        let dynsym_addr = sections[idx(".dynsym") as usize].offset;
        let text_addr = sections[idx(".text") as usize].offset;
        let mut dynamic = self.out();
        let mut dyn_entry = |tag: u64, val: u64| {
            dynamic.word(tag);
            dynamic.word(val);
        };
        for n in &spec.needed {
            dyn_entry(1, u64::from(dynstr.add(n)));
        }
        if let Some(s) = &spec.soname {
            dyn_entry(14, u64::from(dynstr.add(s)));
        }
        if let Some(s) = &spec.rpath {
            dyn_entry(15, u64::from(dynstr.add(s)));
        }
        if let Some(s) = &spec.runpath {
            dyn_entry(29, u64::from(dynstr.add(s)));
        }
        dyn_entry(5, dynstr_addr);
        dyn_entry(6, dynsym_addr);
        dyn_entry(10, dynstr.bytes.len() as u64);
        dyn_entry(11, symsize as u64);
        dyn_entry(0, 0);
        let dynamic_idx = idx(".dynamic") as usize;
        assert_eq!(dynamic.buf.len(), sections[dynamic_idx].data.len());
        sections[dynamic_idx].data = dynamic.buf;

        let mut out = self.out();
        out.buf.extend_from_slice(b"\x7fELF");
        out.u8(if self.w == 4 { 1 } else { 2 });
        out.u8(match spec.order {
            Order::Little => 1,
            Order::Big => 2,
        });
        out.u8(1);
        out.buf.resize(16, 0);
        out.u16(spec.e_type);
        out.u16(spec.machine);
        out.u32(1);
        out.word(text_addr);
        out.word(ehsize);
        out.word(shoff);
        out.u32(0);
        out.u16(ehsize as u16);
        out.u16(phentsize as u16);
        out.u16(phnum as u16);
        out.u16(if self.w == 4 { 40 } else { 64 });
        out.u16(sections.len() as u16);
        out.u16(idx(".shstrtab") as u16);

        let load_end = sections[idx(".dynamic") as usize].offset
            + sections[idx(".dynamic") as usize].data.len() as u64;
        let mut phdr = |kind: u32, flags: u32, offset: u64, size: u64, align: u64| match spec.bits {
            Bits::B32 => {
                out.u32(kind);
                out.u32(offset as u32);
                out.u32(offset as u32);
                out.u32(offset as u32);
                out.u32(size as u32);
                out.u32(size as u32);
                out.u32(flags);
                out.u32(align as u32);
            }
            Bits::B64 => {
                out.u32(kind);
                out.u32(flags);
                out.u64(offset);
                out.u64(offset);
                out.u64(offset);
                out.u64(size);
                out.u64(size);
                out.u64(align);
            }
        };
        if spec.interp.is_some() {
            let s = &sections[idx(".interp") as usize];
            phdr(3, 4, s.offset, s.data.len() as u64, 1);
        }
        phdr(1, 7, 0, load_end, 0x1000);
        let d = &sections[dynamic_idx];
        phdr(2, 6, d.offset, d.data.len() as u64, self.w);

        for s in sections.iter().skip(1) {
            out.buf.resize(s.offset as usize, 0);
            out.buf.extend_from_slice(&s.data);
        }
        out.buf.resize(shoff as usize, 0);
        for s in &sections {
            out.u32(shstrtab.add(&s.name));
            out.u32(s.kind);
            out.word(s.flags);
            out.word(if s.flags & 2 != 0 { s.offset } else { 0 });
            out.word(s.offset);
            out.word(s.data.len() as u64);
            out.u32(s.link);
            out.u32(s.info);
            out.word(s.align);
            out.word(s.entsize);
        }
        out.buf
    }
}
