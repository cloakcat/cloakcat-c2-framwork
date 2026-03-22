//! PE (Portable Executable) parser for sRDI shellcode conversion.
//!
//! Supports PE32+ (64-bit / AMD64) images only.  All parsing is pure safe Rust
//! with explicit bounds checking — no `unsafe`, no platform dependencies.
//!
//! Structure analogous to `bof/coff_parser.rs` but with the additional layers
//! a linked PE image carries on top of a raw COFF object:
//!
//! ```text
//! DOS header (64 B)
//! └─ e_lfanew ──► PE\0\0 signature (4 B)
//!                 IMAGE_FILE_HEADER   / COFF header  (20 B)
//!                 IMAGE_OPTIONAL_HEADER64             (240 B)
//!                   └─ DataDirectory[16]              (128 B of the 240)
//!                 Section headers × N                 (40 B each)
//!                 … raw section data …
//!                 Import Directory Table
//!                 Base Relocation Table
//! ```

use anyhow::{bail, ensure, Context, Result};

// ── Signatures & magic numbers ────────────────────────────────────────────────

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B; // PE32+
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

// ── Section characteristics (selected) ───────────────────────────────────────

pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// ── Data-directory indices ────────────────────────────────────────────────────

pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

/// Total number of data-directory slots in a PE32+ optional header.
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

// ── Base-relocation types ─────────────────────────────────────────────────────

/// Padding / no-op relocation (skip).
pub const IMAGE_REL_BASED_ABSOLUTE: u8 = 0;
/// 64-bit absolute address fixup — the common type in x86-64 images.
pub const IMAGE_REL_BASED_DIR64: u8 = 10;

// ── On-disk record sizes ──────────────────────────────────────────────────────

const DOS_HEADER_MIN_SIZE: usize = 64; // we only need magic + e_lfanew
const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
/// Fixed part of the PE32+ optional header (before DataDirectory).
const OPT_HDR64_FIXED_SIZE: usize = 112;
const DATA_DIR_ENTRY_SIZE: usize = 8;
/// Full PE32+ optional header = fixed + 16 data-directory entries.
const OPT_HDR64_FULL_SIZE: usize =
    OPT_HDR64_FIXED_SIZE + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * DATA_DIR_ENTRY_SIZE; // 240

const SECTION_HEADER_SIZE: usize = 40;
const IMPORT_DESCRIPTOR_SIZE: usize = 20;
const THUNK64_SIZE: usize = 8;
const BASE_RELOC_BLOCK_HDR_SIZE: usize = 8;

// ── Public types ──────────────────────────────────────────────────────────────

/// DOS stub header — only the two fields relevant to PE loading.
#[derive(Debug, Clone)]
pub struct DosHeader {
    /// Magic bytes: must equal `IMAGE_DOS_SIGNATURE` (0x5A4D, "MZ").
    pub e_magic: u16,
    /// File offset of the PE signature ("PE\0\0").
    pub e_lfanew: u32,
}

/// COFF file header (IMAGE_FILE_HEADER) — identical layout to the COFF parser.
#[derive(Debug, Clone)]
pub struct PeHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    /// Bytes occupied by the optional header that follows (240 for PE32+).
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// A single IMAGE_DATA_DIRECTORY entry (RVA + size).
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    /// `true` when both fields are non-zero (the directory exists).
    #[inline]
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

/// Optional header for 64-bit images (IMAGE_OPTIONAL_HEADER64).
#[derive(Debug, Clone)]
pub struct OptionalHeader64 {
    /// Must be `IMAGE_NT_OPTIONAL_HDR64_MAGIC` (0x020B).
    pub magic: u16,
    pub address_of_entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub data_directories: [DataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

impl OptionalHeader64 {
    /// Import directory (entry 1).
    pub fn import_dir(&self) -> DataDirectory {
        self.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT]
    }
    /// Base relocation directory (entry 5).
    pub fn reloc_dir(&self) -> DataDirectory {
        self.data_directories[IMAGE_DIRECTORY_ENTRY_BASERELOC]
    }
    /// Import Address Table directory (entry 12).
    pub fn iat_dir(&self) -> DataDirectory {
        self.data_directories[IMAGE_DIRECTORY_ENTRY_IAT]
    }
}

/// PE section header (IMAGE_SECTION_HEADER).
///
/// Unlike the COFF parser's `SectionHeader`, PE sections don't carry
/// long-name string-table indirection (the linker resolves those).
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Up to 8 NUL-padded ASCII bytes.
    pub name_raw: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl SectionHeader {
    /// Human-readable section name (NUL-terminated, up to 8 bytes).
    pub fn name(&self) -> &str {
        let end = self
            .name_raw
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.name_raw.len());
        std::str::from_utf8(&self.name_raw[..end]).unwrap_or("<invalid-utf8>")
    }

    /// Raw section data from the flat PE byte blob.
    pub fn raw_data<'a>(&self, data: &'a [u8]) -> Result<&'a [u8]> {
        let start = self.pointer_to_raw_data as usize;
        let end = start
            .checked_add(self.size_of_raw_data as usize)
            .context("section raw data range overflow")?;
        ensure!(end <= data.len(), "section raw data out of bounds");
        Ok(&data[start..end])
    }
}

/// A single imported function — by name or by ordinal.
#[derive(Debug, Clone)]
pub struct ImportFunction {
    /// Present when the high bit of the 64-bit thunk is set (ordinal import).
    pub ordinal: Option<u16>,
    /// Present for name imports (`IMAGE_IMPORT_BY_NAME.Name` string).
    pub name: Option<String>,
}

/// Parsed IMAGE_IMPORT_DESCRIPTOR with resolved DLL name and function list.
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// RVA of the Import Name Table (OriginalFirstThunk).
    pub original_first_thunk: u32,
    /// RVA of the Import Address Table (FirstThunk).
    pub first_thunk: u32,
    pub dll_name: String,
    pub functions: Vec<ImportFunction>,
}

/// A single entry within a base-relocation block.
#[derive(Debug, Clone, Copy)]
pub struct RelocationEntry {
    /// Upper 4 bits of the 16-bit packed field (`IMAGE_REL_BASED_*`).
    pub typ: u8,
    /// Lower 12 bits — byte offset relative to the block's `page_rva`.
    pub offset: u16,
}

/// One IMAGE_BASE_RELOCATION block (page header + its relocation entries).
#[derive(Debug, Clone)]
pub struct BaseRelocationBlock {
    /// Page-aligned RVA this block covers.
    pub page_rva: u32,
    pub entries: Vec<RelocationEntry>,
}

// ── Top-level parsed PE ───────────────────────────────────────────────────────

/// Fully parsed PE32+ image (DLL or EXE).
#[derive(Debug, Clone)]
pub struct PeFile {
    pub dos_header: DosHeader,
    pub pe_header: PeHeader,
    pub optional_header: OptionalHeader64,
    pub sections: Vec<SectionHeader>,
    pub imports: Vec<ImportDescriptor>,
    pub relocations: Vec<BaseRelocationBlock>,
    /// Original raw bytes of the PE file, kept for section data access.
    pub raw_data: Vec<u8>,
}

impl PeFile {
    /// Parse a PE32+ image from raw bytes.
    ///
    /// Rejects non-MZ, non-PE, non-AMD64, and non-PE32+ inputs immediately.
    pub fn parse(data: &[u8]) -> Result<Self> {
        // ── DOS header ────────────────────────────────────────────────────────
        ensure!(
            data.len() >= DOS_HEADER_MIN_SIZE,
            "data too short for DOS header ({} bytes)",
            data.len()
        );
        let dos = parse_dos_header(data)?;
        ensure!(
            dos.e_magic == IMAGE_DOS_SIGNATURE,
            "invalid DOS magic 0x{:04X} (expected MZ 0x5A4D)",
            dos.e_magic
        );

        // ── PE signature ──────────────────────────────────────────────────────
        let pe_sig_off = dos.e_lfanew as usize;
        ensure!(
            pe_sig_off.saturating_add(PE_SIGNATURE_SIZE) <= data.len(),
            "PE signature offset 0x{:X} out of bounds",
            pe_sig_off
        );
        let sig = read_u32_le(data, pe_sig_off)?;
        ensure!(
            sig == IMAGE_NT_SIGNATURE,
            "invalid PE signature 0x{:08X} (expected PE\\0\\0 = 0x00004550)",
            sig
        );

        // ── COFF header ───────────────────────────────────────────────────────
        let coff_off = pe_sig_off + PE_SIGNATURE_SIZE;
        ensure!(
            coff_off + COFF_HEADER_SIZE <= data.len(),
            "COFF header out of bounds"
        );
        let pe_hdr = parse_pe_header(data, coff_off)?;
        ensure!(
            pe_hdr.machine == IMAGE_FILE_MACHINE_AMD64,
            "unsupported machine 0x{:04X} (expected AMD64 0x8664)",
            pe_hdr.machine
        );

        // ── Optional header ───────────────────────────────────────────────────
        let opt_off = coff_off + COFF_HEADER_SIZE;
        // We need at least OPT_HDR64_FULL_SIZE (240 B) to read all 16 data dirs.
        ensure!(
            pe_hdr.size_of_optional_header as usize >= OPT_HDR64_FULL_SIZE,
            "optional header too small ({} B, need {} for PE32+)",
            pe_hdr.size_of_optional_header,
            OPT_HDR64_FULL_SIZE
        );
        ensure!(
            opt_off + pe_hdr.size_of_optional_header as usize <= data.len(),
            "optional header extends past end of file"
        );
        let opt_hdr = parse_optional_header_64(data, opt_off)?;
        ensure!(
            opt_hdr.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            "unsupported optional-header magic 0x{:04X} (expected PE32+ 0x020B)",
            opt_hdr.magic
        );

        // ── Section headers ───────────────────────────────────────────────────
        // Sections start immediately after the optional header (declared size).
        let sections_off = opt_off + pe_hdr.size_of_optional_header as usize;
        let sections =
            parse_section_headers(data, sections_off, pe_hdr.number_of_sections)?;

        // ── Import directory ──────────────────────────────────────────────────
        let imports = if opt_hdr.import_dir().is_present() {
            parse_imports(data, &sections, opt_hdr.import_dir())?
        } else {
            Vec::new()
        };

        // ── Base relocation table ─────────────────────────────────────────────
        let relocations = if opt_hdr.reloc_dir().is_present() {
            parse_relocations(data, &sections, opt_hdr.reloc_dir())?
        } else {
            Vec::new()
        };

        Ok(PeFile {
            dos_header: dos,
            pe_header: pe_hdr,
            optional_header: opt_hdr,
            sections,
            imports,
            relocations,
            raw_data: data.to_vec(),
        })
    }

    /// Return the raw bytes of a named section (e.g. `".text"`, `".rdata"`).
    pub fn get_section_data(&self, name: &str) -> Option<&[u8]> {
        self.sections
            .iter()
            .find(|s| s.name() == name)
            .and_then(|s| s.raw_data(&self.raw_data).ok())
    }

    /// Convert `AddressOfEntryPoint` (an RVA) to a raw file offset.
    ///
    /// Returns `0` if the RVA does not fall inside any section.
    pub fn entry_point_offset(&self) -> u64 {
        rva_to_file_offset(
            self.optional_header.address_of_entry_point,
            &self.sections,
        )
        .unwrap_or(0) as u64
    }
}

// ── Internal: RVA → file-offset ───────────────────────────────────────────────

/// Convert an RVA to a file offset using the section table.
///
/// Uses `max(VirtualSize, SizeOfRawData)` so that both the virtual footprint
/// and the on-disk data are covered.
fn rva_to_file_offset(rva: u32, sections: &[SectionHeader]) -> Option<usize> {
    for s in sections {
        let va = s.virtual_address;
        let span = s.virtual_size.max(s.size_of_raw_data);
        if rva >= va && rva < va.saturating_add(span) {
            let delta = rva - va;
            return Some(s.pointer_to_raw_data as usize + delta as usize);
        }
    }
    None
}

// ── Read helpers ──────────────────────────────────────────────────────────────

fn read_u16_le(data: &[u8], offset: usize) -> Result<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .context("u16 read out of bounds")
}

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .context("u32 read out of bounds")
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64> {
    data.get(offset..offset + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .context("u64 read out of bounds")
}

/// Read a NUL-terminated C string from `data[offset..]`.
fn read_cstr(data: &[u8], offset: usize) -> Result<String> {
    let tail = data.get(offset..).context("cstr: offset out of bounds")?;
    let end = tail
        .iter()
        .position(|&b| b == 0)
        .context("cstr: unterminated string")?;
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

// ── Header parsers ────────────────────────────────────────────────────────────

fn parse_dos_header(data: &[u8]) -> Result<DosHeader> {
    Ok(DosHeader {
        e_magic: read_u16_le(data, 0)?,
        e_lfanew: read_u32_le(data, 60)?,
    })
}

fn parse_pe_header(data: &[u8], off: usize) -> Result<PeHeader> {
    Ok(PeHeader {
        machine: read_u16_le(data, off)?,
        number_of_sections: read_u16_le(data, off + 2)?,
        time_date_stamp: read_u32_le(data, off + 4)?,
        size_of_optional_header: read_u16_le(data, off + 16)?,
        characteristics: read_u16_le(data, off + 18)?,
    })
}

/// Parse a PE32+ optional header.
///
/// Layout (byte offsets from `off`):
/// ```text
///   0  Magic                (2)
///   2  MajorLinkerVersion   (1)
///   3  MinorLinkerVersion   (1)
///   4  SizeOfCode           (4)
///   8  SizeOfInitializedData(4)
///  12  SizeOfUninitialized  (4)
///  16  AddressOfEntryPoint  (4)  ← used by entry_point_offset()
///  20  BaseOfCode           (4)
///  24  ImageBase            (8)  ← 8 bytes in PE32+ (vs 4 in PE32)
///  32  SectionAlignment     (4)
///  36  FileAlignment        (4)
///  40  MajorOSVersion       (2)
///  42  MinorOSVersion       (2)
///  44  MajorImageVersion    (2)
///  46  MinorImageVersion    (2)
///  48  MajorSubsysVersion   (2)
///  50  MinorSubsysVersion   (2)
///  52  Win32VersionValue    (4)
///  56  SizeOfImage          (4)
///  60  SizeOfHeaders        (4)
///  64  CheckSum             (4)
///  68  Subsystem            (2)
///  70  DllCharacteristics   (2)
///  72  SizeOfStackReserve   (8)
///  80  SizeOfStackCommit    (8)
///  88  SizeOfHeapReserve    (8)
///  96  SizeOfHeapCommit     (8)
/// 104  LoaderFlags          (4)
/// 108  NumberOfRvaAndSizes  (4)
/// 112  DataDirectory[16]  (128)  ← OPT_HDR64_FIXED_SIZE
/// ```
fn parse_optional_header_64(data: &[u8], off: usize) -> Result<OptionalHeader64> {
    let mut data_directories =
        [DataDirectory::default(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    let dd_base = off + OPT_HDR64_FIXED_SIZE;
    for (i, dir) in data_directories.iter_mut().enumerate() {
        let dd_off = dd_base + i * DATA_DIR_ENTRY_SIZE;
        dir.virtual_address = read_u32_le(data, dd_off)?;
        dir.size = read_u32_le(data, dd_off + 4)?;
    }

    Ok(OptionalHeader64 {
        magic: read_u16_le(data, off)?,
        address_of_entry_point: read_u32_le(data, off + 16)?,
        image_base: read_u64_le(data, off + 24)?,
        section_alignment: read_u32_le(data, off + 32)?,
        file_alignment: read_u32_le(data, off + 36)?,
        size_of_image: read_u32_le(data, off + 56)?,
        size_of_headers: read_u32_le(data, off + 60)?,
        data_directories,
    })
}

fn parse_section_headers(
    data: &[u8],
    off: usize,
    count: u16,
) -> Result<Vec<SectionHeader>> {
    let n = count as usize;
    let mut headers = Vec::with_capacity(n);

    for i in 0..n {
        let base = off + i * SECTION_HEADER_SIZE;
        ensure!(
            base + SECTION_HEADER_SIZE <= data.len(),
            "section header {} out of bounds",
            i
        );
        let mut name_raw = [0u8; 8];
        name_raw.copy_from_slice(&data[base..base + 8]);
        headers.push(SectionHeader {
            name_raw,
            virtual_size: read_u32_le(data, base + 8)?,
            virtual_address: read_u32_le(data, base + 12)?,
            size_of_raw_data: read_u32_le(data, base + 16)?,
            pointer_to_raw_data: read_u32_le(data, base + 20)?,
            characteristics: read_u32_le(data, base + 36)?,
        });
    }
    Ok(headers)
}

// ── Import table parser ───────────────────────────────────────────────────────

fn parse_imports(
    data: &[u8],
    sections: &[SectionHeader],
    dir: DataDirectory,
) -> Result<Vec<ImportDescriptor>> {
    let base_off = rva_to_file_offset(dir.virtual_address, sections)
        .context("import directory RVA not in any section")?;

    let mut imports = Vec::new();
    // Walk IMAGE_IMPORT_DESCRIPTOR entries until the null terminator.
    let max_entries = dir.size as usize / IMPORT_DESCRIPTOR_SIZE;

    for i in 0..max_entries {
        let off = base_off + i * IMPORT_DESCRIPTOR_SIZE;
        if off + IMPORT_DESCRIPTOR_SIZE > data.len() {
            break;
        }

        let original_first_thunk = read_u32_le(data, off)?;
        // [4] TimeDateStamp, [8] ForwarderChain — not stored
        let name_rva = read_u32_le(data, off + 12)?;
        let first_thunk = read_u32_le(data, off + 16)?;

        // Null descriptor terminates the array.
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let dll_name = rva_to_file_offset(name_rva, sections)
            .and_then(|file_off| read_cstr(data, file_off).ok())
            .unwrap_or_else(|| String::from("<unknown-dll>"));

        // Prefer the Import Name Table (OriginalFirstThunk); fall back to IAT.
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let functions = parse_thunk_array(data, sections, thunk_rva)?;

        imports.push(ImportDescriptor {
            original_first_thunk,
            first_thunk,
            dll_name,
            functions,
        });
    }
    Ok(imports)
}

/// Walk a PE32+ (64-bit) Import Name Table.
fn parse_thunk_array(
    data: &[u8],
    sections: &[SectionHeader],
    thunk_rva: u32,
) -> Result<Vec<ImportFunction>> {
    let Some(mut off) = rva_to_file_offset(thunk_rva, sections) else {
        return Ok(Vec::new());
    };

    let mut funcs = Vec::new();
    loop {
        if off + THUNK64_SIZE > data.len() {
            break;
        }
        let thunk = read_u64_le(data, off)?;
        if thunk == 0 {
            break; // null terminator
        }
        off += THUNK64_SIZE;

        if thunk & (1u64 << 63) != 0 {
            // Ordinal import: low 16 bits carry the ordinal.
            funcs.push(ImportFunction {
                ordinal: Some((thunk & 0xFFFF) as u16),
                name: None,
            });
        } else {
            // Name import: thunk low 32 bits = RVA → IMAGE_IMPORT_BY_NAME.
            // Layout: Hint (u16) + Name (NUL-terminated string).
            let name_rva = (thunk & 0xFFFF_FFFF) as u32;
            let name = rva_to_file_offset(name_rva, sections)
                .and_then(|hint_off| {
                    // Skip 2-byte Hint field.
                    read_cstr(data, hint_off + 2).ok()
                })
                .unwrap_or_else(|| String::from("<invalid-import-name>"));
            funcs.push(ImportFunction {
                ordinal: None,
                name: Some(name),
            });
        }
    }
    Ok(funcs)
}

// ── Base relocation parser ────────────────────────────────────────────────────

fn parse_relocations(
    data: &[u8],
    sections: &[SectionHeader],
    dir: DataDirectory,
) -> Result<Vec<BaseRelocationBlock>> {
    let base_off = rva_to_file_offset(dir.virtual_address, sections)
        .context("relocation directory RVA not in any section")?;

    let total = dir.size as usize;
    let region_end = (base_off + total).min(data.len());
    let mut cursor = base_off;
    let mut blocks = Vec::new();

    while cursor + BASE_RELOC_BLOCK_HDR_SIZE <= region_end {
        let page_rva = read_u32_le(data, cursor)?;
        let size_of_block = read_u32_le(data, cursor + 4)? as usize;

        if size_of_block < BASE_RELOC_BLOCK_HDR_SIZE {
            bail!(
                "base relocation block at 0x{:X} has invalid size {}",
                cursor,
                size_of_block
            );
        }

        let entry_bytes = size_of_block - BASE_RELOC_BLOCK_HDR_SIZE;
        let entry_count = entry_bytes / 2;
        let mut entries = Vec::with_capacity(entry_count);

        for j in 0..entry_count {
            let entry_off = cursor + BASE_RELOC_BLOCK_HDR_SIZE + j * 2;
            if entry_off + 2 > data.len() {
                break;
            }
            let raw = read_u16_le(data, entry_off)?;
            entries.push(RelocationEntry {
                typ: (raw >> 12) as u8,
                offset: raw & 0x0FFF,
            });
        }

        blocks.push(BaseRelocationBlock { page_rva, entries });
        cursor += size_of_block;
    }
    Ok(blocks)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Minimal PE32+ DLL byte blob ───────────────────────────────────────────
    //
    // Layout (all offsets in decimal / hex):
    //
    //   0x000 (  0) DOS header      — 64 B  (e_magic=MZ, e_lfanew=0x40)
    //   0x040 ( 64) PE signature    — 4 B   ("PE\0\0")
    //   0x044 ( 68) COFF header     — 20 B  (AMD64, 1 section, SizeOfOptHdr=240)
    //   0x058 ( 88) Optional header — 240 B (PE32+, EP=0x1000, ImageBase=0x180000000)
    //   0x148 (328) Section header  — 40 B  (.text: VA=0x1000, raw@0x170)
    //   0x170 (368) .text raw data  — 16 B  (0x90 × 16 NOPs)
    //   Total: 384 bytes
    //
    // There are no imports and no relocations (data directories all zero).
    fn minimal_pe_bytes() -> Vec<u8> {
        const PE_OFFSET: usize = 0x40; // e_lfanew
        const COFF_OFFSET: usize = PE_OFFSET + PE_SIGNATURE_SIZE; // 0x44
        const OPT_OFFSET: usize = COFF_OFFSET + COFF_HEADER_SIZE; // 0x58
        const SECTION_OFFSET: usize = OPT_OFFSET + OPT_HDR64_FULL_SIZE; // 0x148
        const DATA_OFFSET: usize = SECTION_OFFSET + SECTION_HEADER_SIZE; // 0x170 = 368
        const TOTAL: usize = DATA_OFFSET + 16; // 384 bytes

        let mut b = vec![0u8; TOTAL];

        // ── DOS header ────────────────────────────────────────────────────────
        b[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes()); // "MZ"
        b[60..64].copy_from_slice(&(PE_OFFSET as u32).to_le_bytes()); // e_lfanew

        // ── PE signature ──────────────────────────────────────────────────────
        b[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");

        // ── COFF header ───────────────────────────────────────────────────────
        let ch = COFF_OFFSET;
        b[ch..ch + 2].copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        b[ch + 2..ch + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
        // TimeDateStamp  = 0
        // PointerToSymbolTable = 0
        // NumberOfSymbols = 0
        b[ch + 16..ch + 18]
            .copy_from_slice(&(OPT_HDR64_FULL_SIZE as u16).to_le_bytes()); // 240
        b[ch + 18..ch + 20].copy_from_slice(&0x2022u16.to_le_bytes()); // EXEC | LARGE_ADDR | DLL

        // ── Optional header PE32+ ─────────────────────────────────────────────
        let oh = OPT_OFFSET;
        b[oh..oh + 2]
            .copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes()); // 0x020B
        b[oh + 16..oh + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        b[oh + 24..oh + 32].copy_from_slice(&0x180000000u64.to_le_bytes()); // ImageBase
        b[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        b[oh + 36..oh + 40].copy_from_slice(&0x10u32.to_le_bytes()); // FileAlignment
        b[oh + 56..oh + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // SizeOfImage
        b[oh + 60..oh + 64].copy_from_slice(&(DATA_OFFSET as u32).to_le_bytes()); // SizeOfHeaders
        b[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        // DataDirectory[16]: all zero (no imports, no relocs)

        // ── Section header: .text ─────────────────────────────────────────────
        let sh = SECTION_OFFSET;
        b[sh..sh + 8].copy_from_slice(b".text\0\0\0");
        b[sh + 8..sh + 12].copy_from_slice(&16u32.to_le_bytes()); // VirtualSize
        b[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        b[sh + 16..sh + 20].copy_from_slice(&16u32.to_le_bytes()); // SizeOfRawData
        b[sh + 20..sh + 24].copy_from_slice(&(DATA_OFFSET as u32).to_le_bytes()); // PointerToRawData
        // Characteristics: CODE | EXECUTE | READ
        b[sh + 36..sh + 40]
            .copy_from_slice(&(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ).to_le_bytes());

        // ── .text raw data: 16 × NOP (0x90) ──────────────────────────────────
        b[DATA_OFFSET..DATA_OFFSET + 16].fill(0x90);

        b
    }

    // ── Happy-path tests ──────────────────────────────────────────────────────

    #[test]
    fn parse_minimal_pe() {
        let data = minimal_pe_bytes();
        let pe = PeFile::parse(&data).expect("parse failed");

        // DOS header
        assert_eq!(pe.dos_header.e_magic, IMAGE_DOS_SIGNATURE);
        assert_eq!(pe.dos_header.e_lfanew, 0x40);

        // PE / COFF header
        assert_eq!(pe.pe_header.machine, IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(pe.pe_header.number_of_sections, 1);
        assert_eq!(
            pe.pe_header.size_of_optional_header as usize,
            OPT_HDR64_FULL_SIZE
        );

        // Optional header
        assert_eq!(pe.optional_header.magic, IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        assert_eq!(pe.optional_header.address_of_entry_point, 0x1000);
        assert_eq!(pe.optional_header.image_base, 0x180000000);
        assert_eq!(pe.optional_header.section_alignment, 0x1000);
        assert_eq!(pe.optional_header.file_alignment, 0x10);
        assert_eq!(pe.optional_header.size_of_image, 0x2000);

        // No imports / no relocs
        assert!(!pe.optional_header.import_dir().is_present());
        assert!(!pe.optional_header.reloc_dir().is_present());
        assert!(pe.imports.is_empty());
        assert!(pe.relocations.is_empty());
    }

    #[test]
    fn section_name_and_raw_data() {
        let data = minimal_pe_bytes();
        let pe = PeFile::parse(&data).expect("parse failed");

        assert_eq!(pe.sections.len(), 1);
        let sec = &pe.sections[0];
        assert_eq!(sec.name(), ".text");
        assert_eq!(sec.virtual_address, 0x1000);
        assert_eq!(sec.virtual_size, 16);
        assert!(sec.characteristics & IMAGE_SCN_CNT_CODE != 0);
        assert!(sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0);

        // get_section_data helper
        let raw = pe
            .get_section_data(".text")
            .expect(".text section not found");
        assert_eq!(raw.len(), 16);
        assert!(raw.iter().all(|&b| b == 0x90), "expected 16 × NOP");

        // get_section_data on missing section
        assert!(pe.get_section_data(".rdata").is_none());
    }

    #[test]
    fn entry_point_offset_correct() {
        let data = minimal_pe_bytes();
        let pe = PeFile::parse(&data).expect("parse failed");

        // EP RVA 0x1000 → .text VA=0x1000 → PointerToRawData=0x170, delta=0
        const DATA_OFFSET: u64 = 0x170; // 368
        assert_eq!(pe.entry_point_offset(), DATA_OFFSET);
    }

    #[test]
    fn data_directories_all_zero() {
        let data = minimal_pe_bytes();
        let pe = PeFile::parse(&data).expect("parse failed");

        for (i, dir) in pe.optional_header.data_directories.iter().enumerate() {
            assert!(
                !dir.is_present(),
                "DataDirectory[{}] should be absent in minimal PE",
                i
            );
        }
    }

    // ── Helper: build a minimal PE32+ with two sections ──────────────────────
    //
    // Layout (N = s2_data.len()):
    //   0x000  DOS header                       64 B
    //   0x040  PE signature                      4 B
    //   0x044  COFF header (2 sections)          20 B
    //   0x058  Optional header PE32+             240 B
    //   0x148  Section header 1 (.text)          40 B
    //   0x170  Section header 2 (custom)         40 B
    //   0x198  … pad to FileAlignment (0x10) …
    //   0x1A0  .text raw data                    16 B  (NOPs)
    //   0x1B0  s2 raw data                       N B
    //
    // All section headers end before 0x1A0, so there is no overlap with raw data.
    fn pe_with_two_sections(s2_name: &[u8; 8], s2_va: u32, s2_data: &[u8]) -> Vec<u8> {
        const PE_OFF: usize = 0x40;
        const COFF_OFF: usize = PE_OFF + PE_SIGNATURE_SIZE; // 0x44
        const OPT_OFF: usize = COFF_OFF + COFF_HEADER_SIZE; // 0x58
        const S1_HDR: usize = OPT_OFF + OPT_HDR64_FULL_SIZE; // 0x148
        const S2_HDR: usize = S1_HDR + SECTION_HEADER_SIZE; // 0x170
        const HDR_END: usize = S2_HDR + SECTION_HEADER_SIZE; // 0x198
        const FILE_ALIGN: usize = 0x10;
        // Align header region to FileAlignment → 0x1A0.
        let hdrs_aligned = (HDR_END + FILE_ALIGN - 1) & !(FILE_ALIGN - 1);
        const S1_LEN: usize = 16;
        let s1_ptr = hdrs_aligned; // 0x1A0
        let s2_ptr = s1_ptr + S1_LEN; // 0x1B0
        let s2_len = s2_data.len();
        let total = s2_ptr + s2_len;

        let mut b = vec![0u8; total];

        // DOS header
        b[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        b[60..64].copy_from_slice(&(PE_OFF as u32).to_le_bytes());

        // PE signature
        b[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");

        // COFF header
        b[COFF_OFF..COFF_OFF + 2]
            .copy_from_slice(&IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        b[COFF_OFF + 2..COFF_OFF + 4].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
        b[COFF_OFF + 16..COFF_OFF + 18]
            .copy_from_slice(&(OPT_HDR64_FULL_SIZE as u16).to_le_bytes());
        b[COFF_OFF + 18..COFF_OFF + 20].copy_from_slice(&0x2022u16.to_le_bytes());

        // Optional header PE32+
        b[OPT_OFF..OPT_OFF + 2]
            .copy_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        b[OPT_OFF + 16..OPT_OFF + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // EP
        b[OPT_OFF + 24..OPT_OFF + 32]
            .copy_from_slice(&0x180000000u64.to_le_bytes()); // ImageBase
        b[OPT_OFF + 32..OPT_OFF + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlign
        b[OPT_OFF + 36..OPT_OFF + 40]
            .copy_from_slice(&(FILE_ALIGN as u32).to_le_bytes()); // FileAlign
        let size_of_image =
            (s2_va as usize + s2_len + 0x1000 - 1) & !(0x1000 - 1);
        b[OPT_OFF + 56..OPT_OFF + 60]
            .copy_from_slice(&(size_of_image as u32).to_le_bytes());
        b[OPT_OFF + 60..OPT_OFF + 64]
            .copy_from_slice(&(hdrs_aligned as u32).to_le_bytes()); // SizeOfHeaders
        b[OPT_OFF + 108..OPT_OFF + 112].copy_from_slice(&16u32.to_le_bytes());
        // DataDirectory: caller wires as needed (all zero here)

        // Section 1 header: .text at VA=0x1000
        b[S1_HDR..S1_HDR + 8].copy_from_slice(b".text\0\0\0");
        b[S1_HDR + 8..S1_HDR + 12].copy_from_slice(&(S1_LEN as u32).to_le_bytes());
        b[S1_HDR + 12..S1_HDR + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[S1_HDR + 16..S1_HDR + 20].copy_from_slice(&(S1_LEN as u32).to_le_bytes());
        b[S1_HDR + 20..S1_HDR + 24].copy_from_slice(&(s1_ptr as u32).to_le_bytes());
        b[S1_HDR + 36..S1_HDR + 40].copy_from_slice(
            &(IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ).to_le_bytes(),
        );
        b[s1_ptr..s1_ptr + S1_LEN].fill(0x90); // 16 × NOP

        // Section 2 header: custom
        b[S2_HDR..S2_HDR + 8].copy_from_slice(s2_name);
        b[S2_HDR + 8..S2_HDR + 12].copy_from_slice(&(s2_len as u32).to_le_bytes());
        b[S2_HDR + 12..S2_HDR + 16].copy_from_slice(&s2_va.to_le_bytes());
        b[S2_HDR + 16..S2_HDR + 20].copy_from_slice(&(s2_len as u32).to_le_bytes());
        b[S2_HDR + 20..S2_HDR + 24].copy_from_slice(&(s2_ptr as u32).to_le_bytes());
        b[s2_ptr..s2_ptr + s2_len].copy_from_slice(s2_data);

        b
    }

    // ── Import table test ─────────────────────────────────────────────────────
    //
    // Build a PE with .text + .idata sections.  .idata contains one
    // IMAGE_IMPORT_DESCRIPTOR referencing:
    //   - Import by name  : "TestFunction"
    //   - Import by ordinal: 42
    #[test]
    fn parse_import_table() {
        // .idata blob layout (all offsets are relative to IDATA_VA):
        //   0: IMAGE_IMPORT_DESCRIPTOR (20 B)
        //  20: null descriptor / terminator (20 B, zero-filled)
        //  40: "KERNEL32.DLL\0"
        //  56: Thunk[0] — RVA of IMAGE_IMPORT_BY_NAME
        //  64: Thunk[1] — ordinal 42
        //  72: Thunk[2] — null terminator
        //  80: IMAGE_IMPORT_BY_NAME { Hint=0 (2 B), "TestFunction\0" }
        const IDATA_VA: u32 = 0x2000;
        const IDATA_RAW_LEN: usize = 128;
        let mut idata = vec![0u8; IDATA_RAW_LEN];

        let to_rva = |local: u32| IDATA_VA + local;
        let desc_off = 0usize;
        let dll_name_off = 40usize;
        let thunk_off = 56usize;
        let by_name_off = 80usize;

        let int_rva = to_rva(thunk_off as u32);
        let dll_name_rva = to_rva(dll_name_off as u32);

        // IMAGE_IMPORT_DESCRIPTOR
        idata[desc_off..desc_off + 4].copy_from_slice(&int_rva.to_le_bytes()); // OrigFirstThunk
        idata[desc_off + 12..desc_off + 16].copy_from_slice(&dll_name_rva.to_le_bytes()); // Name
        idata[desc_off + 16..desc_off + 20].copy_from_slice(&int_rva.to_le_bytes()); // FirstThunk
        // Null terminator at offset 20 (already zero-filled).

        // DLL name
        idata[dll_name_off..dll_name_off + 13].copy_from_slice(b"KERNEL32.DLL\0");

        // Thunk[0]: import by name — RVA of IMAGE_IMPORT_BY_NAME
        let by_name_rva = to_rva(by_name_off as u32) as u64;
        idata[thunk_off..thunk_off + 8].copy_from_slice(&by_name_rva.to_le_bytes());
        // Thunk[1]: import by ordinal 42 (bit 63 set)
        idata[thunk_off + 8..thunk_off + 16].copy_from_slice(&((1u64 << 63) | 42).to_le_bytes());
        // Thunk[2]: null (already zero)

        // IMAGE_IMPORT_BY_NAME: Hint (2 B = 0) + "TestFunction\0"
        idata[by_name_off + 2..by_name_off + 2 + 13].copy_from_slice(b"TestFunction\0");

        // Build a proper 2-section PE (no layout overlap between headers and data).
        let mut pe_data = pe_with_two_sections(b".idata\0\0", IDATA_VA, &idata);

        // Wire DataDirectory[1] (Import Table): VA = IDATA_VA, size = 40 (2 × descriptor).
        const OPT_OFF: usize = 0x58;
        let dd1 = OPT_OFF + OPT_HDR64_FIXED_SIZE + IMAGE_DIRECTORY_ENTRY_IMPORT * DATA_DIR_ENTRY_SIZE;
        pe_data[dd1..dd1 + 4].copy_from_slice(&IDATA_VA.to_le_bytes());
        pe_data[dd1 + 4..dd1 + 8].copy_from_slice(&40u32.to_le_bytes());

        // ── Assertions ────────────────────────────────────────────────────────
        let pe = PeFile::parse(&pe_data).expect("parse with imports failed");
        assert_eq!(pe.sections.len(), 2);
        assert!(pe.optional_header.import_dir().is_present());
        assert_eq!(pe.imports.len(), 1);

        let imp = &pe.imports[0];
        assert_eq!(imp.dll_name, "KERNEL32.DLL");
        assert_eq!(imp.functions.len(), 2);

        let f0 = &imp.functions[0];
        assert!(f0.ordinal.is_none());
        assert_eq!(f0.name.as_deref(), Some("TestFunction"));

        let f1 = &imp.functions[1];
        assert_eq!(f1.ordinal, Some(42));
        assert!(f1.name.is_none());
    }

    // ── Base-relocation table test ────────────────────────────────────────────
    //
    // Build a PE with .text + .reloc sections.  .reloc contains one
    // IMAGE_BASE_RELOCATION block: page_rva=0x1000, DIR64 at 0x10 + ABSOLUTE pad.
    #[test]
    fn parse_base_relocs() {
        const RELOC_VA: u32 = 0x3000;
        let size_of_block: u32 = 8 + 4; // header + 2 entries × 2 B

        let mut reloc_data = vec![0u8; 64];
        reloc_data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // page_rva
        reloc_data[4..8].copy_from_slice(&size_of_block.to_le_bytes());
        let e0: u16 = ((IMAGE_REL_BASED_DIR64 as u16) << 12) | 0x010;
        reloc_data[8..10].copy_from_slice(&e0.to_le_bytes());
        let e1: u16 = (IMAGE_REL_BASED_ABSOLUTE as u16) << 12;
        reloc_data[10..12].copy_from_slice(&e1.to_le_bytes());

        let mut pe_data = pe_with_two_sections(b".reloc\0\0", RELOC_VA, &reloc_data);

        // Wire DataDirectory[5] (BaseReloc).
        const OPT_OFF: usize = 0x58;
        let dd5 = OPT_OFF
            + OPT_HDR64_FIXED_SIZE
            + IMAGE_DIRECTORY_ENTRY_BASERELOC * DATA_DIR_ENTRY_SIZE;
        pe_data[dd5..dd5 + 4].copy_from_slice(&RELOC_VA.to_le_bytes());
        pe_data[dd5 + 4..dd5 + 8].copy_from_slice(&size_of_block.to_le_bytes());

        let pe = PeFile::parse(&pe_data).expect("parse with relocs failed");
        assert!(pe.optional_header.reloc_dir().is_present());
        assert_eq!(pe.relocations.len(), 1);

        let block = &pe.relocations[0];
        assert_eq!(block.page_rva, 0x1000);
        assert_eq!(block.entries.len(), 2);
        assert_eq!(block.entries[0].typ, IMAGE_REL_BASED_DIR64);
        assert_eq!(block.entries[0].offset, 0x010);
        assert_eq!(block.entries[1].typ, IMAGE_REL_BASED_ABSOLUTE);
    }

    // ── Rejection tests ───────────────────────────────────────────────────────

    #[test]
    fn reject_bad_mz() {
        let mut data = minimal_pe_bytes();
        data[0..2].copy_from_slice(&0x0000u16.to_le_bytes());
        let err = PeFile::parse(&data).unwrap_err();
        assert!(err.to_string().contains("DOS magic"), "{err}");
    }

    #[test]
    fn reject_bad_pe_signature() {
        let mut data = minimal_pe_bytes();
        // Overwrite "PE\0\0" with "XX\0\0".
        data[0x40..0x44].copy_from_slice(b"XX\0\0");
        let err = PeFile::parse(&data).unwrap_err();
        assert!(err.to_string().contains("PE signature"), "{err}");
    }

    #[test]
    fn reject_non_amd64() {
        let mut data = minimal_pe_bytes();
        const COFF_OFFSET: usize = 0x44;
        data[COFF_OFFSET..COFF_OFFSET + 2].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
        let err = PeFile::parse(&data).unwrap_err();
        assert!(err.to_string().contains("machine"), "{err}");
    }

    #[test]
    fn reject_pe32_not_pe32plus() {
        let mut data = minimal_pe_bytes();
        const OPT_OFFSET: usize = 0x58;
        data[OPT_OFFSET..OPT_OFFSET + 2].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
        let err = PeFile::parse(&data).unwrap_err();
        assert!(err.to_string().contains("optional-header magic"), "{err}");
    }

    #[test]
    fn reject_too_short() {
        let data = vec![0u8; 16];
        assert!(PeFile::parse(&data).is_err());
    }

    #[test]
    fn reject_truncated_optional_header() {
        let mut data = minimal_pe_bytes();
        const COFF_OFFSET: usize = 0x44;
        // Claim SizeOfOptionalHeader = 50 (< 240).
        data[COFF_OFFSET + 16..COFF_OFFSET + 18].copy_from_slice(&50u16.to_le_bytes());
        let err = PeFile::parse(&data).unwrap_err();
        assert!(err.to_string().contains("optional header too small"), "{err}");
    }
}
