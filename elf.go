package elfparser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
)

// ELFInfo holds parsed ELF file information
type ELFInfo struct {
	Class        string // 32 or 64 bit
	Endianness   string
	OSABI        string
	Type         string
	Machine      string
	EntryPoint   uint64
	Sections     []SectionInfo
	Symbols      []string
	DynLibs      []string
	IsPacked     bool
	PackerHints  []string
	Interpreter  string
}

// SectionInfo holds ELF section details
type SectionInfo struct {
	Name    string
	Type    string
	Size    uint64
	Offset  uint64
	Entropy float64
	Flags   []string
}

// ELF identification bytes
const (
	elfMagic    = "\x7fELF"
	elfClass32  = 1
	elfClass64  = 2
	elfData2LSB = 1
	elfData2MSB = 2
)

// Parse reads and parses an ELF file
func Parse(filepath string) (*ELFInfo, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("fayl oxuna bilmədi: %w", err)
	}

	if len(data) < 64 {
		return nil, fmt.Errorf("fayl ELF üçün çox kiçikdir")
	}

	// Check magic
	if string(data[0:4]) != elfMagic {
		return nil, fmt.Errorf("etibarsız ELF imzası")
	}

	info := &ELFInfo{}

	// EI_CLASS
	switch data[4] {
	case elfClass32:
		info.Class = "ELF32"
	case elfClass64:
		info.Class = "ELF64"
	default:
		return nil, fmt.Errorf("naməlum ELF sinfi: %d", data[4])
	}

	// EI_DATA (endianness)
	var order binary.ByteOrder
	switch data[5] {
	case elfData2LSB:
		info.Endianness = "Little Endian"
		order = binary.LittleEndian
	case elfData2MSB:
		info.Endianness = "Big Endian"
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("naməlum endianness: %d", data[5])
	}

	// EI_OSABI
	info.OSABI = osabiString(data[7])

	if data[4] == elfClass64 {
		return parse64(data, order, info)
	}
	return parse32(data, order, info)
}

func parse64(data []byte, order binary.ByteOrder, info *ELFInfo) (*ELFInfo, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("ELF64 başlığı üçün kifayət qədər bayt yoxdur")
	}

	reader := bytes.NewReader(data[16:])

	var eType, eMachine uint16
	var eEntry uint64
	var ePhoff, eShoff uint64
	var ePhentsize, ePhnum, eShentsize, eShnum, eShstrndx uint16

	binary.Read(reader, order, &eType)
	binary.Read(reader, order, &eMachine)
	reader.Seek(4, 1) // e_version
	binary.Read(reader, order, &eEntry)
	binary.Read(reader, order, &ePhoff)
	binary.Read(reader, order, &eShoff)
	reader.Seek(4, 1) // e_flags
	reader.Seek(2, 1) // e_ehsize
	binary.Read(reader, order, &ePhentsize)
	binary.Read(reader, order, &ePhnum)
	binary.Read(reader, order, &eShentsize)
	binary.Read(reader, order, &eShnum)
	binary.Read(reader, order, &eShstrndx)

	info.Type = typeString(eType)
	info.Machine = machineString(eMachine)
	info.EntryPoint = eEntry

	// Parse section headers
	if eShoff > 0 && eShnum > 0 && int(eShoff+uint64(eShnum)*uint64(eShentsize)) <= len(data) {
		// Get string table
		var strtab []byte
		if eShstrndx < eShnum {
			strtabOff := eShoff + uint64(eShstrndx)*uint64(eShentsize)
			if int(strtabOff+64) <= len(data) {
				r := bytes.NewReader(data[strtabOff:])
				var shName uint32
				var shType uint32
				var shFlags, shAddr, shOffset, shSize uint64
				binary.Read(r, order, &shName)
				binary.Read(r, order, &shType)
				binary.Read(r, order, &shFlags)
				binary.Read(r, order, &shAddr)
				binary.Read(r, order, &shOffset)
				binary.Read(r, order, &shSize)

				if int(shOffset+shSize) <= len(data) {
					strtab = data[shOffset : shOffset+shSize]
				}
			}
		}

		for i := uint16(0); i < eShnum; i++ {
			off := eShoff + uint64(i)*uint64(eShentsize)
			if int(off+64) > len(data) {
				break
			}

			r := bytes.NewReader(data[off:])
			var shName uint32
			var shType uint32
			var shFlags, shAddr, shOffset, shSize uint64
			binary.Read(r, order, &shName)
			binary.Read(r, order, &shType)
			binary.Read(r, order, &shFlags)
			binary.Read(r, order, &shAddr)
			binary.Read(r, order, &shOffset)
			binary.Read(r, order, &shSize)

			name := readCString(strtab, int(shName))

			sec := SectionInfo{
				Name:   name,
				Type:   sectionTypeString(shType),
				Size:   shSize,
				Offset: shOffset,
				Flags:  parseSectionFlags(shFlags),
			}

			// Calc section entropy
			if shSize > 0 && shType != 8 && int(shOffset+shSize) <= len(data) {
				sec.Entropy = calcEntropy(data[shOffset : shOffset+shSize])
			}

			info.Sections = append(info.Sections, sec)
		}
	}

	// Parse program headers for INTERP and DYNAMIC
	if ePhoff > 0 && ePhnum > 0 {
		for i := uint16(0); i < ePhnum; i++ {
			off := ePhoff + uint64(i)*uint64(ePhentsize)
			if int(off+56) > len(data) {
				break
			}
			r := bytes.NewReader(data[off:])
			var pType uint32
			binary.Read(r, order, &pType)

			if pType == 3 { // PT_INTERP
				var pFlags uint32
				var pOffset, pVaddr, pPaddr, pFilesz, pMemsz uint64
				binary.Read(r, order, &pFlags)
				binary.Read(r, order, &pOffset)
				binary.Read(r, order, &pVaddr)
				binary.Read(r, order, &pPaddr)
				binary.Read(r, order, &pFilesz)
				binary.Read(r, order, &pMemsz)

				if pFilesz > 0 && int(pOffset+pFilesz) <= len(data) {
					info.Interpreter = readCString(data[pOffset:pOffset+pFilesz], 0)
				}
			}
		}
	}

	// Extract dynamic libraries from .dynstr + .dynamic
	info.DynLibs = extractDynLibs(data, info.Sections, order)

	// Detect packing
	info.detectPacking()

	return info, nil
}

func parse32(data []byte, order binary.ByteOrder, info *ELFInfo) (*ELFInfo, error) {
	if len(data) < 52 {
		return nil, fmt.Errorf("ELF32 başlığı üçün kifayət qədər bayt yoxdur")
	}

	reader := bytes.NewReader(data[16:])

	var eType, eMachine uint16
	var eEntry uint32
	var ePhoff, eShoff uint32
	var ePhentsize, ePhnum, eShentsize, eShnum, eShstrndx uint16

	binary.Read(reader, order, &eType)
	binary.Read(reader, order, &eMachine)
	reader.Seek(4, 1)
	binary.Read(reader, order, &eEntry)
	binary.Read(reader, order, &ePhoff)
	binary.Read(reader, order, &eShoff)
	reader.Seek(4, 1)
	reader.Seek(2, 1)
	binary.Read(reader, order, &ePhentsize)
	binary.Read(reader, order, &ePhnum)
	binary.Read(reader, order, &eShentsize)
	binary.Read(reader, order, &eShnum)
	binary.Read(reader, order, &eShstrndx)

	info.Type = typeString(eType)
	info.Machine = machineString(eMachine)
	info.EntryPoint = uint64(eEntry)

	// Parse section headers for ELF32
	if eShoff > 0 && eShnum > 0 && int(eShoff)+int(eShnum)*int(eShentsize) <= len(data) {
		var strtab []byte
		if eShstrndx < eShnum {
			strtabOff := uint64(eShoff) + uint64(eShstrndx)*uint64(eShentsize)
			if int(strtabOff+40) <= len(data) {
				r := bytes.NewReader(data[strtabOff:])
				var shName, shType, shFlags, shAddr, shOffset, shSize uint32
				binary.Read(r, order, &shName)
				binary.Read(r, order, &shType)
				binary.Read(r, order, &shFlags)
				binary.Read(r, order, &shAddr)
				binary.Read(r, order, &shOffset)
				binary.Read(r, order, &shSize)
				if int(shOffset)+int(shSize) <= len(data) {
					strtab = data[shOffset : shOffset+shSize]
				}
			}
		}

		for i := uint16(0); i < eShnum; i++ {
			off := uint64(eShoff) + uint64(i)*uint64(eShentsize)
			if int(off+40) > len(data) {
				break
			}
			r := bytes.NewReader(data[off:])
			var shName, shType, shFlags, shAddr, shOffset, shSize uint32
			binary.Read(r, order, &shName)
			binary.Read(r, order, &shType)
			binary.Read(r, order, &shFlags)
			binary.Read(r, order, &shAddr)
			binary.Read(r, order, &shOffset)
			binary.Read(r, order, &shSize)

			name := readCString(strtab, int(shName))
			sec := SectionInfo{
				Name:   name,
				Type:   sectionTypeString(shType),
				Size:   uint64(shSize),
				Offset: uint64(shOffset),
				Flags:  parseSectionFlags(uint64(shFlags)),
			}
			if shSize > 0 && shType != 8 && int(shOffset)+int(shSize) <= len(data) {
				sec.Entropy = calcEntropy(data[shOffset : shOffset+shSize])
			}
			info.Sections = append(info.Sections, sec)
		}
	}

	info.detectPacking()
	return info, nil
}

func extractDynLibs(data []byte, sections []SectionInfo, order binary.ByteOrder) []string {
	// Find .dynstr and .dynamic sections
	var dynstrData []byte
	var dynamicData []byte

	for _, sec := range sections {
		if sec.Name == ".dynstr" && sec.Size > 0 && int(sec.Offset+sec.Size) <= len(data) {
			dynstrData = data[sec.Offset : sec.Offset+sec.Size]
		}
		if sec.Name == ".dynamic" && sec.Size > 0 && int(sec.Offset+sec.Size) <= len(data) {
			dynamicData = data[sec.Offset : sec.Offset+sec.Size]
		}
	}

	if dynstrData == nil || dynamicData == nil {
		return nil
	}

	var libs []string
	// DT_NEEDED = 1, each entry is 16 bytes (64-bit) or 8 bytes (32-bit)
	// Try 64-bit first
	entrySize := 16
	if len(dynamicData)%16 != 0 && len(dynamicData)%8 == 0 {
		entrySize = 8
	}

	for i := 0; i+entrySize <= len(dynamicData); i += entrySize {
		r := bytes.NewReader(dynamicData[i:])
		var tag, val uint64
		if entrySize == 16 {
			var t, v int64
			binary.Read(r, order, &t)
			binary.Read(r, order, &v)
			tag = uint64(t)
			val = uint64(v)
		} else {
			var t, v int32
			binary.Read(r, order, &t)
			binary.Read(r, order, &v)
			tag = uint64(t)
			val = uint64(v)
		}

		if tag == 0 { // DT_NULL
			break
		}
		if tag == 1 { // DT_NEEDED
			name := readCString(dynstrData, int(val))
			if name != "" {
				libs = append(libs, name)
			}
		}
	}
	return libs
}

func (e *ELFInfo) detectPacking() {
	for _, sec := range e.Sections {
		if sec.Entropy > 7.0 && sec.Size > 1024 {
			e.IsPacked = true
			e.PackerHints = append(e.PackerHints, fmt.Sprintf("Yüksək entropiya: %s (%.2f)", sec.Name, sec.Entropy))
		}
	}

	packerSections := map[string]string{
		"UPX!": "UPX", ".upx": "UPX",
	}
	for _, sec := range e.Sections {
		if packer, ok := packerSections[sec.Name]; ok {
			e.IsPacked = true
			e.PackerHints = append(e.PackerHints, fmt.Sprintf("Paketləyici bölmə: %s → %s", sec.Name, packer))
		}
	}
}

func readCString(data []byte, offset int) string {
	if offset < 0 || offset >= len(data) {
		return ""
	}
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[offset:end])
}

func calcEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	total := float64(len(data))
	var ent float64
	for _, c := range freq {
		if c > 0 {
			p := c / total
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

func osabiString(v byte) string {
	switch v {
	case 0:
		return "UNIX System V"
	case 3:
		return "Linux"
	case 6:
		return "Solaris"
	case 9:
		return "FreeBSD"
	default:
		return fmt.Sprintf("Naməlum (0x%X)", v)
	}
}

func typeString(t uint16) string {
	switch t {
	case 1:
		return "Relocatable (ET_REL)"
	case 2:
		return "Executable (ET_EXEC)"
	case 3:
		return "Shared Object (ET_DYN)"
	case 4:
		return "Core Dump (ET_CORE)"
	default:
		return fmt.Sprintf("Naməlum (%d)", t)
	}
}

func machineString(m uint16) string {
	switch m {
	case 3:
		return "Intel 80386 (i386)"
	case 8:
		return "MIPS"
	case 20:
		return "PowerPC"
	case 40:
		return "ARM"
	case 62:
		return "AMD64 (x86_64)"
	case 183:
		return "AArch64 (ARM64)"
	case 243:
		return "RISC-V"
	default:
		return fmt.Sprintf("Naməlum (0x%X)", m)
	}
}

func sectionTypeString(t uint32) string {
	switch t {
	case 0:
		return "NULL"
	case 1:
		return "PROGBITS"
	case 2:
		return "SYMTAB"
	case 3:
		return "STRTAB"
	case 4:
		return "RELA"
	case 5:
		return "HASH"
	case 6:
		return "DYNAMIC"
	case 7:
		return "NOTE"
	case 8:
		return "NOBITS"
	case 9:
		return "REL"
	case 11:
		return "DYNSYM"
	default:
		return fmt.Sprintf("0x%X", t)
	}
}

func parseSectionFlags(f uint64) []string {
	var flags []string
	if f&0x1 != 0 {
		flags = append(flags, "WRITE")
	}
	if f&0x2 != 0 {
		flags = append(flags, "ALLOC")
	}
	if f&0x4 != 0 {
		flags = append(flags, "EXECINSTR")
	}
	return flags
}
