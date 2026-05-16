package peparser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"time"
)

// PEInfo holds parsed PE file information
type PEInfo struct {
	Machine            string
	TimeDateStamp      time.Time
	NumberOfSections   uint16
	Characteristics    []string
	Subsystem          string
	DLLCharacteristics []string
	EntryPoint         uint32
	ImageBase          uint64
	Sections           []SectionInfo
	Imports            []ImportInfo
	Exports            []string
	IsPacked           bool
	PackerHints        []string
}

// SectionInfo holds PE section details
type SectionInfo struct {
	Name            string
	VirtualSize     uint32
	VirtualAddress  uint32
	RawSize         uint32
	Entropy         float64
	Characteristics []string
}

// ImportInfo holds imported DLL and function info
type ImportInfo struct {
	DLLName   string
	Functions []string
}

// DOS Header
type dosHeader struct {
	Magic    uint16
	_        [58]byte
	LFANew   uint32
}

// PE Signature + COFF Header
type coffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// Optional Header (PE32)
type optionalHeader32 struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	BaseOfData              uint32
	ImageBase               uint32
	SectionAlignment        uint32
	FileAlignment           uint32
	_                       [16]byte
	SizeOfImage             uint32
	SizeOfHeaders           uint32
	CheckSum                uint32
	Subsystem               uint16
	DLLCharacteristics      uint16
	_                       [16]byte
	NumberOfRvaAndSizes     uint32
}

// Optional Header (PE32+)
type optionalHeader64 struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	ImageBase               uint64
	SectionAlignment        uint32
	FileAlignment           uint32
	_                       [16]byte
	SizeOfImage             uint32
	SizeOfHeaders           uint32
	CheckSum                uint32
	Subsystem               uint16
	DLLCharacteristics      uint16
	_                       [32]byte
	NumberOfRvaAndSizes     uint32
}

// Section Header
type sectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

// Data Directory
type dataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// Import Directory Entry
type importDirectoryEntry struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	NameRVA            uint32
	FirstThunk         uint32
}

// Parse reads and parses a PE file
func Parse(filepath string) (*PEInfo, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("fayl oxuna bilmədi: %w", err)
	}

	reader := bytes.NewReader(data)

	// Parse DOS Header
	var dos dosHeader
	if err := binary.Read(reader, binary.LittleEndian, &dos); err != nil {
		return nil, fmt.Errorf("DOS başlığı oxuna bilmədi: %w", err)
	}

	if dos.Magic != 0x5A4D {
		return nil, fmt.Errorf("etibarsız DOS imzası: 0x%X (gözlənilən: 0x5A4D)", dos.Magic)
	}

	// Seek to PE header
	reader.Seek(int64(dos.LFANew), 0)

	// Read PE signature
	var peSignature uint32
	if err := binary.Read(reader, binary.LittleEndian, &peSignature); err != nil {
		return nil, fmt.Errorf("PE imzası oxuna bilmədi: %w", err)
	}
	if peSignature != 0x00004550 {
		return nil, fmt.Errorf("etibarsız PE imzası: 0x%X", peSignature)
	}

	// Parse COFF Header
	var coff coffHeader
	if err := binary.Read(reader, binary.LittleEndian, &coff); err != nil {
		return nil, fmt.Errorf("COFF başlığı oxuna bilmədi: %w", err)
	}

	info := &PEInfo{
		Machine:          machineString(coff.Machine),
		TimeDateStamp:    time.Unix(int64(coff.TimeDateStamp), 0),
		NumberOfSections: coff.NumberOfSections,
		Characteristics:  parseCharacteristics(coff.Characteristics),
	}

	// Parse Optional Header
	var optMagic uint16
	currentPos, _ := reader.Seek(0, 1)
	binary.Read(bytes.NewReader(data[currentPos:currentPos+2]), binary.LittleEndian, &optMagic)

	var entryPoint uint32
	var imageBase uint64
	var subsystem uint16
	var dllChars uint16
	var numRvaAndSizes uint32
	if optMagic == 0x20B { // PE32+
		var opt optionalHeader64
		if err := binary.Read(reader, binary.LittleEndian, &opt); err != nil {
			return nil, fmt.Errorf("Optional başlıq (PE32+) oxuna bilmədi: %w", err)
		}
		entryPoint = opt.AddressOfEntryPoint
		imageBase = opt.ImageBase
		subsystem = opt.Subsystem
		dllChars = opt.DLLCharacteristics
		numRvaAndSizes = opt.NumberOfRvaAndSizes
	} else { // PE32
		var opt optionalHeader32
		if err := binary.Read(reader, binary.LittleEndian, &opt); err != nil {
			return nil, fmt.Errorf("Optional başlıq (PE32) oxuna bilmədi: %w", err)
		}
		entryPoint = opt.AddressOfEntryPoint
		imageBase = uint64(opt.ImageBase)
		subsystem = opt.Subsystem
		dllChars = opt.DLLCharacteristics
		numRvaAndSizes = opt.NumberOfRvaAndSizes
	}

	info.EntryPoint = entryPoint
	info.ImageBase = imageBase
	info.Subsystem = subsystemString(subsystem)
	info.DLLCharacteristics = parseDLLCharacteristics(dllChars)

	// Read data directories from current position
	dataDirs := make([]dataDirectory, numRvaAndSizes)
	for i := uint32(0); i < numRvaAndSizes && i < 16; i++ {
		binary.Read(reader, binary.LittleEndian, &dataDirs[i])
	}

	// Seek to exact section header offset: lfanew + 4(PEsig) + 20(COFF) + SizeOfOptionalHeader
	sectionOffset := int64(dos.LFANew) + 4 + 20 + int64(coff.SizeOfOptionalHeader)
	reader.Seek(sectionOffset, 0)

	// Parse Sections
	for i := uint16(0); i < coff.NumberOfSections; i++ {
		var sec sectionHeader
		if err := binary.Read(reader, binary.LittleEndian, &sec); err != nil {
			break
		}

		name := string(bytes.TrimRight(sec.Name[:], "\x00"))
		secInfo := SectionInfo{
			Name:            name,
			VirtualSize:     sec.VirtualSize,
			VirtualAddress:  sec.VirtualAddress,
			RawSize:         sec.SizeOfRawData,
			Characteristics: parseSectionCharacteristics(sec.Characteristics),
		}

		// Calculate section entropy
		if sec.SizeOfRawData > 0 && int(sec.PointerToRawData+sec.SizeOfRawData) <= len(data) {
			secData := data[sec.PointerToRawData : sec.PointerToRawData+sec.SizeOfRawData]
			secInfo.Entropy = calcEntropy(secData)
		}

		info.Sections = append(info.Sections, secInfo)
	}

	// Parse Imports (Data Directory index 1)
	if len(dataDirs) > 1 && dataDirs[1].VirtualAddress != 0 {
		importRVA := dataDirs[1].VirtualAddress
		importOffset := rvaToOffset(importRVA, data, coff.NumberOfSections, dos.LFANew)
		if importOffset > 0 {
			info.Imports = parseImports(data, importOffset, coff.NumberOfSections, dos.LFANew)
		}
	}

	// Parse Exports (Data Directory index 0)
	if len(dataDirs) > 0 && dataDirs[0].VirtualAddress != 0 {
		exportRVA := dataDirs[0].VirtualAddress
		exportOffset := rvaToOffset(exportRVA, data, coff.NumberOfSections, dos.LFANew)
		if exportOffset > 0 {
			info.Exports = parseExports(data, exportOffset, coff.NumberOfSections, dos.LFANew)
		}
	}

	// Detect packing
	info.detectPacking()

	return info, nil
}

// rvaToOffset converts RVA to file offset using section table
func rvaToOffset(rva uint32, data []byte, numSections uint16, lfaNew uint32) int {
	// Section headers start after PE sig (4) + COFF header (20) + optional header size
	reader := bytes.NewReader(data)
	reader.Seek(int64(lfaNew+4), 0)

	var coff coffHeader
	binary.Read(reader, binary.LittleEndian, &coff)

	secStart := int64(lfaNew) + 4 + 20 + int64(coff.SizeOfOptionalHeader)

	for i := uint16(0); i < numSections; i++ {
		offset := secStart + int64(i)*40
		if int(offset+40) > len(data) {
			break
		}
		var sec sectionHeader
		binary.Read(bytes.NewReader(data[offset:]), binary.LittleEndian, &sec)

		secEnd := sec.VirtualAddress + sec.SizeOfRawData
		if sec.SizeOfRawData == 0 {
			secEnd = sec.VirtualAddress + sec.VirtualSize
		}

		if rva >= sec.VirtualAddress && rva < secEnd {
			return int(rva - sec.VirtualAddress + sec.PointerToRawData)
		}
	}
	return 0
}

func readStringAtOffset(data []byte, offset int) string {
	if offset <= 0 || offset >= len(data) {
		return ""
	}
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}
	if end-offset > 256 {
		return string(data[offset : offset+256])
	}
	return string(data[offset:end])
}

func parseImports(data []byte, offset int, numSections uint16, lfaNew uint32) []ImportInfo {
	var imports []ImportInfo

	for i := 0; i < 256; i++ { // max 256 DLLs
		entryOffset := offset + i*20
		if entryOffset+20 > len(data) {
			break
		}

		var entry importDirectoryEntry
		binary.Read(bytes.NewReader(data[entryOffset:]), binary.LittleEndian, &entry)

		// NULL entry terminates
		if entry.NameRVA == 0 && entry.OriginalFirstThunk == 0 {
			break
		}

		nameOffset := rvaToOffset(entry.NameRVA, data, numSections, lfaNew)
		dllName := readStringAtOffset(data, nameOffset)
		if dllName == "" {
			continue
		}

		imp := ImportInfo{DLLName: dllName}

		// Read Import Name Table (INT) via OriginalFirstThunk
		thunkRVA := entry.OriginalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = entry.FirstThunk
		}

		thunkOffset := rvaToOffset(thunkRVA, data, numSections, lfaNew)
		if thunkOffset > 0 {
			for j := 0; j < 512; j++ {
				pos := thunkOffset + j*4
				if pos+4 > len(data) {
					break
				}
				var thunkValue uint32
				binary.Read(bytes.NewReader(data[pos:]), binary.LittleEndian, &thunkValue)

				if thunkValue == 0 {
					break
				}

				// Check if import by ordinal (high bit set)
				if thunkValue&0x80000000 != 0 {
					imp.Functions = append(imp.Functions, fmt.Sprintf("Ordinal#%d", thunkValue&0x7FFFFFFF))
				} else {
					// Import by name - hint/name table entry
					hintOffset := rvaToOffset(thunkValue, data, numSections, lfaNew)
					if hintOffset > 0 && hintOffset+2 < len(data) {
						funcName := readStringAtOffset(data, hintOffset+2)
						if funcName != "" {
							imp.Functions = append(imp.Functions, funcName)
						}
					}
				}
			}
		}

		imports = append(imports, imp)
	}
	return imports
}

func parseExports(data []byte, offset int, numSections uint16, lfaNew uint32) []string {
	if offset+40 > len(data) {
		return nil
	}

	// Export directory table
	var numberOfNames uint32
	var addressOfNames uint32

	binary.Read(bytes.NewReader(data[offset+24:]), binary.LittleEndian, &numberOfNames)
	binary.Read(bytes.NewReader(data[offset+32:]), binary.LittleEndian, &addressOfNames)

	namesOffset := rvaToOffset(addressOfNames, data, numSections, lfaNew)
	if namesOffset <= 0 {
		return nil
	}

	var exports []string
	for i := uint32(0); i < numberOfNames && i < 1024; i++ {
		pos := namesOffset + int(i*4)
		if pos+4 > len(data) {
			break
		}
		var nameRVA uint32
		binary.Read(bytes.NewReader(data[pos:]), binary.LittleEndian, &nameRVA)

		nameOff := rvaToOffset(nameRVA, data, numSections, lfaNew)
		name := readStringAtOffset(data, nameOff)
		if name != "" {
			exports = append(exports, name)
		}
	}
	return exports
}

func (p *PEInfo) detectPacking() {
	for _, sec := range p.Sections {
		if sec.Entropy > 7.0 {
			p.IsPacked = true
			p.PackerHints = append(p.PackerHints, fmt.Sprintf("Yüksək entropiya bölmə: %s (%.2f)", sec.Name, sec.Entropy))
		}
		if sec.VirtualSize > 0 && sec.RawSize > 0 {
			ratio := float64(sec.VirtualSize) / float64(sec.RawSize)
			if ratio > 10 {
				p.IsPacked = true
				p.PackerHints = append(p.PackerHints, fmt.Sprintf("Virtual/Raw nisbəti çox yüksək: %s (%.1fx)", sec.Name, ratio))
			}
		}
	}

	// Known packer section names
	packerSections := map[string]string{
		"UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
		".aspack": "ASPack", ".adata": "ASPack",
		".nsp0": "NsPack", ".nsp1": "NsPack",
		".packed": "Ümumi paketləyici",
		".themida": "Themida",
		".vmp0": "VMProtect", ".vmp1": "VMProtect",
	}

	for _, sec := range p.Sections {
		if packer, ok := packerSections[sec.Name]; ok {
			p.IsPacked = true
			p.PackerHints = append(p.PackerHints, fmt.Sprintf("Paketləyici bölmə adı: %s → %s", sec.Name, packer))
		}
	}
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
	var entropy float64
	for _, count := range freq {
		if count > 0 {
			p := count / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func machineString(m uint16) string {
	switch m {
	case 0x14C:
		return "i386 (32-bit)"
	case 0x8664:
		return "AMD64 (64-bit)"
	case 0x1C0:
		return "ARM"
	case 0xAA64:
		return "ARM64"
	default:
		return fmt.Sprintf("Naməlum (0x%X)", m)
	}
}

func subsystemString(s uint16) string {
	switch s {
	case 1:
		return "Native"
	case 2:
		return "Windows GUI"
	case 3:
		return "Windows Console"
	case 5:
		return "OS/2 Console"
	case 7:
		return "POSIX Console"
	case 10:
		return "EFI Application"
	case 14:
		return "Xbox"
	default:
		return fmt.Sprintf("Naməlum (%d)", s)
	}
}

func parseCharacteristics(c uint16) []string {
	var chars []string
	flags := map[uint16]string{
		0x0001: "RELOCS_STRIPPED",
		0x0002: "EXECUTABLE_IMAGE",
		0x0004: "LINE_NUMS_STRIPPED",
		0x0020: "LARGE_ADDRESS_AWARE",
		0x0100: "32BIT_MACHINE",
		0x0200: "DEBUG_STRIPPED",
		0x2000: "DLL",
	}
	for bit, name := range flags {
		if c&bit != 0 {
			chars = append(chars, name)
		}
	}
	return chars
}

func parseDLLCharacteristics(c uint16) []string {
	var chars []string
	flags := map[uint16]string{
		0x0020: "HIGH_ENTROPY_VA",
		0x0040: "DYNAMIC_BASE (ASLR)",
		0x0080: "FORCE_INTEGRITY",
		0x0100: "NX_COMPAT (DEP)",
		0x0200: "NO_ISOLATION",
		0x0400: "NO_SEH",
		0x0800: "NO_BIND",
		0x1000: "APPCONTAINER",
		0x2000: "WDM_DRIVER",
		0x4000: "GUARD_CF",
		0x8000: "TERMINAL_SERVER_AWARE",
	}
	for bit, name := range flags {
		if c&bit != 0 {
			chars = append(chars, name)
		}
	}
	return chars
}

func parseSectionCharacteristics(c uint32) []string {
	var chars []string
	flags := map[uint32]string{
		0x00000020: "CODE",
		0x00000040: "INITIALIZED_DATA",
		0x00000080: "UNINITIALIZED_DATA",
		0x20000000: "EXECUTE",
		0x40000000: "READ",
		0x80000000: "WRITE",
	}
	for bit, name := range flags {
		if c&bit != 0 {
			chars = append(chars, name)
		}
	}
	return chars
}
