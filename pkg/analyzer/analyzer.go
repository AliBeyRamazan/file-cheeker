package analyzer

import (
	"fmt"
	"os"
)

// FileType represents the detected file type
type FileType int

const (
	Unknown FileType = iota
	PE
	ELF
	MachO
	PDF
	ZIP
	Script
)

// DetectFileType reads magic bytes to determine file type
func DetectFileType(filepath string) (FileType, string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return Unknown, "", err
	}
	defer f.Close()

	header := make([]byte, 16)
	n, err := f.Read(header)
	if err != nil || n < 4 {
		return Unknown, "Naməlum", fmt.Errorf("fayl başlığı oxuna bilmədi")
	}

	// PE: MZ header
	if header[0] == 'M' && header[1] == 'Z' {
		return PE, "PE (Windows Executable)", nil
	}

	// ELF: \x7fELF
	if header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return ELF, "ELF (Linux/Unix Executable)", nil
	}

	// Mach-O
	if (header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && (header[3] == 0xCE || header[3] == 0xCF)) ||
		(header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) ||
		(header[0] == 0xCE && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) {
		return MachO, "Mach-O (macOS Executable)", nil
	}

	// PDF
	if header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F' {
		return PDF, "PDF Sənədi", nil
	}

	// ZIP (also covers DOCX, XLSX, JAR, APK)
	if header[0] == 'P' && header[1] == 'K' && header[2] == 0x03 && header[3] == 0x04 {
		return ZIP, "ZIP/Arxiv (DOCX, APK, JAR ola bilər)", nil
	}

	// Script detection
	if header[0] == '#' && header[1] == '!' {
		return Script, "Script (Shebang)", nil
	}

	return Unknown, "Naməlum fayl növü", nil
}

// FormatSize returns human-readable file size
func FormatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
