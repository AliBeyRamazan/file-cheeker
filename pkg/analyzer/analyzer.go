package analyzer

import (
	"fmt"
	"os"
)

// FileType represents the detected file type.
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

// DetectFileType reads magic bytes to determine file type.
func DetectFileType(filepath string) (FileType, string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return Unknown, "", err
	}
	defer f.Close()

	header := make([]byte, 16)
	n, err := f.Read(header)
	if err != nil || n < 4 {
		return Unknown, "Bilinmiyor", fmt.Errorf("dosya basligi okunamadi")
	}

	if header[0] == 'M' && header[1] == 'Z' {
		return PE, "PE (Windows executable)", nil
	}

	if header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F' {
		return ELF, "ELF (Linux/Unix executable)", nil
	}

	if (header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && (header[3] == 0xCE || header[3] == 0xCF)) ||
		(header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) ||
		(header[0] == 0xCE && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE) {
		return MachO, "Mach-O (macOS executable)", nil
	}

	if header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F' {
		return PDF, "PDF dokumani", nil
	}

	if header[0] == 'P' && header[1] == 'K' && header[2] == 0x03 && header[3] == 0x04 {
		return ZIP, "ZIP/arsiv (DOCX, APK veya JAR olabilir)", nil
	}

	if header[0] == '#' && header[1] == '!' {
		return Script, "Script (shebang)", nil
	}

	return Unknown, "Bilinmeyen dosya turu", nil
}

// FormatSize returns human-readable file size.
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
