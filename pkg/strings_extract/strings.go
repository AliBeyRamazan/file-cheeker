package strings_extract

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// SuspiciousPatterns defines regex patterns for malicious indicators
var SuspiciousPatterns = map[string]*regexp.Regexp{
	"IP ünvanı":          regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	"URL":                regexp.MustCompile(`https?://[^\s"'<>]+`),
	"E-poçt":             regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	"Registry açarı":     regexp.MustCompile(`(?i)(HKEY_[A-Z_]+\\[^\s"]+|SOFTWARE\\[^\s"]+)`),
	"Fayl yolu (Win)":    regexp.MustCompile(`(?i)[A-Z]:\\[^\s"]+`),
	"Fayl yolu (Unix)":   regexp.MustCompile(`/(?:etc|tmp|var|usr|bin|dev|proc|home)/[^\s"]+`),
	"Shell əmri":         regexp.MustCompile(`(?i)(cmd\.exe|powershell|/bin/sh|/bin/bash|wget\s|curl\s|chmod\s|nc\s+-[a-z])`),
	"DLL/API çağırışı":   regexp.MustCompile(`(?i)(LoadLibrary|GetProcAddress|VirtualAlloc|CreateRemoteThread|WriteProcessMemory|NtCreateThread|IsDebuggerPresent|CreateFile[AW]|RegOpenKey|InternetOpen|HttpSendRequest|URLDownloadToFile|ShellExecute|WinExec)`),
	"Kripto/Kodlama":     regexp.MustCompile(`(?i)(AES|RSA|base64|XOR|RC4|encrypt|decrypt|crypt)`),
	"Anti-debug":         regexp.MustCompile(`(?i)(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString|anti.?debug|anti.?vm|vmware|virtualbox|sandbox)`),
	"Şəbəkə funksiyası": regexp.MustCompile(`(?i)(socket|connect|bind|listen|accept|send|recv|WSAStartup|gethostbyname|inet_addr)`),
	"Proses manipulyasiyası": regexp.MustCompile(`(?i)(OpenProcess|CreateProcess|TerminateProcess|inject|hook|CreateThread)`),
}

// ExtractedString represents a found string with its context
type ExtractedString struct {
	Offset  int
	Value   string
	Category string
}

// Extract reads a file and finds printable ASCII strings of minimum length
func Extract(filepath string, minLen int) ([]string, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("fayl oxuna bilmədi: %w", err)
	}

	return ExtractFromBytes(data, minLen), nil
}

// ExtractFromBytes finds printable ASCII strings in a byte slice
func ExtractFromBytes(data []byte, minLen int) []string {
	var results []string
	var current []byte

	for _, b := range data {
		if b >= 32 && b < 127 {
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				results = append(results, string(current))
			}
			current = current[:0]
		}
	}
	if len(current) >= minLen {
		results = append(results, string(current))
	}
	return results
}

// FindSuspicious scans extracted strings for malicious indicators
func FindSuspicious(strs []string) map[string][]string {
	results := make(map[string][]string)

	for _, s := range strs {
		for category, pattern := range SuspiciousPatterns {
			matches := pattern.FindAllString(s, -1)
			for _, m := range matches {
				m = strings.TrimSpace(m)
				if len(m) > 3 {
					// Deduplicate
					found := false
					for _, existing := range results[category] {
						if existing == m {
							found = true
							break
						}
					}
					if !found {
						results[category] = append(results[category], m)
					}
				}
			}
		}
	}

	return results
}
