package yara_rules

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

// Rule defines a simple YARA-like detection rule
type Rule struct {
	Name        string
	Description string
	Severity    string // "low", "medium", "high", "critical"
	Patterns    []Pattern
	Strings     []string // plain text patterns
}

// Pattern defines a hex byte pattern to search for
type Pattern struct {
	Name  string
	Hex   string
	Bytes []byte
}

// Match represents a rule that matched
type Match struct {
	RuleName    string
	Description string
	Severity    string
	Details     []string
}

// DefaultRules returns built-in detection rules
func DefaultRules() []Rule {
	return []Rule{
		{
			Name:        "UPX_Packed",
			Description: "UPX paketləyicisi ilə sıxılmış fayl aşkarlandı",
			Severity:    "medium",
			Strings:     []string{"UPX0", "UPX1", "UPX!", "UPX2"},
		},
		{
			Name:        "Suspicious_PowerShell",
			Description: "PowerShell icra əmrləri aşkarlandı",
			Severity:    "high",
			Strings:     []string{"powershell", "PowerShell", "-EncodedCommand", "-ExecutionPolicy Bypass", "Invoke-Expression", "IEX(", "iex(", "downloadstring", "DownloadString"},
		},
		{
			Name:        "Suspicious_CMD",
			Description: "Şübhəli CMD əmrləri aşkarlandı",
			Severity:    "medium",
			Strings:     []string{"cmd.exe /c", "cmd /c", "cmd.exe /k", "command.com"},
		},
		{
			Name:        "Anti_Debug_Techniques",
			Description: "Anti-debug texnikaları aşkarlandı",
			Severity:    "high",
			Strings:     []string{"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter"},
		},
		{
			Name:        "Anti_VM_Detection",
			Description: "Virtual maşın aşkarlama texnikaları tapıldı",
			Severity:    "high",
			Strings:     []string{"vmware", "VMware", "VirtualBox", "VBOX", "QEMU", "Xen", "Hyper-V", "SbieDll.dll", "sbiedll.dll"},
		},
		{
			Name:        "Process_Injection",
			Description: "Proses inyeksiya texnikaları aşkarlandı",
			Severity:    "critical",
			Strings:     []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx"},
		},
		{
			Name:        "Keylogger_Indicators",
			Description: "Klaviatura izləyicisi göstəriciləri aşkarlandı",
			Severity:    "critical",
			Strings:     []string{"GetAsyncKeyState", "SetWindowsHookExA", "GetKeyState", "GetKeyboardState", "keylog", "keystroke"},
		},
		{
			Name:        "Network_Communication",
			Description: "Şəbəkə rabitə funksiyaları aşkarlandı",
			Severity:    "medium",
			Strings:     []string{"InternetOpenA", "InternetOpenUrlA", "HttpOpenRequestA", "HttpSendRequestA", "URLDownloadToFileA", "WinHttpOpen"},
		},
		{
			Name:        "Persistence_Mechanisms",
			Description: "Davamlılıq mexanizmləri aşkarlandı",
			Severity:    "high",
			Strings:     []string{"CurrentVersion\\Run", "CurrentVersion\\RunOnce", "schtasks", "SCHTASKS", "sc create", "RegSetValueEx"},
		},
		{
			Name:        "Crypto_Operations",
			Description: "Kriptoqrafik əməliyyatlar aşkarlandı",
			Severity:    "medium",
			Strings:     []string{"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt", "AES", "RSA"},
		},
		{
			Name:        "Shellcode_Indicators",
			Description: "Shellcode göstəriciləri aşkarlandı",
			Severity:    "critical",
			Patterns: []Pattern{
				{Name: "NOP Sled", Hex: "9090909090909090"},
				{Name: "INT3 Sled", Hex: "cccccccccccccccc"},
			},
			Strings: []string{"VirtualAlloc", "VirtualProtect", "RtlMoveMemory"},
		},
		{
			Name:        "Ransomware_Indicators",
			Description: "Ransomware göstəriciləri aşkarlandı",
			Severity:    "critical",
			Strings:     []string{"Your files have been encrypted", "bitcoin", "BTC", ".onion", "ransom", "decrypt your files", "pay ", "wallet"},
		},
		{
			Name:        "Data_Exfiltration",
			Description: "Məlumat oğurluğu göstəriciləri aşkarlandı",
			Severity:    "high",
			Strings:     []string{"ftp://", "sftp://", "smtp://", ".pastebin.com", "base64_encode", "upload", "exfil"},
		},
	}
}

// Scan checks data against all rules and returns matches
func Scan(data []byte, rules []Rule) []Match {
	var matches []Match

	for _, rule := range rules {
		var details []string

		// Check string patterns
		for _, s := range rule.Strings {
			if bytes.Contains(data, []byte(s)) {
				details = append(details, fmt.Sprintf("String tapıldı: \"%s\"", s))
			}
		}

		// Check hex patterns
		for _, p := range rule.Patterns {
			patternBytes := p.Bytes
			if len(patternBytes) == 0 && p.Hex != "" {
				var err error
				patternBytes, err = hex.DecodeString(strings.ReplaceAll(p.Hex, " ", ""))
				if err != nil {
					continue
				}
			}
			if len(patternBytes) > 0 && bytes.Contains(data, patternBytes) {
				details = append(details, fmt.Sprintf("Hex pattern tapıldı: %s (%s)", p.Name, p.Hex))
			}
		}

		if len(details) > 0 {
			matches = append(matches, Match{
				RuleName:    rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				Details:     details,
			})
		}
	}

	return matches
}

// SeverityIcon returns an emoji for severity level
func SeverityIcon(severity string) string {
	switch severity {
	case "low":
		return "ℹ️"
	case "medium":
		return "⚠️"
	case "high":
		return "🔶"
	case "critical":
		return "🚨"
	default:
		return "❓"
	}
}
