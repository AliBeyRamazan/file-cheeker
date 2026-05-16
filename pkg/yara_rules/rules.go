package yara_rules

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

// Rule defines a simple YARA-like detection rule.
type Rule struct {
	Name        string
	Description string
	Severity    string
	Patterns    []Pattern
	Strings     []string
}

// Pattern defines a hex byte pattern to search for.
type Pattern struct {
	Name  string
	Hex   string
	Bytes []byte
}

// Match represents a rule that matched.
type Match struct {
	RuleName    string
	Description string
	Severity    string
	Details     []string
}

// DefaultRules returns built-in detection rules.
func DefaultRules() []Rule {
	return []Rule{
		{Name: "UPX_Packed", Description: "UPX packer belirtisi bulundu", Severity: "medium", Strings: []string{"UPX0", "UPX1", "UPX!", "UPX2"}},
		{Name: "Suspicious_PowerShell", Description: "PowerShell komut calistirma belirtisi bulundu", Severity: "high", Strings: []string{"powershell", "PowerShell", "-EncodedCommand", "-ExecutionPolicy Bypass", "Invoke-Expression", "IEX(", "iex(", "downloadstring", "DownloadString"}},
		{Name: "Suspicious_CMD", Description: "Supheli CMD komutu bulundu", Severity: "medium", Strings: []string{"cmd.exe /c", "cmd /c", "cmd.exe /k", "command.com"}},
		{Name: "Anti_Debug_Techniques", Description: "Anti-debug teknigi belirtisi bulundu", Severity: "high", Strings: []string{"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter"}},
		{Name: "Anti_VM_Detection", Description: "Sanal makine tespit teknigi belirtisi bulundu", Severity: "high", Strings: []string{"vmware", "VMware", "VirtualBox", "VBOX", "QEMU", "Xen", "Hyper-V", "SbieDll.dll", "sbiedll.dll"}},
		{Name: "Process_Injection", Description: "Process injection belirtisi bulundu", Severity: "critical", Strings: []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetWindowsHookEx"}},
		{Name: "Keylogger_Indicators", Description: "Keylogger belirtisi bulundu", Severity: "critical", Strings: []string{"GetAsyncKeyState", "SetWindowsHookExA", "GetKeyState", "GetKeyboardState", "keylog", "keystroke"}},
		{Name: "Network_Communication", Description: "Ag iletisim fonksiyonu belirtisi bulundu", Severity: "medium", Strings: []string{"InternetOpenA", "InternetOpenUrlA", "HttpOpenRequestA", "HttpSendRequestA", "URLDownloadToFileA", "WinHttpOpen"}},
		{Name: "Persistence_Mechanisms", Description: "Kalicilik mekanizmasi belirtisi bulundu", Severity: "high", Strings: []string{"CurrentVersion\\Run", "CurrentVersion\\RunOnce", "schtasks", "SCHTASKS", "sc create", "RegSetValueEx"}},
		{Name: "Crypto_Operations", Description: "Kriptografi islemi belirtisi bulundu", Severity: "medium", Strings: []string{"CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt", "AES", "RSA"}},
		{
			Name:        "Shellcode_Indicators",
			Description: "Shellcode belirtisi bulundu",
			Severity:    "critical",
			Patterns: []Pattern{
				{Name: "NOP sled", Hex: "9090909090909090"},
				{Name: "INT3 sled", Hex: "cccccccccccccccc"},
			},
			Strings: []string{"VirtualAlloc", "VirtualProtect", "RtlMoveMemory"},
		},
		{Name: "Ransomware_Indicators", Description: "Ransomware belirtisi bulundu", Severity: "critical", Strings: []string{"Your files have been encrypted", "bitcoin", "BTC", ".onion", "ransom", "decrypt your files", "pay ", "wallet"}},
		{Name: "Data_Exfiltration", Description: "Veri sizdirma belirtisi bulundu", Severity: "high", Strings: []string{"ftp://", "sftp://", "smtp://", ".pastebin.com", "base64_encode", "upload", "exfil"}},
	}
}

// Scan checks data against all rules and returns matches.
func Scan(data []byte, rules []Rule) []Match {
	var matches []Match

	for _, rule := range rules {
		var details []string

		for _, s := range rule.Strings {
			if bytes.Contains(data, []byte(s)) {
				details = append(details, fmt.Sprintf("String bulundu: %q", s))
			}
		}

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
				details = append(details, fmt.Sprintf("Hex pattern bulundu: %s (%s)", p.Name, p.Hex))
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

// SeverityIcon is kept for compatibility with older callers.
func SeverityIcon(severity string) string {
	switch severity {
	case "low":
		return "i"
	case "medium":
		return "!"
	case "high":
		return "!!"
	case "critical":
		return "!!!"
	default:
		return "?"
	}
}
