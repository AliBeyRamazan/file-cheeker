package main

import (
	"file-analyzer/pkg/analyzer"
	"file-analyzer/pkg/elfparser"
	"file-analyzer/pkg/entropy"
	"file-analyzer/pkg/hasher"
	"file-analyzer/pkg/peparser"
	"file-analyzer/pkg/strings_extract"
	"file-analyzer/pkg/yara_rules"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ANSI color codes
const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Blue      = "\033[34m"
	Magenta   = "\033[35m"
	Cyan      = "\033[36m"
	White     = "\033[37m"
	BgRed     = "\033[41m"
	BgGreen   = "\033[42m"
	BgYellow  = "\033[43m"
	BgBlue    = "\033[44m"
	BgMagenta = "\033[45m"
)

func banner() {
	fmt.Println(Cyan + Bold + `
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   ██████╗ ██╗███╗   ██╗ █████╗ ██████╗ ██╗   ██╗            ║
  ║   ██╔══██╗██║████╗  ██║██╔══██╗██╔══██╗╚██╗ ██╔╝            ║
  ║   ██████╔╝██║██╔██╗ ██║███████║██████╔╝ ╚████╔╝             ║
  ║   ██╔══██╗██║██║╚██╗██║██╔══██║██╔══██╗  ╚██╔╝              ║
  ║   ██████╔╝██║██║ ╚████║██║  ██║██║  ██║   ██║               ║
  ║   ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝               ║
  ║                                                               ║
  ║   ████████╗ █████╗ ██╗  ██╗██╗     ██╗██╗     ██╗            ║
  ║      ██║   ██╔══██╗██║  ██║██║     ██║██║     ██║            ║
  ║      ██║   ███████║███████║██║     ██║██║     ██║            ║
  ║      ██║   ██╔══██║██╔══██║██║     ██║██║     ██║            ║
  ║      ██║   ██║  ██║██║  ██║███████╗██║███████╗██║            ║
  ║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝            ║
  ║                                                               ║
  ║          🔍 Fayl Təhlilçisi v1.0 — Binary Analysis Tool       ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝` + Reset)
	fmt.Println()
}

func section(title string) {
	line := strings.Repeat("─", 60)
	fmt.Printf("\n%s%s ┌%s┐%s\n", Bold, Blue, line, Reset)
	fmt.Printf("%s%s │ %-58s │%s\n", Bold, Blue, title, Reset)
	fmt.Printf("%s%s └%s┘%s\n", Bold, Blue, line, Reset)
}

func field(label, value string) {
	fmt.Printf("  %s%-22s%s %s\n", Yellow, label+":", Reset, value)
}

func fieldColor(label, value, color string) {
	fmt.Printf("  %s%-22s%s %s%s%s\n", Yellow, label+":", Reset, color, value, Reset)
}

func main() {
	if len(os.Args) < 2 {
		banner()
		fmt.Printf("%sİstifadə:%s %s <fayl_yolu> [seçimlər]\n\n", Bold, Reset, os.Args[0])
		fmt.Printf("%sSeçimlər:%s\n", Bold, Reset)
		fmt.Printf("  %s--strings%s      Çıxarılmış string-ləri göstər\n", Cyan, Reset)
		fmt.Printf("  %s--all%s          Bütün təfsilatları göstər\n", Cyan, Reset)
		fmt.Printf("  %s--imports%s      Bütün import funksiyalarını göstər\n", Cyan, Reset)
		fmt.Printf("  %s--json%s         JSON formatında çıxış\n", Cyan, Reset)
		fmt.Println()
		fmt.Printf("%sNümunə:%s\n", Bold, Reset)
		fmt.Printf("  %s malware.exe\n", os.Args[0])
		fmt.Printf("  %s suspicious.elf --all\n", os.Args[0])
		os.Exit(1)
	}

	filePath := os.Args[1]
	showStrings := false
	showAll := false
	showImports := false

	for _, arg := range os.Args[2:] {
		switch arg {
		case "--strings":
			showStrings = true
		case "--all":
			showAll = true
			showStrings = true
			showImports = true
		case "--imports":
			showImports = true
		}
	}

	banner()

	startTime := time.Now()

	// Check file exists
	info, err := os.Stat(filePath)
	if err != nil {
		fmt.Printf("%s%s[XƏTA]%s Fayl tapılmadı: %s\n", Bold, Red, Reset, filePath)
		os.Exit(1)
	}

	// ═══════════════════════════════════════════
	// BASIC FILE INFO
	// ═══════════════════════════════════════════
	section("📋 ƏSAS FAYL MƏLUMATLARI")

	absPath, _ := filepath.Abs(filePath)
	field("Fayl adı", filepath.Base(filePath))
	field("Tam yol", absPath)
	field("Ölçü", fmt.Sprintf("%s (%d bayt)", analyzer.FormatSize(info.Size()), info.Size()))
	field("Dəyişmə tarixi", info.ModTime().Format("2006-01-02 15:04:05"))

	// ═══════════════════════════════════════════
	// FILE TYPE DETECTION
	// ═══════════════════════════════════════════
	section("🔎 FAYL NÖVÜNÜN TƏYİNİ")

	fileType, fileTypeStr, err := analyzer.DetectFileType(filePath)
	if err != nil {
		field("Fayl növü", "Təyin edilə bilmədi")
	} else {
		field("Fayl növü", fileTypeStr)
	}

	// ═══════════════════════════════════════════
	// HASHES
	// ═══════════════════════════════════════════
	section("🔐 HƏŞ DƏYƏRLƏRİ")

	hashes, err := hasher.ComputeHashes(filePath)
	if err != nil {
		fmt.Printf("  %s[XƏTA]%s Həşlər hesablana bilmədi: %v\n", Red, Reset, err)
	} else {
		fieldColor("MD5", hashes.MD5, Green)
		fieldColor("SHA1", hashes.SHA1, Green)
		fieldColor("SHA256", hashes.SHA256, Green)
	}

	// ═══════════════════════════════════════════
	// ENTROPY
	// ═══════════════════════════════════════════
	section("📊 ENTROPİYA TƏHLİLİ")

	ent, err := entropy.Calculate(filePath)
	if err != nil {
		fmt.Printf("  %s[XƏTA]%s Entropiya hesablana bilmədi: %v\n", Red, Reset, err)
	} else {
		entColor := Green
		if ent > 7.0 {
			entColor = Red
		} else if ent > 5.0 {
			entColor = Yellow
		}
		fieldColor("Entropiya", fmt.Sprintf("%.4f / 8.0", ent), entColor)
		field("Qiymətləndirmə", entropy.Verdict(ent))

		// Visual entropy bar
		barLen := 40
		filled := int(ent / 8.0 * float64(barLen))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)
		fmt.Printf("  %s%-22s%s %s%s%s\n", Yellow, "Vizual:", Reset, entColor, bar, Reset)
	}

	// ═══════════════════════════════════════════
	// PE ANALYSIS
	// ═══════════════════════════════════════════
	if fileType == analyzer.PE {
		section("🪟 PE (Windows) TƏHLİLİ")

		peInfo, err := peparser.Parse(filePath)
		if err != nil {
			fmt.Printf("  %s[XƏTA]%s PE təhlil edilə bilmədi: %v\n", Red, Reset, err)
		} else {
			field("Maşın", peInfo.Machine)
			field("Tarix", peInfo.TimeDateStamp.Format("2006-01-02 15:04:05 UTC"))
			field("Giriş nöqtəsi", fmt.Sprintf("0x%X", peInfo.EntryPoint))
			field("Image Base", fmt.Sprintf("0x%X", peInfo.ImageBase))
			field("Alt sistem", peInfo.Subsystem)
			field("Bölmə sayı", fmt.Sprintf("%d", peInfo.NumberOfSections))
			field("Xüsusiyyətlər", strings.Join(peInfo.Characteristics, ", "))
			field("DLL Xüsusiyyətləri", strings.Join(peInfo.DLLCharacteristics, ", "))

			// Sections
			if len(peInfo.Sections) > 0 {
				fmt.Printf("\n  %s%sBölmələr:%s\n", Bold, Cyan, Reset)
				fmt.Printf("  %s┌──────────┬──────────┬──────────┬─────────┬──────────────────────┐%s\n", Dim, Reset)
				fmt.Printf("  %s│ %-8s │ %-8s │ %-8s │ %-7s │ %-20s │%s\n", Dim, "Ad", "VirtÖlçü", "RawÖlçü", "Entrop.", "Xüsusiyyətlər", Reset)
				fmt.Printf("  %s├──────────┼──────────┼──────────┼─────────┼──────────────────────┤%s\n", Dim, Reset)
				for _, sec := range peInfo.Sections {
					entColor := Green
					if sec.Entropy > 7.0 {
						entColor = Red + Bold
					} else if sec.Entropy > 6.0 {
						entColor = Yellow
					}
					chars := strings.Join(sec.Characteristics, ",")
					if len(chars) > 20 {
						chars = chars[:20]
					}
					fmt.Printf("  %s│%s %-8s %s│%s %8X %s│%s %8X %s│%s %s%.4f%s %s│%s %-20s %s│%s\n",
						Dim, Reset, sec.Name,
						Dim, Reset, sec.VirtualSize,
						Dim, Reset, sec.RawSize,
						Dim, Reset, entColor, sec.Entropy, Reset,
						Dim, Reset, chars, Dim, Reset)
				}
				fmt.Printf("  %s└──────────┴──────────┴──────────┴─────────┴──────────────────────┘%s\n", Dim, Reset)
			}

			// Imports
			if len(peInfo.Imports) > 0 {
				fmt.Printf("\n  %s%sİmport edilən DLL-lər (%d):%s\n", Bold, Cyan, len(peInfo.Imports), Reset)
				for _, imp := range peInfo.Imports {
					fmt.Printf("    %s📦 %s%s %s(%d funksiya)%s\n", Yellow, imp.DLLName, Reset, Dim, len(imp.Functions), Reset)
					if showImports || showAll {
						for _, fn := range imp.Functions {
							fmt.Printf("      %s→ %s%s\n", Dim, fn, Reset)
						}
					}
				}
			}

			// Exports
			if len(peInfo.Exports) > 0 {
				fmt.Printf("\n  %s%sExport edilən funksiyalar (%d):%s\n", Bold, Cyan, len(peInfo.Exports), Reset)
				for _, exp := range peInfo.Exports {
					fmt.Printf("    %s📤 %s%s\n", Green, exp, Reset)
				}
			}

			// Packing detection
			if peInfo.IsPacked {
				fmt.Printf("\n  %s%s🚨 PAKETLƏNMİŞ FAYL AŞKARLANDI!%s\n", Bold, Red, Reset)
				for _, hint := range peInfo.PackerHints {
					fmt.Printf("    %s⚠ %s%s\n", Red, hint, Reset)
				}
			}
		}
	}

	// ═══════════════════════════════════════════
	// ELF ANALYSIS
	// ═══════════════════════════════════════════
	if fileType == analyzer.ELF {
		section("🐧 ELF (Linux/Unix) TƏHLİLİ")

		elfInfo, err := elfparser.Parse(filePath)
		if err != nil {
			fmt.Printf("  %s[XƏTA]%s ELF təhlil edilə bilmədi: %v\n", Red, Reset, err)
		} else {
			field("Sinif", elfInfo.Class)
			field("Bayt sırası", elfInfo.Endianness)
			field("OS/ABI", elfInfo.OSABI)
			field("Növ", elfInfo.Type)
			field("Maşın", elfInfo.Machine)
			field("Giriş nöqtəsi", fmt.Sprintf("0x%X", elfInfo.EntryPoint))
			if elfInfo.Interpreter != "" {
				field("Interpreter", elfInfo.Interpreter)
			}

			// Sections
			if len(elfInfo.Sections) > 0 {
				fmt.Printf("\n  %s%sBölmələr:%s\n", Bold, Cyan, Reset)
				fmt.Printf("  %s┌──────────────────┬──────────┬──────────┬─────────┬────────────────┐%s\n", Dim, Reset)
				fmt.Printf("  %s│ %-16s │ %-8s │ %-8s │ %-7s │ %-14s │%s\n", Dim, "Ad", "Növ", "Ölçü", "Entrop.", "Bayraqlar", Reset)
				fmt.Printf("  %s├──────────────────┼──────────┼──────────┼─────────┼────────────────┤%s\n", Dim, Reset)
				for _, sec := range elfInfo.Sections {
					if sec.Name == "" {
						continue
					}
					entColor := Green
					if sec.Entropy > 7.0 {
						entColor = Red + Bold
					} else if sec.Entropy > 6.0 {
						entColor = Yellow
					}
					name := sec.Name
					if len(name) > 16 {
						name = name[:16]
					}
					flags := strings.Join(sec.Flags, ",")
					if len(flags) > 14 {
						flags = flags[:14]
					}
					fmt.Printf("  %s│%s %-16s %s│%s %-8s %s│%s %8d %s│%s %s%.4f%s %s│%s %-14s %s│%s\n",
						Dim, Reset, name,
						Dim, Reset, sec.Type,
						Dim, Reset, sec.Size,
						Dim, Reset, entColor, sec.Entropy, Reset,
						Dim, Reset, flags, Dim, Reset)
				}
				fmt.Printf("  %s└──────────────────┴──────────┴──────────┴─────────┴────────────────┘%s\n", Dim, Reset)
			}

			// Dynamic Libraries
			if len(elfInfo.DynLibs) > 0 {
				fmt.Printf("\n  %s%sDinamik kitabxanalar (%d):%s\n", Bold, Cyan, len(elfInfo.DynLibs), Reset)
				for _, lib := range elfInfo.DynLibs {
					fmt.Printf("    %s📦 %s%s\n", Yellow, lib, Reset)
				}
			}

			// Packing
			if elfInfo.IsPacked {
				fmt.Printf("\n  %s%s🚨 PAKETLƏNMİŞ FAYL AŞKARLANDI!%s\n", Bold, Red, Reset)
				for _, hint := range elfInfo.PackerHints {
					fmt.Printf("    %s⚠ %s%s\n", Red, hint, Reset)
				}
			}
		}
	}

	// ═══════════════════════════════════════════
	// YARA-LIKE RULE SCANNING
	// ═══════════════════════════════════════════
	section("🛡️ İMZA ƏSASLI SKAN")

	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("  %s[XƏTA]%s Fayl oxuna bilmədi: %v\n", Red, Reset, err)
	} else {
		rules := yara_rules.DefaultRules()
		matches := yara_rules.Scan(data, rules)

		if len(matches) == 0 {
			fmt.Printf("  %s✅ Heç bir şübhəli imza tapılmadı.%s\n", Green, Reset)
		} else {
			fmt.Printf("  %s%s⚠ %d qayda uyğunluğu tapıldı!%s\n\n", Bold, Red, len(matches), Reset)
			for _, m := range matches {
				icon := yara_rules.SeverityIcon(m.Severity)
				sevColor := Green
				switch m.Severity {
				case "medium":
					sevColor = Yellow
				case "high":
					sevColor = Magenta
				case "critical":
					sevColor = Red + Bold
				}
				fmt.Printf("  %s %s%s[%s]%s %s\n", icon, sevColor, Bold, strings.ToUpper(m.Severity), Reset, m.RuleName)
				fmt.Printf("    %s%s%s\n", Dim, m.Description, Reset)
				for _, d := range m.Details {
					fmt.Printf("    %s→ %s%s\n", sevColor, d, Reset)
				}
				fmt.Println()
			}
		}
	}

	// ═══════════════════════════════════════════
	// SUSPICIOUS STRINGS
	// ═══════════════════════════════════════════
	section("🔤 ŞÜBHƏLİ STRİNG-LƏR")

	strs, err := strings_extract.Extract(filePath, 6)
	if err != nil {
		fmt.Printf("  %s[XƏTA]%s String-lər çıxarıla bilmədi: %v\n", Red, Reset, err)
	} else {
		field("Cəmi string", fmt.Sprintf("%d (min 6 simvol)", len(strs)))

		suspicious := strings_extract.FindSuspicious(strs)
		if len(suspicious) == 0 {
			fmt.Printf("  %s✅ Şübhəli string tapılmadı.%s\n", Green, Reset)
		} else {
			totalSuspicious := 0
			for _, v := range suspicious {
				totalSuspicious += len(v)
			}
			fmt.Printf("  %s%s⚠ %d şübhəli string tapıldı:%s\n\n", Bold, Yellow, totalSuspicious, Reset)

			for category, values := range suspicious {
				fmt.Printf("  %s%s📌 %s:%s\n", Bold, Cyan, category, Reset)
				maxShow := 10
				if showAll {
					maxShow = len(values)
				}
				for i, v := range values {
					if i >= maxShow {
						fmt.Printf("    %s... və %d daha%s\n", Dim, len(values)-maxShow, Reset)
						break
					}
					fmt.Printf("    %s→ %s%s\n", Yellow, v, Reset)
				}
			}
		}

		// Show all strings if requested
		if showStrings {
			fmt.Printf("\n  %s%sBütün string-lər (ilk 100):%s\n", Bold, Cyan, Reset)
			maxShow := 100
			if len(strs) < maxShow {
				maxShow = len(strs)
			}
			for i := 0; i < maxShow; i++ {
				s := strs[i]
				if len(s) > 80 {
					s = s[:80] + "..."
				}
				fmt.Printf("    %s[%04d]%s %s\n", Dim, i, Reset, s)
			}
			if len(strs) > 100 {
				fmt.Printf("    %s... və %d daha (--all ilə göstərin)%s\n", Dim, len(strs)-100, Reset)
			}
		}
	}

	// ═══════════════════════════════════════════
	// THREAT SCORE
	// ═══════════════════════════════════════════
	section("🎯 TƏHDİD QİYMƏTLƏNDİRMƏSİ")

	score := calculateThreatScore(filePath, fileType, ent, data)
	scoreColor := Green
	scoreLabel := "TƏHLÜKƏ AŞKARLANMADI"
	if score > 80 {
		scoreColor = Red + Bold
		scoreLabel = "ÇOX YÜKSƏK RİSK"
	} else if score > 60 {
		scoreColor = Red
		scoreLabel = "YÜKSƏK RİSK"
	} else if score > 40 {
		scoreColor = Yellow
		scoreLabel = "ORTA RİSK"
	} else if score > 20 {
		scoreColor = Yellow
		scoreLabel = "AŞAĞI RİSK"
	}

	barLen := 50
	filled := score * barLen / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)
	fmt.Printf("  %sBAL: %s%d/100 — %s%s\n", Bold, scoreColor, score, scoreLabel, Reset)
	fmt.Printf("  %s%s%s\n", scoreColor, bar, Reset)

	// ═══════════════════════════════════════════
	// SUMMARY
	// ═══════════════════════════════════════════
	elapsed := time.Since(startTime)
	fmt.Printf("\n%s%s ⏱ Təhlil tamamlandı: %v%s\n\n", Dim, Blue, elapsed, Reset)
}

func calculateThreatScore(filePath string, fileType analyzer.FileType, ent float64, data []byte) int {
	score := 0

	// Entropy score
	if ent > 7.5 {
		score += 30
	} else if ent > 7.0 {
		score += 20
	} else if ent > 6.5 {
		score += 10
	}

	// YARA matches
	rules := yara_rules.DefaultRules()
	matches := yara_rules.Scan(data, rules)
	for _, m := range matches {
		switch m.Severity {
		case "critical":
			score += 25
		case "high":
			score += 15
		case "medium":
			score += 8
		case "low":
			score += 3
		}
	}

	// Suspicious strings
	strs := strings_extract.ExtractFromBytes(data, 6)
	suspicious := strings_extract.FindSuspicious(strs)
	for range suspicious {
		score += 5
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
