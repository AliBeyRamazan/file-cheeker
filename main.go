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

const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
)

type options struct {
	filePath    string
	showStrings bool
	showAll     bool
	showImports bool
}

func main() {
	program := filepath.Base(os.Args[0])
	opts, ok := parseArgs(program, os.Args[1:])
	if !ok {
		os.Exit(1)
	}

	runScan(opts)
}

func parseArgs(program string, args []string) (options, bool) {
	if len(args) == 0 || isHelp(args[0]) {
		usage(program)
		if len(args) > 0 {
			os.Exit(0)
		}
		return options{}, false
	}

	if args[0] == "scan" {
		args = args[1:]
		if len(args) == 0 {
			usage(program)
			return options{}, false
		}
	}

	opts := options{filePath: args[0]}
	for _, arg := range args[1:] {
		switch arg {
		case "-a", "--all":
			opts.showAll = true
			opts.showStrings = true
			opts.showImports = true
		case "-s", "--strings":
			opts.showStrings = true
		case "-i", "--imports":
			opts.showImports = true
		case "-h", "--help":
			usage(program)
			os.Exit(0)
		default:
			fmt.Printf("%sBilinmeyen secenek:%s %s\n\n", Red, Reset, arg)
			usage(program)
			return options{}, false
		}
	}

	return opts, true
}

func isHelp(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "help"
}

func usage(program string) {
	banner()
	fmt.Printf("%sKullanim:%s\n", Bold, Reset)
	fmt.Printf("  %s <dosya> [secenek]\n", program)
	fmt.Printf("  %s scan <dosya> [secenek]\n\n", program)

	fmt.Printf("%sKisa secenekler:%s\n", Bold, Reset)
	fmt.Printf("  %s-a%s  tam analiz: stringler + importlar\n", Cyan, Reset)
	fmt.Printf("  %s-s%s  bulunan stringleri goster\n", Cyan, Reset)
	fmt.Printf("  %s-i%s  PE import fonksiyonlarini goster\n", Cyan, Reset)
	fmt.Printf("  %s-h%s  yardim\n\n", Cyan, Reset)

	fmt.Printf("%sLinux ornekleri:%s\n", Bold, Reset)
	fmt.Printf("  %s ./suspicious\n", program)
	fmt.Printf("  %s ./suspicious -a\n", program)
	fmt.Printf("  %s /bin/ls -s\n", program)
	fmt.Printf("  %s scan ./sample.elf -a\n", program)
}

func runScan(opts options) {
	banner()
	startTime := time.Now()

	info, err := os.Stat(opts.filePath)
	if err != nil {
		fmt.Printf("%s[HATA]%s Dosya bulunamadi: %s\n", Red, Reset, opts.filePath)
		os.Exit(1)
	}

	absPath, _ := filepath.Abs(opts.filePath)
	section("DOSYA BILGILERI")
	field("Dosya adi", filepath.Base(opts.filePath))
	field("Tam yol", absPath)
	field("Boyut", fmt.Sprintf("%s (%d bayt)", analyzer.FormatSize(info.Size()), info.Size()))
	field("Degisme tarihi", info.ModTime().Format("2006-01-02 15:04:05"))

	section("DOSYA TURU")
	fileType, fileTypeStr, err := analyzer.DetectFileType(opts.filePath)
	if err != nil {
		field("Dosya turu", "Belirlenemedi")
	} else {
		field("Dosya turu", fileTypeStr)
	}

	section("HASH DEGERLERI")
	hashes, err := hasher.ComputeHashes(opts.filePath)
	if err != nil {
		fmt.Printf("  %s[HATA]%s Hash hesaplanamadi: %v\n", Red, Reset, err)
	} else {
		fieldColor("MD5", hashes.MD5, Green)
		fieldColor("SHA1", hashes.SHA1, Green)
		fieldColor("SHA256", hashes.SHA256, Green)
	}

	section("ENTROPI ANALIZI")
	ent, err := entropy.Calculate(opts.filePath)
	if err != nil {
		fmt.Printf("  %s[HATA]%s Entropi hesaplanamadi: %v\n", Red, Reset, err)
	} else {
		color := Green
		if ent > 7.0 {
			color = Red
		} else if ent > 5.0 {
			color = Yellow
		}
		fieldColor("Entropi", fmt.Sprintf("%.4f / 8.0", ent), color)
		field("Yorum", entropy.Verdict(ent))
	}

	if fileType == analyzer.ELF {
		printELF(opts.filePath)
	}
	if fileType == analyzer.PE {
		printPE(opts.filePath, opts)
	}

	data, err := os.ReadFile(opts.filePath)
	if err != nil {
		fmt.Printf("  %s[HATA]%s Dosya okunamadi: %v\n", Red, Reset, err)
		os.Exit(1)
	}

	matches := printRules(data)
	suspiciousCount := printStrings(opts.filePath, opts)
	printScore(ent, matches, suspiciousCount)

	fmt.Printf("\n%sAnaliz tamamlandi: %v%s\n\n", Dim, time.Since(startTime), Reset)
}

func printELF(filePath string) {
	section("ELF ANALIZI")
	info, err := elfparser.Parse(filePath)
	if err != nil {
		fmt.Printf("  %s[HATA]%s ELF analiz edilemedi: %v\n", Red, Reset, err)
		return
	}

	field("Sinif", info.Class)
	field("Byte sirasi", info.Endianness)
	field("OS/ABI", info.OSABI)
	field("Tur", info.Type)
	field("Makine", info.Machine)
	field("Entry point", fmt.Sprintf("0x%X", info.EntryPoint))
	if info.Interpreter != "" {
		field("Interpreter", info.Interpreter)
	}
	if len(info.DynLibs) > 0 {
		field("Dinamik kutuphane", strings.Join(info.DynLibs, ", "))
	}
	printPacker(info.IsPacked, info.PackerHints)
}

func printPE(filePath string, opts options) {
	section("PE ANALIZI")
	info, err := peparser.Parse(filePath)
	if err != nil {
		fmt.Printf("  %s[HATA]%s PE analiz edilemedi: %v\n", Red, Reset, err)
		return
	}

	field("Makine", info.Machine)
	field("Tarih", info.TimeDateStamp.Format("2006-01-02 15:04:05 UTC"))
	field("Entry point", fmt.Sprintf("0x%X", info.EntryPoint))
	field("Image base", fmt.Sprintf("0x%X", info.ImageBase))
	field("Alt sistem", info.Subsystem)
	field("Bolum sayisi", fmt.Sprintf("%d", info.NumberOfSections))

	if len(info.Imports) > 0 {
		fmt.Printf("\n  %sImport edilen DLL'ler (%d):%s\n", Bold+Cyan, len(info.Imports), Reset)
		for _, imp := range info.Imports {
			fmt.Printf("    %s (%d fonksiyon)\n", imp.DLLName, len(imp.Functions))
			if opts.showImports || opts.showAll {
				for _, fn := range imp.Functions {
					fmt.Printf("      - %s\n", fn)
				}
			}
		}
	}

	if len(info.Exports) > 0 {
		fmt.Printf("\n  %sExport edilen fonksiyonlar (%d):%s\n", Bold+Cyan, len(info.Exports), Reset)
		for _, exp := range info.Exports {
			fmt.Printf("    - %s\n", exp)
		}
	}

	printPacker(info.IsPacked, info.PackerHints)
}

func printPacker(isPacked bool, hints []string) {
	if !isPacked {
		return
	}
	fmt.Printf("\n  %sPAKETLENMIS DOSYA BULUNDU%s\n", Red+Bold, Reset)
	for _, hint := range hints {
		fmt.Printf("    - %s\n", hint)
	}
}

func printRules(data []byte) []yara_rules.Match {
	section("IMZA TARAMASI")
	matches := yara_rules.Scan(data, yara_rules.DefaultRules())
	if len(matches) == 0 {
		fmt.Printf("  %sSupheli imza bulunmadi.%s\n", Green, Reset)
		return matches
	}

	fmt.Printf("  %s%d kural eslesmesi bulundu.%s\n\n", Red+Bold, len(matches), Reset)
	for _, match := range matches {
		color := severityColor(match.Severity)
		fmt.Printf("  %s[%s]%s %s\n", color+Bold, strings.ToUpper(match.Severity), Reset, match.RuleName)
		fmt.Printf("    %s%s%s\n", Dim, match.Description, Reset)
		for _, detail := range match.Details {
			fmt.Printf("    - %s\n", detail)
		}
	}
	return matches
}

func printStrings(filePath string, opts options) int {
	section("SUPHELI STRINGLER")
	strs, err := strings_extract.Extract(filePath, 6)
	if err != nil {
		fmt.Printf("  %s[HATA]%s Stringler cikarilamadi: %v\n", Red, Reset, err)
		return 0
	}

	field("Toplam string", fmt.Sprintf("%d (min 6 karakter)", len(strs)))
	suspicious := strings_extract.FindSuspicious(strs)
	total := 0
	for _, values := range suspicious {
		total += len(values)
	}

	if total == 0 {
		fmt.Printf("  %sSupheli string bulunmadi.%s\n", Green, Reset)
	} else {
		fmt.Printf("  %s%d supheli string bulundu:%s\n\n", Yellow+Bold, total, Reset)
		for category, values := range suspicious {
			fmt.Printf("  %s%s:%s\n", Cyan+Bold, category, Reset)
			limit := 10
			if opts.showAll || len(values) < limit {
				limit = len(values)
			}
			for i := 0; i < limit; i++ {
				fmt.Printf("    - %s\n", values[i])
			}
			if len(values) > limit {
				fmt.Printf("    %s... ve %d tane daha%s\n", Dim, len(values)-limit, Reset)
			}
		}
	}

	if opts.showStrings {
		fmt.Printf("\n  %sTum stringler (ilk 100):%s\n", Cyan+Bold, Reset)
		limit := 100
		if len(strs) < limit {
			limit = len(strs)
		}
		for i := 0; i < limit; i++ {
			value := strs[i]
			if len(value) > 100 {
				value = value[:100] + "..."
			}
			fmt.Printf("    [%04d] %s\n", i, value)
		}
		if len(strs) > limit {
			fmt.Printf("    %s... ve %d tane daha (-a ile gosterin)%s\n", Dim, len(strs)-limit, Reset)
		}
	}

	return len(suspicious)
}

func printScore(ent float64, matches []yara_rules.Match, suspiciousCategories int) {
	section("RISK PUANI")
	score := calculateThreatScore(ent, matches, suspiciousCategories)
	color := Green
	label := "RISK BULUNMADI"
	if score > 80 {
		color = Red + Bold
		label = "COK YUKSEK RISK"
	} else if score > 60 {
		color = Red
		label = "YUKSEK RISK"
	} else if score > 40 {
		color = Yellow
		label = "ORTA RISK"
	} else if score > 20 {
		color = Yellow
		label = "DUSUK RISK"
	}

	fmt.Printf("  %sPuan:%s %s%d/100 - %s%s\n", Bold, Reset, color, score, label, Reset)
}

func calculateThreatScore(ent float64, matches []yara_rules.Match, suspiciousCategories int) int {
	score := 0
	if ent > 7.5 {
		score += 30
	} else if ent > 7.0 {
		score += 20
	} else if ent > 6.5 {
		score += 10
	}

	for _, match := range matches {
		switch match.Severity {
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

	score += suspiciousCategories * 5
	if score > 100 {
		return 100
	}
	return score
}

func banner() {
	fmt.Println(Cyan + Bold + "file-cheeker" + Reset)
	fmt.Println(Dim + "Linux binary and file triage tool" + Reset)
	fmt.Println()
}

func section(title string) {
	fmt.Printf("\n%s%s[%s]%s\n", Bold, Blue, title, Reset)
	fmt.Printf("%s%s%s%s\n", Dim, Blue, strings.Repeat("-", 60), Reset)
}

func field(label, value string) {
	fmt.Printf("  %s%-22s%s %s\n", Yellow, label+":", Reset, value)
}

func fieldColor(label, value, color string) {
	fmt.Printf("  %s%-22s%s %s%s%s\n", Yellow, label+":", Reset, color, value, Reset)
}

func severityColor(severity string) string {
	switch severity {
	case "medium":
		return Yellow
	case "high":
		return Magenta
	case "critical":
		return Red
	default:
		return Green
	}
}
