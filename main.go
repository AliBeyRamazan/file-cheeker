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
	"io"
	"io/fs"
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
	filePath      string
	showStrings   bool
	showAll       bool
	showImports   bool
	recursive     bool
	quarantine    bool
	quarantineDir string
}

type fileSummary struct {
	path                 string
	fileType             string
	sha256               string
	entropy              float64
	ruleMatches          []yara_rules.Match
	suspiciousCategories int
	score                int
	err                  error
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

	opts := options{filePath: args[0], recursive: true, quarantineDir: ".fc-quarantine"}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-a", "--all":
			opts.showAll = true
			opts.showStrings = true
			opts.showImports = true
		case "-s", "--strings":
			opts.showStrings = true
		case "-i", "--imports":
			opts.showImports = true
		case "--no-recursive":
			opts.recursive = false
		case "-q", "--quarantine":
			opts.quarantine = true
		case "--quarantine-dir":
			if i+1 >= len(args) {
				fmt.Printf("%sEksik deger:%s --quarantine-dir <klasor>\n\n", Red, Reset)
				usage(program)
				return options{}, false
			}
			i++
			opts.quarantineDir = args[i]
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
	fmt.Printf("  %s-q%s  viruslu bulunan dosyalari karantinaya al\n", Cyan, Reset)
	fmt.Printf("  %s--no-recursive%s  klasor tararken alt klasorlere girme\n", Cyan, Reset)
	fmt.Printf("  %s--quarantine-dir%s <klasor>  karantina klasoru\n", Cyan, Reset)
	fmt.Printf("  %s-h%s  yardim\n\n", Cyan, Reset)

	fmt.Printf("%sLinux ornekleri:%s\n", Bold, Reset)
	fmt.Printf("  %s ./suspicious\n", program)
	fmt.Printf("  %s ./suspicious -a\n", program)
	fmt.Printf("  %s /bin/ls -s\n", program)
	fmt.Printf("  %s ~/Downloads -a\n", program)
	fmt.Printf("  %s /media/$USER/USB_ADI -a\n", program)
	fmt.Printf("  %s /media/$USER/USB_ADI -a -q\n", program)
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
	if info.IsDir() {
		runDirectoryScan(opts, info)
		return
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

	data, err := os.ReadFile(opts.filePath)
	if err != nil {
		fmt.Printf("  %s[HATA]%s Dosya okunamadi: %s\n", Red, Reset, friendlyError(err))
		os.Exit(1)
	}

	section("HASH DEGERLERI")
	hashes := hasher.ComputeHashesFromBytes(data)
	fieldColor("MD5", hashes.MD5, Green)
	fieldColor("SHA1", hashes.SHA1, Green)
	fieldColor("SHA256", hashes.SHA256, Green)

	section("ENTROPI ANALIZI")
	ent := entropy.CalculateFromBytes(data)
	color := Green
	if ent > 7.0 {
		color = Red
	} else if ent > 5.0 {
		color = Yellow
	}
	fieldColor("Entropi", fmt.Sprintf("%.4f / 8.0", ent), color)
	field("Yorum", entropy.Verdict(ent))

	if fileType == analyzer.ELF {
		printELF(opts.filePath)
	}
	if fileType == analyzer.PE {
		printPE(opts.filePath, opts)
	}

	matches := printRules(data)
	suspiciousCount := printStrings(data, opts)
	score := printScore(ent, matches, suspiciousCount)
	result := fileSummary{
		path:                 opts.filePath,
		fileType:             fileTypeStr,
		sha256:               hashes.SHA256,
		entropy:              ent,
		ruleMatches:          matches,
		suspiciousCategories: suspiciousCount,
		score:                score,
	}
	printVirusAnalysis(result)
	if opts.quarantine && isVirus(result) {
		if quarantinedPath, err := quarantineFile(result, opts); err != nil {
			fmt.Printf("  %s[HATA]%s Karantina basarisiz: %s\n", Red, Reset, friendlyError(err))
		} else {
			fmt.Printf("  %sKarantinaya alindi:%s %s\n", Yellow, Reset, quarantinedPath)
		}
	}

	fmt.Printf("\n%sAnaliz tamamlandi: %v%s\n\n", Dim, time.Since(startTime), Reset)
}

func runDirectoryScan(opts options, info os.FileInfo) {
	absPath, _ := filepath.Abs(opts.filePath)
	section("KLASOR / USB TARAMASI")
	field("Hedef", absPath)
	field("Mod", recursiveLabel(opts.recursive))
	field("Boyut", analyzer.FormatSize(info.Size()))
	if opts.quarantine {
		field("Karantina", opts.quarantineDir)
	}

	startTime := time.Now()
	var scanned, skipped, risky, quarantined int
	var highest fileSummary
	highest.score = -1

	err := filepath.WalkDir(opts.filePath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			skipped++
			fmt.Printf("  %s[ATLANDI]%s %s: %s\n", Yellow, Reset, path, friendlyError(walkErr))
			return nil
		}
		if path != opts.filePath && entry.IsDir() && !opts.recursive {
			return filepath.SkipDir
		}
		if entry.IsDir() && isInsideQuarantine(path, opts.quarantineDir) {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			skipped++
			fmt.Printf("  %s[ATLANDI]%s %s: %s\n", Yellow, Reset, path, friendlyError(err))
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		result := analyzeFile(path)
		scanned++
		if result.err != nil {
			skipped++
			fmt.Printf("  %s[ATLANDI]%s %s: %s\n", Yellow, Reset, path, friendlyError(result.err))
			return nil
		}
		if result.score >= 20 || len(result.ruleMatches) > 0 {
			risky++
		}
		if opts.quarantine && isVirus(result) {
			if quarantinedPath, err := quarantineFile(result, opts); err != nil {
				fmt.Printf("  %s[HATA]%s Karantina basarisiz: %s: %s\n", Red, Reset, path, friendlyError(err))
			} else {
				quarantined++
				result.path = quarantinedPath
			}
		}
		if result.score > highest.score {
			highest = result
		}
		printFileSummary(result)
		return nil
	})
	if err != nil {
		fmt.Printf("  %s[HATA]%s Klasor taranamadi: %s\n", Red, Reset, friendlyError(err))
		os.Exit(1)
	}

	section("OZET")
	field("Taranan dosya", fmt.Sprintf("%d", scanned))
	field("Riskli dosya", fmt.Sprintf("%d", risky))
	field("Karantina", fmt.Sprintf("%d", quarantined))
	field("Atlanan", fmt.Sprintf("%d", skipped))
	if highest.score >= 0 {
		field("En yuksek risk", fmt.Sprintf("%d/100 - %s", highest.score, highest.path))
	}
	fmt.Printf("\n%sKlasor taramasi tamamlandi: %v%s\n\n", Dim, time.Since(startTime), Reset)
}

func analyzeFile(path string) fileSummary {
	result := fileSummary{path: path}

	_, fileTypeStr, err := analyzer.DetectFileType(path)
	if err != nil {
		result.fileType = "Belirlenemedi"
	} else {
		result.fileType = fileTypeStr
	}

	data, err := os.ReadFile(path)
	if err != nil {
		result.err = err
		return result
	}

	hashes := hasher.ComputeHashesFromBytes(data)
	result.sha256 = hashes.SHA256
	result.entropy = entropy.CalculateFromBytes(data)
	result.ruleMatches = yara_rules.Scan(data, yara_rules.DefaultRules())
	strs := strings_extract.ExtractFromBytes(data, 6)
	result.suspiciousCategories = len(strings_extract.FindSuspicious(strs))
	result.score = calculateThreatScore(result.entropy, result.ruleMatches, result.suspiciousCategories)

	return result
}

func printFileSummary(result fileSummary) {
	color := Green
	if result.score > 60 {
		color = Red
	} else if result.score > 20 {
		color = Yellow
	}

	shortHash := result.sha256
	if len(shortHash) > 12 {
		shortHash = shortHash[:12]
	}
	fmt.Printf("  %s%3d/100%s  rules:%-2d strings:%-2d ent:%4.2f hash:%s  %s\n",
		color, result.score, Reset,
		len(result.ruleMatches), result.suspiciousCategories, result.entropy, shortHash, result.path)
}

func recursiveLabel(recursive bool) string {
	if recursive {
		return "recursive"
	}
	return "sadece bu klasor"
}

func friendlyError(err error) string {
	if err == nil {
		return ""
	}
	if os.IsPermission(err) {
		return fmt.Sprintf("%v (okuma izni yok; USB icin mount iznini kontrol et veya gerekirse sudo ile calistir)", err)
	}
	if os.IsNotExist(err) {
		return fmt.Sprintf("%v (dosya yolu bulunamadi)", err)
	}
	return err.Error()
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

func printStrings(data []byte, opts options) int {
	section("SUPHELI STRINGLER")
	strs := strings_extract.ExtractFromBytes(data, 6)

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

func printScore(ent float64, matches []yara_rules.Match, suspiciousCategories int) int {
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
	return score
}

func printVirusAnalysis(result fileSummary) {
	section("VIRUS ANALIZI")
	if isVirus(result) {
		fmt.Printf("  %sDurum:%s %sVIRUSLU / COK RISKLI%s\n", Bold, Reset, Red+Bold, Reset)
	} else if result.score >= 20 || len(result.ruleMatches) > 0 {
		fmt.Printf("  %sDurum:%s %sSUPHELI%s\n", Bold, Reset, Yellow, Reset)
	} else {
		fmt.Printf("  %sDurum:%s %sTemiz gorunuyor%s\n", Bold, Reset, Green, Reset)
	}
	field("Skor", fmt.Sprintf("%d/100", result.score))
	field("Imza eslesmesi", fmt.Sprintf("%d", len(result.ruleMatches)))
	field("Supheli kategori", fmt.Sprintf("%d", result.suspiciousCategories))
	if hasCriticalRule(result.ruleMatches) {
		fieldColor("Kritik imza", "var", Red+Bold)
	}
}

func isVirus(result fileSummary) bool {
	return result.score >= 60 || hasCriticalRule(result.ruleMatches)
}

func hasCriticalRule(matches []yara_rules.Match) bool {
	for _, match := range matches {
		if match.Severity == "critical" {
			return true
		}
	}
	return false
}

func quarantineFile(result fileSummary, opts options) (string, error) {
	if err := os.MkdirAll(opts.quarantineDir, 0o700); err != nil {
		return "", err
	}

	absSource, _ := filepath.Abs(result.path)
	base := sanitizeName(filepath.Base(result.path))
	if base == "" {
		base = "file"
	}
	targetName := fmt.Sprintf("%s_%s_%s.quarantine", time.Now().Format("20060102-150405"), shortHash(result.sha256), base)
	targetPath := filepath.Join(opts.quarantineDir, targetName)

	if err := moveFile(result.path, targetPath); err != nil {
		return "", err
	}
	if err := writeQuarantineMeta(targetPath+".meta.txt", absSource, result); err != nil {
		return targetPath, err
	}
	return targetPath, nil
}

func moveFile(source, target string) error {
	if err := os.Rename(source, target); err == nil {
		return nil
	}

	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(target)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(target)
		return closeErr
	}
	return os.Remove(source)
}

func writeQuarantineMeta(path, source string, result fileSummary) error {
	var b strings.Builder
	b.WriteString("file-cheeker quarantine metadata\n")
	b.WriteString(fmt.Sprintf("time: %s\n", time.Now().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("source: %s\n", source))
	b.WriteString(fmt.Sprintf("sha256: %s\n", result.sha256))
	b.WriteString(fmt.Sprintf("score: %d/100\n", result.score))
	b.WriteString(fmt.Sprintf("entropy: %.4f\n", result.entropy))
	b.WriteString(fmt.Sprintf("file_type: %s\n", result.fileType))
	b.WriteString("rules:\n")
	for _, match := range result.ruleMatches {
		b.WriteString(fmt.Sprintf("- [%s] %s\n", strings.ToUpper(match.Severity), match.RuleName))
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func sanitizeName(name string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(name)
}

func shortHash(hash string) string {
	if len(hash) >= 12 {
		return hash[:12]
	}
	if hash == "" {
		return "nohash"
	}
	return hash
}

func isInsideQuarantine(path, quarantineDir string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absQuarantine, err := filepath.Abs(quarantineDir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absQuarantine, absPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
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
