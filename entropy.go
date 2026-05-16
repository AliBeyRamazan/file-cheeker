package entropy

import (
	"fmt"
	"io"
	"math"
	"os"
)

// Calculate computes Shannon entropy of a file (0.0 - 8.0)
// High entropy (>7.0) suggests encryption/compression/packing
func Calculate(filepath string) (float64, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return 0, fmt.Errorf("fayl açıla bilmədi: %w", err)
	}
	defer f.Close()

	return CalculateFromReader(f)
}

// CalculateFromReader computes Shannon entropy from any reader
func CalculateFromReader(r io.Reader) (float64, error) {
	var freq [256]float64
	var total float64

	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		for i := 0; i < n; i++ {
			freq[buf[i]]++
			total++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("oxunarkən xəta: %w", err)
		}
	}

	if total == 0 {
		return 0, nil
	}

	var entropy float64
	for _, count := range freq {
		if count > 0 {
			p := count / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy, nil
}

// CalculateFromBytes computes entropy for a byte slice
func CalculateFromBytes(data []byte) float64 {
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

// Verdict returns a human-readable assessment of entropy level
func Verdict(entropy float64) string {
	switch {
	case entropy < 1.0:
		return "Çox aşağı (boş/təkrarlanan məlumat)"
	case entropy < 3.0:
		return "Aşağı (strukturlaşdırılmış məlumat)"
	case entropy < 5.0:
		return "Orta (normal icra edilə bilən)"
	case entropy < 7.0:
		return "Yüksək (sıxılmış bölmələr ola bilər)"
	case entropy < 7.5:
		return "⚠ Çox yüksək (sıxılmış/paketlənmiş)"
	default:
		return "🚨 Həddindən artıq yüksək (şifrələnmiş/paketlənmiş - ŞÜBHƏLİ)"
	}
}
