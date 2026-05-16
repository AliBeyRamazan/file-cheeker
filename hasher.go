package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashResult holds all computed hash values for a file
type HashResult struct {
	MD5    string
	SHA1   string
	SHA256 string
	Size   int64
}

// ComputeHashes reads a file and computes MD5, SHA1, SHA256 simultaneously
func ComputeHashes(filepath string) (*HashResult, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("fayl açıla bilmədi: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("fayl məlumatı alına bilmədi: %w", err)
	}

	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()

	multiWriter := io.MultiWriter(md5h, sha1h, sha256h)

	if _, err := io.Copy(multiWriter, f); err != nil {
		return nil, fmt.Errorf("həş hesablanarkən xəta: %w", err)
	}

	return &HashResult{
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
		Size:   info.Size(),
	}, nil
}
