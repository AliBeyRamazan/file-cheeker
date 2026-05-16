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

// ComputeHashesFromBytes computes MD5, SHA1, SHA256 from already-read data.
func ComputeHashesFromBytes(data []byte) *HashResult {
	md5Sum := md5.Sum(data)
	sha1Sum := sha1.Sum(data)
	sha256Sum := sha256.Sum256(data)

	return &HashResult{
		MD5:    hex.EncodeToString(md5Sum[:]),
		SHA1:   hex.EncodeToString(sha1Sum[:]),
		SHA256: hex.EncodeToString(sha256Sum[:]),
		Size:   int64(len(data)),
	}
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
