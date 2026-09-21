package quarantine

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrInvalidHash = errors.New("invalid sha256")

type Store struct {
	dir string
}

func New(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("quarantine directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Dir() string {
	if s == nil {
		return ""
	}
	return s.dir
}

// Save stores the file bytes keyed by SHA-256. Existing artifacts are kept.
func (s *Store) Save(sha256 string, data []byte) (string, error) {
	if sha256 == "" {
		return "", ErrInvalidHash
	}

	path := filepath.Join(s.dir, sha256)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return path, nil
		}
		return "", err
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return "", err
	}

	return path, nil
}
