package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"scanner-service/config"
	"scanner-service/core/scanner/interfaces"
	"scanner-service/infra/clamav"
)

const (
	bazaarAPI      = "https://mb-api.abuse.ch/api/v1/"
	bazaarPassword = "infected"
	defaultTypes   = "exe,dll,doc,docm,xls,xlsm,pdf,js,vbs,ps1,hta,zip"
)

// runFetchMalware pulls recent MalwareBazaar samples, scans them with the local
// ClamAV and keeps only the ones it misses. Detected samples never touch the
// corpus; downloads stay in an encrypted zip until they are scanned in memory.
func runFetchMalware(args []string) error {
	flags := flag.NewFlagSet("fetch-malware", flag.ExitOnError)
	manifestPath := flags.String("manifest", "../eval/manifest.json", "manifest path")
	corpusDir := flags.String("corpus", "../eval/corpus", "corpus directory")
	types := flags.String("types", defaultTypes, "comma-separated MalwareBazaar file types")
	perType := flags.Int("per-type", 10, "ClamAV misses to keep per file type")
	candidates := flags.Int("candidates", 100, "recent samples to consider per file type (max 1000)")
	_ = flags.Parse(args)

	cfg := config.Load()
	apiKey := strings.TrimSpace(os.Getenv("MALWAREBAZAAR_API_KEY"))
	if apiKey == "" {
		return errors.New("MALWAREBAZAAR_API_KEY is not set (get a free key at https://auth.abuse.ch/)")
	}
	sevenZip, err := findSevenZip()
	if err != nil {
		return err
	}

	samples, err := loadManifest(*manifestPath)
	if err != nil {
		return err
	}
	known := knownPaths(samples)

	bazaar := bazaarClient{apiKey: apiKey, http: &http.Client{Timeout: 2 * time.Minute}}
	scanner := clamav.NewClient(cfg.ClamAVAddr)
	if _, err := scanner.Version(); err != nil {
		return fmt.Errorf("clamav not reachable at %s: %w", cfg.ClamAVAddr, err)
	}
	ensureNoIndex(*corpusDir)

	added := 0
	for _, fileType := range splitList(*types) {
		list, err := bazaar.recent(fileType, *candidates)
		if err != nil {
			fmt.Printf("[%s] list failed: %v\n", fileType, err)
			continue
		}

		kept, detected, skipped := 0, 0, 0
		for _, entry := range list {
			if kept >= *perType {
				break
			}
			path := filepath.ToSlash(filepath.Join("malware", "bazaar", fileType, entry.SHA256+"."+fileType))
			if known[path] || entry.FileSize > cfg.MaxScanSize {
				skipped++
				continue
			}

			data, err := bazaar.download(entry.SHA256, sevenZip)
			if err != nil {
				fmt.Printf("[%s] %s download failed: %v\n", fileType, short(entry.SHA256), err)
				skipped++
				continue
			}

			signature, err := scanBytes(scanner, data)
			if err != nil {
				fmt.Printf("[%s] %s clamav error: %v\n", fileType, short(entry.SHA256), err)
				skipped++
				continue
			}
			if signature != "" {
				detected++
				continue
			}

			if err := writeSample(*corpusDir, path, data, 0o600); err != nil {
				return err
			}
			tags := []string{"malwarebazaar", fileType, "clamav-missed"}
			if entry.Signature != "" {
				tags = append(tags, "family:"+entry.Signature)
			}
			samples.Samples = append(samples.Samples, manifestSample{Path: path, Expected: "malware", Tags: tags})
			known[path] = true
			kept++
			added++
			fmt.Printf("[%s] kept %s (%s)\n", fileType, short(entry.SHA256), orDash(entry.Signature))

			// MalwareBazaar fair use: keep the request rate low.
			time.Sleep(time.Second)
		}
		fmt.Printf("[%s] kept %d, clamav detected %d, skipped %d\n", fileType, kept, detected, skipped)
	}

	if added == 0 {
		fmt.Println("no new samples")
		return nil
	}
	if err := saveManifest(*manifestPath, samples); err != nil {
		return err
	}
	fmt.Printf("added %d malware samples to %s\n", added, *manifestPath)
	return nil
}

// runFetchBenign downloads the benign samples listed in a TSV file
// (path, url, comma-separated tags) and adds them to the manifest.
func runFetchBenign(args []string) error {
	flags := flag.NewFlagSet("fetch-benign", flag.ExitOnError)
	manifestPath := flags.String("manifest", "../eval/manifest.json", "manifest path")
	corpusDir := flags.String("corpus", "../eval/corpus", "corpus directory")
	sourcesPath := flags.String("sources", "../eval/benign-sources.tsv", "TSV of path, url, tags")
	_ = flags.Parse(args)

	cfg := config.Load()
	sources, err := loadSources(*sourcesPath)
	if err != nil {
		return err
	}
	samples, err := loadManifest(*manifestPath)
	if err != nil {
		return err
	}
	known := knownPaths(samples)

	scanner := clamav.NewClient(cfg.ClamAVAddr)
	if _, err := scanner.Version(); err != nil {
		return fmt.Errorf("clamav not reachable at %s: %w", cfg.ClamAVAddr, err)
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	ensureNoIndex(*corpusDir)

	added := 0
	for _, source := range sources {
		if _, err := os.Stat(filepath.Join(*corpusDir, source.Path)); err == nil && known[source.Path] {
			continue
		}

		data, err := httpGet(client, source.URL, cfg.MaxScanSize)
		if err == nil && source.Member != "" {
			data, err = zipMember(data, source.Member, cfg.MaxScanSize)
		}
		if err != nil {
			fmt.Printf("%-48s download failed: %v\n", source.Path, err)
			continue
		}

		tags := source.Tags
		signature, err := scanBytes(scanner, data)
		if err != nil {
			fmt.Printf("%-48s clamav error: %v\n", source.Path, err)
			continue
		}
		if signature != "" {
			// Kept on purpose: a ClamAV false positive on a benign file is part
			// of what the eval should measure.
			fmt.Printf("%-48s WARNING clamav detected %s\n", source.Path, signature)
			tags = append(tags, "clamav-detected")
		}

		if err := writeSample(*corpusDir, source.Path, data, 0o644); err != nil {
			return err
		}
		if !known[source.Path] {
			samples.Samples = append(samples.Samples, manifestSample{Path: source.Path, Expected: "benign", Tags: tags})
			known[source.Path] = true
			added++
		}
		fmt.Printf("%-48s %d bytes\n", source.Path, len(data))
	}

	if added == 0 {
		fmt.Println("no new manifest entries")
		return nil
	}
	if err := saveManifest(*manifestPath, samples); err != nil {
		return err
	}
	fmt.Printf("added %d benign samples to %s\n", added, *manifestPath)
	return nil
}

type bazaarEntry struct {
	SHA256       string `json:"sha256_hash"`
	FileSize     int64  `json:"file_size"`
	Signature    string `json:"signature"`
	Intelligence struct {
		ClamAV []string `json:"clamav"`
	} `json:"intelligence"`
}

type bazaarClient struct {
	apiKey string
	http   *http.Client
}

func (b bazaarClient) post(form url.Values) (*http.Response, error) {
	request, err := http.NewRequest(http.MethodPost, bazaarAPI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Auth-Key", b.apiKey)
	return b.http.Do(request)
}

// recent lists the newest samples of a file type. Samples without any known
// ClamAV signature come first, since those are the likeliest local misses.
func (b bazaarClient) recent(fileType string, limit int) ([]bazaarEntry, error) {
	response, err := b.post(url.Values{"query": {"get_file_type"}, "file_type": {fileType}, "limit": {fmt.Sprint(limit)}})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var parsed struct {
		QueryStatus string        `json:"query_status"`
		Data        []bazaarEntry `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("status %d: %w", response.StatusCode, err)
	}
	if parsed.QueryStatus != "ok" {
		return nil, fmt.Errorf("query_status %s", parsed.QueryStatus)
	}

	sort.SliceStable(parsed.Data, func(i, j int) bool {
		return len(parsed.Data[i].Intelligence.ClamAV) == 0 && len(parsed.Data[j].Intelligence.ClamAV) > 0
	})
	return parsed.Data, nil
}

func (b bazaarClient) download(sha string, sevenZip string) ([]byte, error) {
	response, err := b.post(url.Values{"query": {"get_file"}, "sha256_hash": {sha}})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	archive, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(archive, []byte("PK")) {
		var parsed struct {
			QueryStatus string `json:"query_status"`
		}
		_ = json.Unmarshal(archive, &parsed)
		return nil, fmt.Errorf("status %d, query_status %s", response.StatusCode, orDash(parsed.QueryStatus))
	}

	temp, err := os.CreateTemp("", "bazaar-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(archive); err != nil {
		temp.Close()
		return nil, err
	}
	temp.Close()

	// MalwareBazaar zips may use AES, which archive/zip cannot read; 7z extracts
	// straight to memory so the plain sample is never written before scanning.
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(sevenZip, "e", "-so", "-p"+bazaarPassword, temp.Name())
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("7z: %v: %s", err, strings.TrimSpace(stderr.String()))
	}

	data := stdout.Bytes()
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != sha {
		return nil, fmt.Errorf("sha256 mismatch after extract: %s", short(got))
	}
	return data, nil
}

func findSevenZip() (string, error) {
	for _, name := range []string{"7z", "7zz"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", errors.New("7z not found (brew install sevenzip)")
}

type benignSource struct {
	Path string
	URL  string
	Tags []string
	// Member, when set, is the file to extract from the downloaded zip
	// (e.g. a DLL inside a NuGet package).
	Member string
}

func loadSources(path string) ([]benignSource, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var sources []benignSource
	lines := bufio.NewScanner(file)
	for number := 1; lines.Scan(); number++ {
		line := strings.TrimSpace(lines.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			return nil, fmt.Errorf("%s:%d: want path<TAB>url<TAB>tags[<TAB>zip member]", path, number)
		}
		source := benignSource{Path: strings.TrimSpace(fields[0]), URL: strings.TrimSpace(fields[1])}
		if len(fields) > 2 {
			source.Tags = splitList(fields[2])
		}
		if len(fields) > 3 {
			source.Member = strings.TrimSpace(fields[3])
		}
		sources = append(sources, source)
	}
	return sources, lines.Err()
}

func httpGet(client *http.Client, rawURL string, maxSize int64) ([]byte, error) {
	response, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", response.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("larger than MAX_SCAN_SIZE (%d bytes)", maxSize)
	}
	return data, nil
}

func zipMember(archive []byte, name string, maxSize int64) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, err
	}
	file, err := reader.Open(name)
	if err != nil {
		return nil, fmt.Errorf("zip member %s: %w", name, err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("zip member %s larger than MAX_SCAN_SIZE", name)
	}
	return data, nil
}

// scanBytes returns the ClamAV signature, or "" when the data is clean.
func scanBytes(client clamav.Client, data []byte) (string, error) {
	err := client.Scan(bytes.NewReader(data))
	if err == nil {
		return "", nil
	}
	var virusErr interfaces.VirusFoundError
	if errors.As(err, &virusErr) {
		return virusErr.VirusName(), nil
	}
	return "", err
}

func writeSample(corpusDir, path string, data []byte, mode os.FileMode) error {
	target := filepath.Join(corpusDir, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	return os.WriteFile(target, data, mode)
}

// ensureNoIndex keeps Spotlight from indexing (and previewing) the corpus.
func ensureNoIndex(corpusDir string) {
	if err := os.MkdirAll(corpusDir, 0o700); err == nil {
		_ = os.WriteFile(filepath.Join(corpusDir, ".metadata_never_index"), nil, 0o644)
	}
}

func loadManifest(path string) (manifest, error) {
	var samples manifest
	raw, err := os.ReadFile(path)
	if err != nil {
		return samples, err
	}
	return samples, json.Unmarshal(raw, &samples)
}

// saveManifest writes one sample per line to keep diffs readable.
func saveManifest(path string, samples manifest) error {
	quote := func(value string) string {
		encoded, _ := json.Marshal(value)
		return string(encoded)
	}

	var b strings.Builder
	b.WriteString("{\n  \"samples\": [\n")
	for index, sample := range samples.Samples {
		fmt.Fprintf(&b, "    { \"path\": %s, \"expected\": %s", quote(sample.Path), quote(sample.Expected))
		if len(sample.Tags) > 0 {
			tags := make([]string, len(sample.Tags))
			for i, tag := range sample.Tags {
				tags[i] = quote(tag)
			}
			fmt.Fprintf(&b, ", \"tags\": [%s]", strings.Join(tags, ", "))
		}
		b.WriteString(" }")
		if index < len(samples.Samples)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  ]\n}\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func knownPaths(samples manifest) map[string]bool {
	known := make(map[string]bool, len(samples.Samples))
	for _, sample := range samples.Samples {
		known[sample.Path] = true
	}
	return known
}

func splitList(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}
