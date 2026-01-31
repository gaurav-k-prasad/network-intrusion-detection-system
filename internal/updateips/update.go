package updateips

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"nids/internal/trie"
	"os"
	"strconv"
	"strings"
)

func DownloadIPs(path string) error {
	baseURL := "https://raw.githubusercontent.com"

	noteName := "firehol/blocklist-ipsets/master/firehol_level1.netset"

	// Send a GET request to download the file
	resp, err := http.Get(fmt.Sprintf("%s/%s", baseURL, noteName))
	if err != nil {
		return fmt.Errorf("error occurred: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error occurred: %s", resp.Status)
	}

	// Save the file locally
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %v", err)
	}

	// Create (or overwrite) the file and write all data at once
	err = os.WriteFile(path, body, 0644)
	if err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}
	return nil
}

func GetIpTrie(path string) (*trie.Trie, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)

	t := trie.CreateTrie()
	for scanner.Scan() {
		txt := strings.TrimSpace(scanner.Text())
		if txt == "" || strings.HasPrefix(txt, "#") {
			continue
		}

		vals := strings.Split(txt, "/")
		if len(vals) != 2 {
			// skip malformed lines
			continue
		}
		ip := vals[0]
		cidr, err := strconv.ParseInt(vals[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr in line %q: %w", txt, err)
		}

		if err := t.InsertIP(ip, int(cidr)); err != nil {
			return nil, err
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return t, nil
}
