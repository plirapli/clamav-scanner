package clamav

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type VirusFoundError struct {
	Name string
}

func (e *VirusFoundError) Error() string {
	return fmt.Sprintf("virus found: %s", e.Name)
}

func (e *VirusFoundError) VirusName() string {
	return e.Name
}

type Client struct {
	addr string
}

func NewClient(addr string) Client {
	return Client{addr: addr}
}

func (c Client) Scan(reader io.Reader) error {
	conn, err := net.DialTimeout("tcp", c.addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return err
	}

	buffer := make([]byte, 32*1024)
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			chunkSize := make([]byte, 4)
			binary.BigEndian.PutUint32(chunkSize, uint32(n))
			if _, err := conn.Write(chunkSize); err != nil {
				return err
			}
			if _, err := conn.Write(buffer[:n]); err != nil {
				return err
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return err
	}

	response, err := bufio.NewReader(conn).ReadString('\x00')
	if err != nil && err != io.EOF {
		return err
	}

	response = strings.TrimSpace(strings.TrimRight(response, "\x00"))
	if strings.HasSuffix(response, "OK") {
		return nil
	}
	if strings.Contains(response, "FOUND") {
		name := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(response, "stream:"), "FOUND"))
		return &VirusFoundError{Name: name}
	}
	return fmt.Errorf("clamav scan failed: %s", response)
}

func (c Client) Version() (int64, error) {
	conn, err := net.DialTimeout("tcp", c.addr, 10*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("zVERSION\x00")); err != nil {
		return 0, err
	}

	response, err := bufio.NewReader(conn).ReadString('\x00')
	if err != nil && err != io.EOF {
		return 0, err
	}

	response = strings.Trim(strings.TrimSpace(response), "\x00")
	parts := strings.Split(response, "/")
	if len(parts) < 2 {
		return 0, fmt.Errorf("unexpected version reply: %s", response)
	}

	var dbVersion int64
	for _, char := range parts[1] {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("unexpected db version: %s", parts[1])
		}
		dbVersion = dbVersion*10 + int64(char-'0')
	}

	return dbVersion, nil
}
