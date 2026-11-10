package security

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

const listeningLimit = 200

func readListening(root string) []Listener {
	listeners := []Listener{}
	seen := map[string]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(hostPath(root, path))
		if err != nil {
			continue
		}
		for _, listener := range parseProcNet(file) {
			key := net.JoinHostPort(listener.Address, strconv.Itoa(listener.Port))
			if !seen[key] {
				seen[key] = true
				listeners = append(listeners, listener)
			}
		}
		file.Close()
	}
	sort.Slice(listeners, func(i, j int) bool {
		if listeners[i].Port != listeners[j].Port {
			return listeners[i].Port < listeners[j].Port
		}
		return listeners[i].Address < listeners[j].Address
	})
	if len(listeners) > listeningLimit {
		listeners = listeners[:listeningLimit]
	}
	return listeners
}

func parseProcNet(r io.Reader) []Listener {
	listeners := []Listener{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		hexAddress, hexPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		ip := decodeProcAddress(hexAddress)
		port, err := strconv.ParseUint(hexPort, 16, 16)
		if ip == nil || err != nil || ip.IsLoopback() {
			continue
		}
		listeners = append(listeners, Listener{Protocol: "tcp", Address: ip.String(), Port: int(port)})
	}
	return listeners
}

func decodeProcAddress(value string) net.IP {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 4 && len(raw) != 16 {
		return nil
	}
	ip := make(net.IP, len(raw))
	for word := 0; word < len(raw); word += 4 {
		for i := 0; i < 4; i++ {
			ip[word+i] = raw[word+3-i]
		}
	}
	return ip
}
