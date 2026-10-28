package collect

import (
	"encoding/json"
	"net"
	"strings"
)

type TailscaleInfo struct {
	Name string `json:"name,omitempty"`
	IP   string `json:"ip,omitempty"`
}

func IsTailscaleAddress(ip net.IP) bool {
	_, v4, _ := net.ParseCIDR("100.64.0.0/10")
	_, v6, _ := net.ParseCIDR("fd7a:115c:a1e0::/48")
	return v4.Contains(ip) || v6.Contains(ip)
}

func TailscaleIPv4() string {
	iface, err := net.InterfaceByName("tailscale0")
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if network, ok := addr.(*net.IPNet); ok && network.IP.To4() != nil && IsTailscaleAddress(network.IP) {
			return network.IP.String()
		}
	}
	return ""
}

func TailscaleName(status []byte) string {
	var parsed struct {
		Self struct {
			DNSName string `json:"DNSName"`
		} `json:"Self"`
	}
	if json.Unmarshal(status, &parsed) != nil {
		return ""
	}
	return strings.TrimSuffix(parsed.Self.DNSName, ".")
}

func tailscaleInfo(name string) *TailscaleInfo {
	info := TailscaleInfo{Name: name, IP: TailscaleIPv4()}
	if info.Name == "" && info.IP == "" {
		return nil
	}
	return &info
}
