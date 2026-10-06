package main

import (
	"errors"
	"golang.org/x/net/idna"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type ScopeRule struct {
	Scheme, Host, Path string
	Port               int
	Subdomains         bool
}

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var ambiguousPath = regexp.MustCompile(`(?i)%2f|%5c|%2e`)
var decimalPort = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
var numericHost = regexp.MustCompile(`^[0-9.]+$`)

func normalizeHost(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, "% /@?#\\\t\r\n") {
		return "", errors.New("E_HOST")
	}
	if strings.Contains(value, ":") {
		if strings.Contains(value, ".") {
			return "", errors.New("E_HOST")
		}
		addr, e := netip.ParseAddr(value)
		if e != nil || !addr.Is6() {
			return "", errors.New("E_HOST")
		}
		return addr.String(), nil
	}
	profile := idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(true), idna.ValidateLabels(true), idna.VerifyDNSLength(true))
	ascii, e := profile.ToASCII(strings.TrimSuffix(value, "."))
	if e != nil {
		return "", errors.New("E_HOST")
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", errors.New("E_HOST")
	}
	for _, label := range strings.Split(ascii, ".") {
		if !domainLabel.MatchString(label) {
			return "", errors.New("E_HOST")
		}
	}
	if numericHost.MatchString(ascii) {
		addr, e := netip.ParseAddr(ascii)
		if e != nil || !addr.Is4() {
			return "", errors.New("E_HOST")
		}
	}
	if regexp.MustCompile(`^0x[0-9a-f]+(?:\..*)?$`).MatchString(ascii) {
		return "", errors.New("E_HOST")
	}
	return ascii, nil
}
func normalizeScope(value string) (ScopeRule, error) {
	rule := ScopeRule{}
	if len(value) == 0 || len(value) > 8192 || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \\\r\n\t@?#") {
		return rule, errors.New("E_HOST")
	}
	rest := value
	if parts := strings.SplitN(value, "://", 2); len(parts) == 2 {
		rule.Scheme = strings.ToLower(parts[0])
		rest = parts[1]
		if rule.Scheme != "http" && rule.Scheme != "https" {
			return rule, errors.New("E_HOST")
		}
	}
	authority := strings.SplitN(rest, "/", 2)[0]
	if strings.Contains(rest, "/") {
		if rule.Scheme == "" {
			return rule, errors.New("E_HOST")
		}
		rule.Path = rest[len(authority):]
	}
	rule.Subdomains = strings.HasPrefix(authority, "*.")
	authority = strings.TrimPrefix(authority, "*.")
	if strings.Contains(authority, "*") {
		return rule, errors.New("E_HOST")
	}
	host := authority
	port := ""
	if strings.HasPrefix(authority, "[") {
		end := strings.Index(authority, "]")
		if end < 2 {
			return rule, errors.New("E_HOST")
		}
		host = authority[1:end]
		suffix := authority[end+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") {
				return rule, errors.New("E_HOST")
			}
			port = suffix[1:]
			if port == "" {
				return rule, errors.New("E_HOST")
			}
		}
	} else if strings.Count(authority, ":") == 1 {
		parts := strings.SplitN(authority, ":", 2)
		host = parts[0]
		port = parts[1]
		if port == "" {
			return rule, errors.New("E_HOST")
		}
	}
	var e error
	rule.Host, e = normalizeHost(host)
	if e != nil {
		return rule, e
	}
	if rule.Subdomains && (strings.Contains(rule.Host, ":") || numericHost.MatchString(rule.Host) || !strings.Contains(rule.Host, ".")) {
		return rule, errors.New("E_HOST")
	}
	if port != "" {
		if !decimalPort.MatchString(port) {
			return rule, errors.New("E_HOST")
		}
		rule.Port, _ = strconv.Atoi(port)
		if rule.Port < 1 || rule.Port > 65535 {
			return rule, errors.New("E_HOST")
		}
	}
	if ambiguousPath.MatchString(rule.Path) {
		return rule, errors.New("E_HOST")
	}
	for _, segment := range strings.Split(rule.Path, "/") {
		if segment == "." || segment == ".." {
			return rule, errors.New("E_HOST")
		}
	}
	if _, e = url.Parse("https://example.test" + rule.Path); e != nil {
		return rule, errors.New("E_HOST")
	}
	return rule, nil
}
func allows(specs []string, target string) bool {
	u, e := url.Parse(target)
	if e != nil || u.User != nil || u.Fragment != "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	candidate, e := normalizeScope(u.Scheme + "://" + u.Host + u.EscapedPath())
	if e != nil {
		return false
	}
	for _, value := range specs {
		rule, e := normalizeScope(value)
		if e != nil {
			continue
		}
		host := candidate.Host == rule.Host
		if rule.Subdomains {
			host = strings.HasSuffix(candidate.Host, "."+rule.Host)
		}
		if !host || rule.Scheme != "" && rule.Scheme != candidate.Scheme {
			continue
		}
		port := candidate.Port
		if port == 0 {
			port = 443
			if candidate.Scheme == "http" {
				port = 80
			}
		}
		required := rule.Port
		if required == 0 && rule.Scheme != "" {
			required = 443
			if rule.Scheme == "http" {
				required = 80
			}
		}
		if required != 0 && required != port {
			continue
		}
		if rule.Path == "" || rule.Path == "/" || candidate.Path == rule.Path || strings.HasPrefix(candidate.Path, strings.TrimRight(rule.Path, "/")+"/") {
			return true
		}
	}
	return false
}
func privateAddress(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() || netip.MustParsePrefix("100.64.0.0/10").Contains(addr)
}
func verifyResolution(specs []string, hostname string, ips []net.IP) error {
	if len(ips) == 0 {
		return errors.New("E_HOST")
	}
	for _, ip := range ips {
		if !privateAddress(ip) {
			continue
		}
		explicit := false
		for _, value := range specs {
			rule, e := normalizeScope(value)
			if e != nil || rule.Subdomains {
				continue
			}
			literal := net.ParseIP(rule.Host)
			if literal != nil && privateAddress(literal) && literal.Equal(ip) || (rule.Host == "localhost" || strings.HasSuffix(rule.Host, ".localhost")) && rule.Host == strings.ToLower(hostname) && ip.IsLoopback() {
				explicit = true
				break
			}
		}
		if !explicit {
			return errors.New("E_PRIVATE_DESTINATION")
		}
	}
	return nil
}
