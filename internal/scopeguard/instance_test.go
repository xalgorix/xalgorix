package scopeguard

import "testing"

func TestIsInstanceService(t *testing.T) {
	yes := []string{
		"169.254.169.254",
		"169.254.169.254:80",
		"169.254.169.254:443",
		"169.254.170.2:80",
		"[fd00:ec2::254]:80",
		"fd00:ec2::254",
		"[::ffff:169.254.169.254]:80",
		"[::ffff:a9fe:a9fe]:80",
		"100.100.100.200:80",
		"168.63.129.16:80",
		"2852039166:80",       // 169.254.169.254 as one decimal number
		"0xa9.0xfe.0xa9.0xfe", // hexadecimal parts
		"0251.0376.0251.0376", // octal parts
		"metadata.google.internal:80",
		"METADATA.GOOGLE.INTERNAL.:80",
		"metadata.goog",
		"metadata:80",
		"instance-data.ec2.internal:80",
		"[fd20:ce::254]:80",
		"[fe80::a9fe:a9fe]:80",
		"169.254.170.23:80",
		"192.0.0.192:80",
		" 169.254.169.254:80 ",
	}
	for _, a := range yes {
		if !IsInstanceService(a) {
			t.Errorf("IsInstanceService(%q) = false, want true", a)
		}
	}
	no := []string{
		"",
		"169.254.10.5:80",
		"93.184.216.34:443",
		"10.0.0.1:80",
		"127.0.0.1:80",
		"example.com:443",
		"169.254.169.254.nip.io:80", // a name: resolved and checked when dialed
		"metadata.google.internal.example.com:80",
		"[fd00:ec2::253]:80",
	}
	for _, a := range no {
		if IsInstanceService(a) {
			t.Errorf("IsInstanceService(%q) = true, want false", a)
		}
	}
}

func TestIsLinkLocal(t *testing.T) {
	yes := []string{
		"169.254.0.1",
		"169.254.10.5:8080",
		"169.254.169.254:80",
		"[fe80::1]:80",
		"[fe80::1%eth0]:80",
		"fe80::abcd",
		"[::ffff:169.254.1.1]:80",
		"2851995905:80", // 169.254.0.1
	}
	for _, a := range yes {
		if !IsLinkLocal(a) {
			t.Errorf("IsLinkLocal(%q) = false, want true", a)
		}
	}
	no := []string{
		"",
		"169.253.255.255:80",
		"169.255.0.1:80",
		"10.0.0.1:80",
		"192.168.1.1:80",
		"[fd12::1]:80",
		"[fc00::1]:80",
		"100.100.100.200:80",
		"printer.local:80",
	}
	for _, a := range no {
		if IsLinkLocal(a) {
			t.Errorf("IsLinkLocal(%q) = true, want false", a)
		}
	}
}

func TestSameAddress(t *testing.T) {
	same := [][2]string{
		{"169.254.10.5", "169.254.10.5:8080"},
		{"169.254.10.5", "[::ffff:169.254.10.5]:80"},
		{"fe80::2", "[fe80::2%eth0]:443"},
		{"[fe80::2]", "fe80:0:0:0:0:0:0:2"},
	}
	for _, p := range same {
		if !SameAddress(p[0], p[1]) {
			t.Errorf("SameAddress(%q, %q) = false, want true", p[0], p[1])
		}
	}
	differ := [][2]string{
		{"169.254.10.5", "169.254.10.6:80"},
		{"printer.local", "printer.local:80"}, // names never match
		{"", ""},
	}
	for _, p := range differ {
		if SameAddress(p[0], p[1]) {
			t.Errorf("SameAddress(%q, %q) = true, want false", p[0], p[1])
		}
	}
}
