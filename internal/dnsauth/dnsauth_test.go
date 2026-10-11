package dnsauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

type fake struct {
	txt  map[string][]string
	mx   map[string][]*net.MX
	ptr  map[string][]string
	addr map[string][]net.IP
}

func nf(name string) error { return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true} }

func (f fake) LookupTXT(_ context.Context, n string) ([]string, error) {
	if v, ok := f.txt[n]; ok {
		return v, nil
	}
	return nil, nf(n)
}
func (f fake) LookupMX(_ context.Context, n string) ([]*net.MX, error) {
	if v, ok := f.mx[n]; ok {
		return v, nil
	}
	return nil, nf(n)
}
func (f fake) LookupAddr(_ context.Context, a string) ([]string, error) {
	if v, ok := f.ptr[a]; ok {
		return v, nil
	}
	return nil, nf(a)
}
func (f fake) LookupIP(_ context.Context, _, h string) ([]net.IP, error) {
	if v, ok := f.addr[strings.TrimSuffix(h, ".")]; ok {
		return v, nil
	}
	return nil, nf(h)
}

func key(t *testing.T, bits int) string {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return base64.StdEncoding.EncodeToString(der)
}

func byName(r Report) map[string]Check {
	m := map[string]Check{}
	for _, c := range r.Checks {
		if _, dup := m[c.Name]; !dup {
			m[c.Name] = c
		}
	}
	return m
}

func goodZone(t *testing.T) fake {
	return fake{
		txt: map[string][]string{
			"example.com":                 {"google-site-verification=x", "v=spf1 mx include:_spf.mailer.example ~all"},
			"_spf.mailer.example":         {"v=spf1 ip4:198.51.100.0/24 -all"},
			"mail._domainkey.example.com": {"v=DKIM1; k=rsa; p=" + key(t, 2048)},
			"_dmarc.example.com":          {"v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"},
		},
		mx:   map[string][]*net.MX{"example.com": {{Host: "mail.example.com.", Pref: 10}}},
		ptr:  map[string][]string{"203.0.113.7": {"mail.example.com."}},
		addr: map[string][]net.IP{"mail.example.com": {net.ParseIP("203.0.113.7")}},
	}
}

func TestHealthyDomain(t *testing.T) {
	r := Run(context.Background(), goodZone(t), Options{Domain: "example.com", IPs: []string{"203.0.113.7"}, HELO: "mail.example.com", Selectors: []string{"mail"}})
	for _, c := range r.Checks {
		if c.Status != OK {
			t.Errorf("%s: %s %s", c.Name, c.Status, c.Message)
		}
	}
	if r.Worst() != OK {
		t.Fatal(r.Worst())
	}
	m := byName(r)
	if !strings.Contains(m["spf"].Message, "2 of 10") {
		t.Errorf("lookups: %s", m["spf"].Message)
	}
	if !strings.Contains(m["spf-ip"].Message, "matched mx") {
		t.Errorf("spf-ip: %s", m["spf-ip"].Message)
	}
}

func TestSPFViaInclude(t *testing.T) {
	r := Run(context.Background(), goodZone(t), Options{Domain: "example.com", IPs: []string{"198.51.100.9"}, Selectors: []string{"mail"}})
	m := byName(r)
	if m["spf-ip"].Status != OK {
		t.Fatalf("%+v", m["spf-ip"])
	}
	if m["ptr"].Status != Fail {
		t.Fatalf("ptr should fail without PTR: %+v", m["ptr"])
	}
}

func TestBrokenDomain(t *testing.T) {
	z := fake{
		txt: map[string][]string{
			"bad.example":               {"v=spf1 a -all", "v=spf1 mx -all"},
			"s1._domainkey.bad.example": {"v=DKIM1; k=rsa; p=" + key(t, 1024)},
			"_dmarc.bad.example":        {"v=DMARC1; p=none"},
		},
		ptr:  map[string][]string{"192.0.2.5": {"host-5.isp.example."}},
		addr: map[string][]net.IP{"host-5.isp.example": {net.ParseIP("192.0.2.99")}},
	}
	r := Run(context.Background(), z, Options{Domain: "bad.example", IPs: []string{"192.0.2.5"}, Selectors: []string{"s1", "missing"}})
	m := byName(r)
	want := map[string]string{"mx": Warn, "spf": Fail, "dkim": Warn, "dmarc": Warn, "ptr": Fail}
	for k, v := range want {
		if m[k].Status != v {
			t.Errorf("%s = %s (%s), want %s", k, m[k].Status, m[k].Message, v)
		}
	}
	var missing bool
	for _, c := range r.Checks {
		if c.Name == "dkim" && strings.HasPrefix(c.Record, "missing.") && c.Status == Fail {
			missing = true
		}
	}
	if !missing {
		t.Error("missing selector not reported")
	}
}

func TestSPFLookupLimitAndPlusAll(t *testing.T) {
	txt := map[string][]string{"many.example": {"v=spf1 include:a.example include:b.example ~all"}}
	txt["a.example"] = []string{"v=spf1 a mx a:x mx:y ptr -all"}
	txt["b.example"] = []string{"v=spf1 a mx a:x mx:y exists:z -all"}
	r := Run(context.Background(), fake{txt: txt}, Options{Domain: "many.example", Selectors: []string{"none"}})
	if c := byName(r)["spf"]; c.Status != Fail || !strings.Contains(c.Message, "12 DNS lookups") {
		t.Fatalf("%+v", c)
	}
	r = Run(context.Background(), fake{txt: map[string][]string{"open.example": {"v=spf1 +all"}}}, Options{Domain: "open.example"})
	if c := byName(r)["spf"]; c.Status != Fail {
		t.Fatalf("+all: %+v", c)
	}
	r = Run(context.Background(), fake{}, Options{Domain: "none.example"})
	m := byName(r)
	if m["spf"].Status != Fail || m["dmarc"].Status != Fail || m["dkim"].Status != Warn {
		t.Fatalf("%+v", m)
	}
}

func TestPTRHeloMismatch(t *testing.T) {
	z := goodZone(t)
	r := Run(context.Background(), z, Options{Domain: "example.com", IPs: []string{"203.0.113.7"}, HELO: "other.example.com", Selectors: []string{"mail"}})
	if c := byName(r)["ptr"]; c.Status != Warn {
		t.Fatalf("%+v", c)
	}
}
