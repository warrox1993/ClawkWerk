package controls

import (
	"encoding/json"
	"testing"
	"time"
)

// horloge figée : 100 jours après l'epoch de référence utilisé dans les fixtures.
func fixedClock() func() time.Time {
	return func() time.Time { return time.Unix(100*86400, 0).UTC() }
}

func TestAntivirusWindowsNormalizer(t *testing.T) {
	raw := []byte(`{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":3}`)
	out, err := AntivirusWindowsNormalizer(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev AntivirusEvidence
	json.Unmarshal(out, &ev)
	if !ev.Present || !ev.Enabled || !ev.RealtimeProtection || ev.DefinitionsAgeDays != 3 {
		t.Fatalf("mapping Defender inattendu: %+v", ev)
	}
}

func TestAntivirusWindowsNormalizer_MissingField(t *testing.T) {
	if _, err := AntivirusWindowsNormalizer([]byte(`{"Foo":1}`)); err == nil {
		t.Fatal("champ AntivirusEnabled absent doit produire une erreur")
	}
}

func TestAntivirusLinuxNormalizer(t *testing.T) {
	// service actif, ClamAV présent, définitions à l'epoch 95 jours -> âge 5 j.
	raw := []byte("active\nClamAV 1.0.1/27000\n" + itoa(95*86400) + "\n")
	out, err := AntivirusLinuxNormalizer(fixedClock())(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev AntivirusEvidence
	json.Unmarshal(out, &ev)
	if !ev.Present || !ev.Enabled || ev.DefinitionsAgeDays != 5 {
		t.Fatalf("mapping ClamAV inattendu: %+v", ev)
	}
}

func TestFirewallWindowsNormalizer_Array(t *testing.T) {
	raw := []byte(`[{"Name":"Domain","Enabled":true,"DefaultInboundAction":"Block"},{"Name":"Public","Enabled":false,"DefaultInboundAction":"Allow"}]`)
	out, err := FirewallWindowsNormalizer(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev FirewallEvidence
	json.Unmarshal(out, &ev)
	if ev.ProfilesTotal != 2 || ev.ProfilesEnabled != 1 || ev.DefaultInboundDeny {
		t.Fatalf("agrégat profils inattendu: %+v", ev)
	}
}

func TestFirewallWindowsNormalizer_EnumAsInt(t *testing.T) {
	// Enabled=1 et DefaultInboundAction=4 (NetSecurity.Block) doivent être compris.
	raw := []byte(`{"Name":"Domain","Enabled":1,"DefaultInboundAction":4}`)
	out, err := FirewallWindowsNormalizer(raw)
	if err != nil {
		t.Fatal(err)
	}
	var ev FirewallEvidence
	json.Unmarshal(out, &ev)
	if ev.ProfilesEnabled != 1 || !ev.DefaultInboundDeny {
		t.Fatalf("interprétation enum entier ratée: %+v", ev)
	}
}

func TestFirewallLinuxNormalizer(t *testing.T) {
	// Multi-distro : ufw actif, firewalld actif, nftables policy drop.
	cases := []struct {
		name    string
		raw     string
		product string
		denyIn  bool
	}{
		{"ufw", "Status: active\nDefault: deny (incoming), allow (outgoing)\n", "ufw", true},
		{"firewalld", "running\npublic (active)\n  target: default\n  services: ssh dhcpv6-client\n", "firewalld", true},
		{"nftables", "table inet filter {\n chain input { type filter hook input priority 0; policy drop; }\n}", "nftables", true},
		{"ufw inactif", "Status: inactive\n", "ufw", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := FirewallLinuxNormalizer([]byte(c.raw))
			if err != nil {
				t.Fatal(err)
			}
			var ev FirewallEvidence
			json.Unmarshal(out, &ev)
			if ev.Product != c.product || ev.DefaultInboundDeny != c.denyIn {
				t.Fatalf("détection %s inattendue: %+v", c.name, ev)
			}
		})
	}
}

func TestPatchLinuxNormalizer_MultiDistro(t *testing.T) {
	// Format enrichi : gestionnaire, nb correctifs, epoch, auto.
	cases := []struct {
		raw     string
		manager string
		pending int
		auto    bool
	}{
		{"apt\n4\n" + itoa(90*86400) + "\nyes\n", "apt", 4, true},
		{"dnf\n2\n" + itoa(95*86400) + "\nno\n", "dnf", 2, false},
		{"zypper\n0\n" + itoa(99*86400) + "\nno\n", "zypper", 0, false},
	}
	for _, c := range cases {
		t.Run(c.manager, func(t *testing.T) {
			out, err := PatchLinuxNormalizer(fixedClock())([]byte(c.raw))
			if err != nil {
				t.Fatal(err)
			}
			var ev PatchEvidence
			json.Unmarshal(out, &ev)
			if ev.Manager != c.manager || ev.PendingSecurityUpdates != c.pending || ev.AutoUpdateEnabled != c.auto {
				t.Fatalf("parsing %s inattendu: %+v", c.manager, ev)
			}
		})
	}
}

func TestPatchWindowsNormalizer(t *testing.T) {
	out, err := PatchWindowsNormalizer([]byte(`{"pending":8,"auto":false}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev PatchEvidence
	json.Unmarshal(out, &ev)
	if ev.PendingSecurityUpdates != 8 || ev.AutoUpdateEnabled {
		t.Fatalf("mapping Windows Update inattendu: %+v", ev)
	}
}

// itoa local pour éviter d'importer strconv dans le test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
