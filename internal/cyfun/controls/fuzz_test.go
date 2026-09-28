package controls

import (
	"testing"
	"time"

	"github.com/warrox1993/clawkwerk/internal/assess"
)

// allNormalizers rassemble TOUS les normaliseurs (endpoints + réseau, tous
// constructeurs et tous contrôles) pour le fuzzing. Ils parsent des sorties
// d'équipements imprévisibles : l'invariant est qu'ils ne PANIQUENT jamais —
// au pire ils renvoient une erreur propre. Un parseur qui panique ferait
// planter l'audit en clientèle.
func allNormalizers() []assess.NormalizeFunc {
	clk := func() time.Time { return time.Unix(1_700_000_000, 0) }
	fns := []assess.NormalizeFunc{
		// Endpoints.
		AntivirusWindowsNormalizer, AntivirusLinuxNormalizer(clk),
		FirewallWindowsNormalizer, FirewallLinuxNormalizer,
		PatchWindowsNormalizer, PatchLinuxNormalizer(clk),
		LoggingWindowsNormalizer, LoggingLinuxNormalizer,
		LocalAdminWindowsNormalizer, LocalAdminLinuxNormalizer,
		// Réseau : tous les adaptateurs enregistrés (pare-feu, segmentation, log).
	}
	for _, m := range []map[string]assess.NormalizeFunc{
		NetFirewallNormalizers(), NetSegmentationNormalizers(), NetLoggingNormalizers(),
	} {
		for _, fn := range m {
			fns = append(fns, fn)
		}
	}
	return fns
}

// FuzzNormalizers alimente chaque normaliseur avec des octets arbitraires et
// exige l'absence de panique (une erreur est un résultat acceptable).
func FuzzNormalizers(f *testing.F) {
	// Graines représentatives : vide, non-JSON, JSON tronqué, sorties plausibles.
	seeds := []string{
		"", "{", "]", "not json at all",
		`{"AntivirusEnabled":true}`,
		"active\nClamAV 1.0\n1699999999",
		"Status: active\nDefault: deny (incoming)",
		"apt\n3\n1699999999\nyes",
		" 0 chain=input action=drop",
		`{"data":[{"ruleset":"WAN_IN","action":"drop","enabled":true}]}`,
		"<Response><FirewallRule><Name>r</Name></FirewallRule></Response>",
		"\x00\xff\xfe garbage \n\n bytes",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	fns := allNormalizers()
	f.Fuzz(func(t *testing.T, data []byte) {
		for i, fn := range fns {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("normaliseur #%d a paniqué sur %q : %v", i, data, r)
					}
				}()
				_, _ = fn(data) // erreur OK ; panique interdite
			}()
		}
	})
}
