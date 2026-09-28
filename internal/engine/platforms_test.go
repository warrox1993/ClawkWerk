package engine

import "testing"

func TestKnownPlatforms(t *testing.T) {
	ps := KnownPlatforms()
	for _, want := range []string{"windows", "linux", "m365", "routeros", "fortios", "pfsense"} {
		if !IsKnownPlatform(want) {
			t.Errorf("plateforme %q absente de %v", want, ps)
		}
	}
	for _, bad := range []string{"", "Windows", "windoze", "macos"} {
		if IsKnownPlatform(bad) {
			t.Errorf("plateforme %q acceptée à tort", bad)
		}
	}
	for i := 1; i < len(ps); i++ {
		if ps[i-1] >= ps[i] {
			t.Fatalf("liste non triée ou avec doublon : %v", ps)
		}
	}
}
