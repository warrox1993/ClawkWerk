package engine

import "testing"

// privilegeGap ne fait que CONSTATER un accès refusé — jamais d'élévation (règle
// de sécurité absolue). Il doit repérer les marqueurs Windows/Linux, et ne PAS
// déclencher de faux positif sur une sortie normale.
func TestPrivilegeGap(t *testing.T) {
	denied := []string{
		"Access is denied.",
		"cat: /etc/shadow: Permission denied",
		"You must be root to run this",
		"Operation not permitted",
		"Accès refusé",
	}
	for _, d := range denied {
		if privilegeGap([]byte(d)) == "" {
			t.Errorf("accès refusé non détecté : %q", d)
		}
	}
	ok := []string{
		`{"antivirus_enabled":true}`,
		"apt\n3\n1700000000\nyes",
		"",
	}
	for _, o := range ok {
		if privilegeGap([]byte(o)) != "" {
			t.Errorf("faux positif de droits sur une sortie normale : %q", o)
		}
	}
}
