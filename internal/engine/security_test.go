package engine

import (
	"regexp"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// TestRegistry_AllCommandsReadOnly prouve que TOUTES les commandes du registre
// (tous niveaux — on itère Essential, le sur-ensemble le plus large) sont en
// lecture seule. La garantie « aucune écriture » ne repose alors plus sur la
// vigilance humaine mais sur un test automatique : un futur contributeur qui
// glisserait une commande mutante casse le build.
func TestRegistry_AllCommandsReadOnly(t *testing.T) {
	// tokens clairement destructeurs qui ne doivent JAMAIS apparaître (défense
	// en profondeur, en plus du contrat de type IsReadOnly).
	forbidden := []string{"reboot", "shutdown", "delete", "erase", "format ", "mkfs", "rm -", "reload", "factory-reset", "write mem"}
	// On matche chaque token comme un MOT de commande (précédé d'un début de
	// chaîne ou d'un caractère non alphanumérique), pas une sous-chaîne : sinon
	// "reboot" capturerait à tort "SecureBoot" (lecture seule). La garantie reste
	// stricte — un vrai reboot/shutdown/… en position de commande est toujours pris.
	res := make([]*regexp.Regexp, len(forbidden))
	for i, bad := range forbidden {
		res[i] = regexp.MustCompile(`(^|[^a-z0-9])` + regexp.QuoteMeta(bad))
	}

	for _, c := range ControlsForLevel(cyfun.LevelEssential) {
		for os, cmd := range c.Commands {
			if !cmd.IsReadOnly() {
				t.Errorf("%s/%s : commande NON lecture seule", c.Meta.ID, os)
			}
			low := strings.ToLower(cmd.Script)
			for i, re := range res {
				if re.MatchString(low) {
					t.Errorf("%s/%s : token destructeur %q dans %q", c.Meta.ID, os, forbidden[i], cmd.Script)
				}
			}
		}
	}
}
