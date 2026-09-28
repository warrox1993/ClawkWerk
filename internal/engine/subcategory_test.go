package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// La maturité est agrégée par SOUS-CATÉGORIE : une exigence rattachée à une
// sous-catégorie mal écrite forme un groupe à part et fausse la moyenne de sa
// catégorie. Constaté le 28/09/2026 face à l'outil officiel ESSENTIAL :
// ID.AM-03-2 était isolée de ID.AM-03.3. Les identifiants d'exigence gardent
// l'écriture du CCB (ID.AM-5.1, ID.AM-03-2, DE.CM-03-1), mais la sous-catégorie
// doit être la forme canonique (ID.AM-05, ID.AM-03, DE.CM-03).
func TestSousCategorie_CoherenteAvecLIdentifiant(t *testing.T) {
	re := regexp.MustCompile(`^([A-Z]{2}\.[A-Z]{2})-0?(\d+)[.-]\d+$`)
	for _, c := range ControlsForLevel(cyfun.LevelEssential) {
		m := re.FindStringSubmatch(c.Meta.ID)
		if m == nil {
			t.Errorf("%s : identifiant non reconnu", c.Meta.ID)
			continue
		}
		n, _ := strconv.Atoi(m[2])
		want := fmt.Sprintf("%s-%02d", m[1], n)
		if c.Meta.Subcategory != want || c.Meta.Category != m[1] {
			t.Errorf("%s : sous-catégorie %q / catégorie %q, attendu %q / %q", c.Meta.ID, c.Meta.Subcategory, c.Meta.Category, want, m[1])
		}
	}
}
