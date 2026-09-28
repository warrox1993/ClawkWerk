package engine

import (
	"sort"

	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// KnownPlatforms renvoie, triées, toutes les plateformes (valeurs « os » d'un
// périmètre) pour lesquelles au moins un contrôle possède une commande de
// collecte, tous niveaux confondus : windows, linux, m365 et les plateformes
// d'équipements réseau (routeros, fortios…). Sert à refuser une faute de frappe
// dans le périmètre avant l'audit, plutôt que d'obtenir des « N/A » en silence.
func KnownPlatforms() []string {
	seen := map[string]bool{}
	for _, c := range ControlsForLevel(cyfun.LevelEssential) {
		for os := range c.Commands {
			seen[os] = true
		}
	}
	out := make([]string, 0, len(seen))
	for os := range seen {
		out = append(out, os)
	}
	sort.Strings(out)
	return out
}

// IsKnownPlatform indique si os figure parmi KnownPlatforms.
func IsKnownPlatform(os string) bool {
	for _, p := range KnownPlatforms() {
		if p == os {
			return true
		}
	}
	return false
}
