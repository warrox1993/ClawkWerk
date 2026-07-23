package controls

import (
	"strconv"
	"strings"
	"time"
)

// Helpers partagés par les normaliseurs (brut → preuve canonique). Tous purs.

// lines découpe une sortie brute en lignes non vides, espaces rognés.
func lines(raw []byte) []string {
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// atoiSafe parse un entier ; renvoie 0 et false si non entier.
func atoiSafe(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return n, true
}

// ageDaysSinceEpoch convertit un timestamp epoch (secondes) en âge en jours par
// rapport à now. Si epochStr n'est pas un entier valide, renvoie missing (grand
// nombre) pour que l'évaluateur traite l'absence de preuve de fraîcheur comme
// périmé, jamais comme frais.
func ageDaysSinceEpoch(epochStr string, now time.Time, missing int) int {
	epoch, ok := atoiSafe(epochStr)
	if !ok || epoch <= 0 {
		return missing
	}
	d := int(now.Sub(time.Unix(int64(epoch), 0)).Hours() / 24)
	if d < 0 {
		d = 0
	}
	return d
}

// derefInt déréférence un *int (0 si nil).
func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// derefBool déréférence un *bool (false si nil).
func derefBool(p *bool) bool {
	return p != nil && *p
}

// accentFolder retire les accents courants FR/NL/DE (é→e, ä→a, ß→ss…). Défini une
// fois (allocation unique) pour éviter de le reconstruire à chaque appel.
var accentFolder = strings.NewReplacer(
	"é", "e", "è", "e", "ê", "e", "ë", "e",
	"à", "a", "â", "a", "ä", "a", "á", "a",
	"î", "i", "ï", "i", "í", "i",
	"ô", "o", "ö", "o", "ó", "o",
	"û", "u", "ù", "u", "ü", "u", "ú", "u",
	"ç", "c", "ñ", "n", "ß", "ss",
)

// foldLower met en minuscule et retire les accents : comparaison de libellés
// robuste aux langues nationales (FR/NL/DE) et aux aléas d'encodage.
func foldLower(s string) string {
	return accentFolder.Replace(strings.ToLower(s))
}
