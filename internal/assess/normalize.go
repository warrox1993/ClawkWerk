package assess

import "encoding/json"

// NormalizeFunc convertit la sortie BRUTE d'une commande de collecte (telle que
// renvoyée par un transport réel : SSH, WinRM…) en preuve CANONIQUE JSON, celle
// que l'Evaluator du contrôle sait décoder. C'est la « couche de normalisation
// brut → preuve » : elle isole les évaluateurs (fonctions pures sur des faits
// typés) des aléas de format des outils système (versions de PowerShell,
// variations de sortie shell, locales…).
//
// Contrat : fonction PURE et déterministe (aucune I/O). Si un état dépend de
// l'horloge (ex. « âge des définitions en jours »), l'horloge est injectée à la
// CONSTRUCTION du normaliseur, pas lue dedans — la fonction reste testable avec
// une date figée. Une par (contrôle, OS).
//
// En cas de sortie illisible, renvoyer une erreur : le moteur la transforme en
// trou de collecte (l'évaluateur produira un constat « preuve illisible »), le
// pipeline continue et le rapport montre la couverture réelle.
type NormalizeFunc func(raw []byte) (json.RawMessage, error)

// PassThrough est le normaliseur identité : il vérifie seulement que l'entrée
// est un JSON valide et la renvoie telle quelle. Utile quand la source fournit
// déjà la preuve canonique (ex. fixtures de test, FileSource de dev).
func PassThrough(raw []byte) (json.RawMessage, error) {
	if !json.Valid(raw) {
		return nil, ErrInvalidJSON
	}
	return json.RawMessage(raw), nil
}

// ErrInvalidJSON est renvoyée par PassThrough sur une entrée non-JSON.
var ErrInvalidJSON = jsonError("preuve : JSON invalide")

type jsonError string

func (e jsonError) Error() string { return string(e) }
