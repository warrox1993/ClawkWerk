// Package scan définit la collecte de preuve à distance, en LECTURE SEULE.
// Le contrat n'expose QUE l'exécution de commandes de collecte non mutantes :
// aucune primitive d'écriture, d'élévation de privilèges ou de mouvement
// latéral n'existe ici — absence par conception.
package scan

import (
	"context"

	"projetcyber/internal/assess"
	"projetcyber/internal/audit"
	"projetcyber/internal/scope"
)

// CollectCommand = commande de collecte read-only attachée à un contrôle et à
// un OS. Le drapeau readOnly est NON EXPORTÉ et ne peut être mis qu'à true via
// le constructeur : il n'existe aucun moyen de fabriquer une commande mutante.
type CollectCommand struct {
	ControlID string
	OS        string // "windows" | "linux"
	Script    string // commande de lecture (ex. PowerShell Get-MpComputerStatus)
	readOnly  bool
}

// ReadOnlyCommand est l'unique constructeur : toute commande créée est, par
// construction, en lecture seule.
func ReadOnlyCommand(controlID, os, script string) CollectCommand {
	return CollectCommand{ControlID: controlID, OS: os, Script: script, readOnly: true}
}

// IsReadOnly indique si la commande est bien une commande de collecte. Une
// CollectCommand à zéro-valeur (readOnly=false) est refusée par les Source.
func (c CollectCommand) IsReadOnly() bool { return c.readOnly }

// Source = accès distant en lecture seule à UN hôte du périmètre. Le Journal
// est un PARAMÈTRE REQUIS (pas un champ optionnel) : on ne peut pas construire
// un appel de collecte sans fournir un journal — c'est ainsi que « non
// désactivable » devient une contrainte de compilation.
type Source interface {
	Collect(ctx context.Context, host scope.ScopedHost, cmd CollectCommand, cred *scope.Credential, j audit.Journal) (assess.RawEvidence, error)
}
