// Package assess définit le contrat d'évaluation d'un contrôle : ce qui entre
// (RawEvidence, produit par la collecte) et ce qui sort (HostAssessment).
// Il dépend seulement de cyfun. La couche scan (WinRM/SSH) importera assess
// pour produire des RawEvidence — jamais l'inverse.
package assess

import (
	"encoding/json"
	"time"

	"projetcyber/internal/cyfun"
)

// HostRef identifie une machine du périmètre. On n'y met que le strict
// nécessaire (RGPD) : pas de données personnelles superflues.
type HostRef struct {
	ID   string `json:"id"`             // "PC-COMPTA-01" ou un pseudonyme
	OS   string `json:"os"`             // "windows" | "linux"
	Role string `json:"role,omitempty"` // "workstation" | "server" (optionnel)
}

// RawEvidence = sortie BRUTE de la collecte read-only pour UN contrôle sur UN
// hôte. Data reste du JSON non typé (json.RawMessage) : la couche collecte/
// transport reste générique, et c'est l'évaluateur du contrôle qui connaît la
// forme concrète des faits. CollectErr est non vide si la collecte a échoué.
type RawEvidence struct {
	ControlID   string          `json:"control_id"`
	Host        HostRef         `json:"host"`
	Source      string          `json:"source"` // "winrm" | "ssh" | ...
	CollectedAt time.Time       `json:"collected_at"`
	Data        json.RawMessage `json:"data"`
	CollectErr  string          `json:"collect_err,omitempty"`
}

// Status résume l'état d'un constat pour un hôte.
type Status string

const (
	StatusPass    Status = "pass"
	StatusPartial Status = "partial"
	StatusFail    Status = "fail"
	StatusNA      Status = "n/a"
	StatusError   Status = "error" // collecte impossible / preuve illisible
)

// Finding = un constat lisible + les faits saillants (repris comme preuve au
// rapport).
type Finding struct {
	HostID  string         `json:"host_id"`
	Status  Status         `json:"status"`
	Message string         `json:"message"`
	Detail  map[string]any `json:"detail,omitempty"`
}

// HostAssessment = résultat de l'évaluation d'un contrôle pour UN hôte :
// constats + niveau d'Implementation proposé (dérivé du scan) + justification
// (traçabilité d'audit).
type HostAssessment struct {
	Host              HostRef             `json:"host"`
	Findings          []Finding           `json:"findings"`
	ProposedImplLevel cyfun.MaturityLevel `json:"proposed_impl_level"`
	Rationale         string              `json:"rationale"`
}

// Evaluator transforme la preuve brute d'UN hôte en constat + niveau proposé.
// Contrat : fonction PURE — aucune I/O, déterministe, testable unitairement
// avec des faits en dur. C'est le patron réutilisable des 34 contrôles :
// pour un nouveau contrôle scannable, on écrit seulement un Evaluator.
type Evaluator interface {
	Evaluate(raw RawEvidence) HostAssessment
}
