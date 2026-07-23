package controls

import (
	"encoding/json"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// Famille ACCÈS DISTANT — modèle « sonde de famille » : une seule sonde,
// RemoteMFAEvidence (déjà écrite pour PR.AA-03.2 Basic dans praa0302.go),
// alimente plusieurs contrôles Important/Essential à des niveaux différents.
//
// Ces trois contrôles sont tous MIXTES : ce qui compte vraiment (MFA réelle,
// chiffrement du transport, authentification forte de la maintenance) vit au
// niveau de l'IdP / VPN / passerelle, PAS dans la configuration d'une machine
// du périmètre. Le scan ne constate honnêtement que le durcissement de
// l'exposition distante (NLA côté RDP, SSH clé-uniquement côté Linux). Ce
// durcissement est nécessaire mais jamais suffisant pour prouver MFA/chiffrement.
//
// PLAFOND cyfun.Defined(3) dans TOUS les cas : atteindre Managed/Optimizing
// suppose une preuve organisationnelle (config IdP/VPN, override tracé). Chaque
// message rappelle que la MFA/le chiffrement sont à attester au niveau IdP/VPN.

// decodeRemoteMFA factorise le décodage commun aux évaluateurs de la famille :
// gère la collecte échouée et la preuve illisible via errorAssessment (renvoyé
// non nil si l'on ne peut pas scorer). Réutilise le type de sonde RemoteMFAEvidence.
func decodeRemoteMFA(raw assess.RawEvidence) (RemoteMFAEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return RemoteMFAEvidence{}, &ha
	}
	var ev RemoteMFAEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return RemoteMFAEvidence{}, &ha
	}
	return ev, nil
}

// evalRemoteAccess note l'exposition distante à partir de la sonde, PLAFONNÉE à
// Defined. Fonction PURE. label préfixe les messages ; attest rappelle la preuve
// organisationnelle attendue (MFA/chiffrement/authentification forte). Le plafond
// Defined tient dans les trois branches — aucune n'atteint Managed par scan seul.
func evalRemoteAccess(host assess.HostRef, ev RemoteMFAEvidence, label, attest string) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"remote_access_enabled": ev.RemoteAccessEnabled,
			"hardened":              ev.Hardened,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case !ev.RemoteAccessEnabled:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = label + " : aucun accès distant exposé côté hôte ; " + attest + " à attester au niveau IdP/VPN (preuve organisationnelle)."
	case ev.Hardened:
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = label + " : accès distant durci (NLA/clé) ; " + attest + " non prouvable côté hôte — à attester au niveau IdP/VPN (preuve organisationnelle)."
	default:
		lvl, f.Status = cyfun.Repeatable, assess.StatusFail
		f.Message = label + " : accès distant exposé sans durcissement ; " + attest + " non prouvable côté hôte — à attester au niveau IdP/VPN (preuve organisationnelle)."
	}
	if lvl > cyfun.Defined { // plafond de niveau : contrôle MIXTE, jamais au-delà de Defined par scan.
		lvl = cyfun.Defined
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- PR.AA-03.3 (Important, KEY MEASURE, MIXTE) — MFA pour l'accès distant ---

// PRAA0303Meta : texte officiel du CCB (Important). Key Measure.
var PRAA0303Meta = cyfun.ControlMeta{
	ID:          "PR.AA-03.3",
	Function:    cyfun.Protect,
	Category:    "PR.AA",
	Subcategory: "PR.AA-03",
	Level:       cyfun.LevelImportant,
	KeyMeasure:  true,
	Requirement: "The organisation shall define, document, and implement usage restrictions, connection requirements, and authorisation procedures for remote access to its critical systems. These controls shall ensure that only approved users can connect, using secure methods, with access limited to what is necessary for their role.",
}

// PRAA0303Questions : volet Documentation. La MFA n'étant pas prouvable côté
// hôte, c'est le questionnaire (preuve organisationnelle) qui porte l'essentiel.
var PRAA0303Questions = []survey.Question{
	survey.Ask("PR.AA-03.3", survey.Documentation, "policy",
		"Le MFA est-il exigé par une règle documentée pour tout accès distant aux systèmes critiques (VPN, RDP, cloud, tiers) ?"),
}

// RemoteMFA0303Evaluator (PR.AA-03.3) — MIXTE, plafond Defined.
type RemoteMFA0303Evaluator struct{}

func (RemoteMFA0303Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeRemoteMFA(raw)
	if errHA != nil {
		return *errHA
	}
	return evalRemoteAccess(raw.Host, ev, "MFA accès distant", "la MFA")
}

// --- PR.AA-03.4 (Essential, non-KM, MIXTE) — chiffrement des accès distants ---

// PRAA0304Meta : texte officiel du CCB (Essential).
var PRAA0304Meta = cyfun.ControlMeta{
	ID:          "PR.AA-03.4",
	Function:    cyfun.Protect,
	Category:    "PR.AA",
	Subcategory: "PR.AA-03",
	Level:       cyfun.LevelEssential,
	KeyMeasure:  false,
	Requirement: "Remote access to the organisation’s critical systems shall be monitored and cryptographic mechanisms shall be implemented where determined necessary.",
}

// PRAA0304Questions : volet Documentation. Le chiffrement du transport distant
// vit au niveau VPN/passerelle — preuve organisationnelle, non prouvable côté hôte.
var PRAA0304Questions = []survey.Question{
	survey.Ask("PR.AA-03.4", survey.Documentation, "policy",
		"Les accès distants aux systèmes critiques sont-ils surveillés et protégés par des mécanismes cryptographiques documentés ?"),
}

// RemoteCrypto0304Evaluator (PR.AA-03.4) — MIXTE, plafond Defined.
type RemoteCrypto0304Evaluator struct{}

func (RemoteCrypto0304Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeRemoteMFA(raw)
	if errHA != nil {
		return *errHA
	}
	return evalRemoteAccess(raw.Host, ev, "Chiffrement accès distant", "le chiffrement")
}

// --- ID.AM-08.12 (Important, non-KM, MIXTE) — authentification forte de la maintenance distante ---

// IDAM0812Meta : texte officiel du CCB (Important).
var IDAM0812Meta = cyfun.ControlMeta{
	ID:          "ID.AM-08.12",
	Function:    cyfun.Identify,
	Category:    "ID.AM",
	Subcategory: "ID.AM-08",
	Level:       cyfun.LevelImportant,
	KeyMeasure:  false,
	Requirement: "Setting up non-local maintenance and diagnostic sessions over remote network connections shall require strong authenticators and these connections shall be terminated when non-local maintenance is completed.",
}

// IDAM0812Questions : volet Documentation. L'authentification forte de la
// maintenance distante s'atteste au niveau IdP/VPN (preuve organisationnelle).
var IDAM0812Questions = []survey.Question{
	survey.Ask("ID.AM-08.12", survey.Documentation, "policy",
		"Les sessions de maintenance/diagnostic distantes exigent-elles une authentification forte et sont-elles terminées à la fin de l'intervention ?"),
}

// RemoteMaint0812Evaluator (ID.AM-08.12) — MIXTE, plafond Defined.
type RemoteMaint0812Evaluator struct{}

func (RemoteMaint0812Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeRemoteMFA(raw)
	if errHA != nil {
		return *errHA
	}
	return evalRemoteAccess(raw.Host, ev, "Maintenance distante", "l'authentification forte")
}
