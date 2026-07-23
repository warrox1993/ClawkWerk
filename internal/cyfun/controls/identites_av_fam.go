package controls

import (
	"encoding/json"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// Famille IDENTITÉS-AUTHENTIFICATION-VÉRIFICATION (PR.AA) — batch Essential.
// Ces trois contrôles Essential (non-KM) sont MIXTES : le scan constate un SIGNAL
// technique, mais la conformité pleine relève d'une part ORGANISATIONNELLE (revue
// formelle, attestation d'unicité, configuration IdP). Aucune sonde nouvelle : on
// RÉUTILISE deux sondes déjà écrites au niveau Basic —
//   - AccessReviewEvidence (praa0501.go : comptes inactifs + total énuméré) pour
//     PR.AA-01.3 (comptes dormants désactivés) et PR.AA-02.2 (comptes uniques) ;
//   - RemoteMFAEvidence (praa0302.go : exposition distante durcie) pour
//     PR.AA-01.4 (MFA/certificats d'authentification).
// Preuve PARTIELLE => PLAFOND cyfun.Defined (3) partout ; chaque message rappelle
// explicitement la part organisationnelle restant à attester.

// decodeAccessReview factorise le décodage commun aux deux évaluateurs qui
// réutilisent la sonde AccessReview : gère la collecte échouée et la preuve
// illisible via errorAssessment (renvoyé si non nil). Symétrique de decodeHardening
// / decodeRemoteMFA — on ne redéfinit pas ces derniers, on ajoute le pendant manquant.
func decodeAccessReview(raw assess.RawEvidence) (AccessReviewEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return AccessReviewEvidence{}, &ha
	}
	var ev AccessReviewEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return AccessReviewEvidence{}, &ha
	}
	return ev, nil
}

// --- PR.AA-01.3 (Essential, non-KM, MIXTE) — désactivation des comptes dormants ---
// Le scan lit le nombre de comptes activés jamais/plus connectés (InactiveAccounts).
// La désactivation effective après inactivité est un SIGNAL ; la politique formelle
// (délai défini, exceptions maîtrisées) reste organisationnelle => plafond Defined.

// PRAA0103Meta : texte officiel du CCB (Essential, non Key Measure).
var PRAA0103Meta = cyfun.ControlMeta{
	ID: "PR.AA-01.3", Function: cyfun.Protect, Category: "PR.AA", Subcategory: "PR.AA-01",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "System credentials shall be deactivated after a specified period of inactivity unless it would compromise the safe operation of (critical) processes.",
}

// PRAA0103Questions : volet Documentation (le scan couvre le signal technique).
var PRAA0103Questions = []survey.Question{
	survey.Ask("PR.AA-01.3", survey.Documentation, "policy",
		"La désactivation des identifiants après une période d'inactivité définie est-elle documentée, approuvée et revue ?"),
}

// Dormant0103Evaluator (PR.AA-01.3) — réutilise AccessReviewEvidence, plafond Defined.
type Dormant0103Evaluator struct{}

func (Dormant0103Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeAccessReview(raw)
	if errHA != nil {
		return *errHA
	}
	f := assess.Finding{HostID: raw.Host.ID, Detail: map[string]any{
		"inactive_accounts":    ev.InactiveAccounts,
		"total_local_accounts": ev.TotalLocalAccounts,
	}}
	var lvl cyfun.MaturityLevel
	switch {
	case ev.TotalLocalAccounts <= 0:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Énumération des comptes impossible ; désactivation des comptes dormants non vérifiable."
	case ev.InactiveAccounts > inactiveAccountsManyThreshold:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("%d comptes dormants encore actifs — désactivation après inactivité insuffisante ; politique de désactivation à attester (part organisationnelle).", ev.InactiveAccounts)
	case ev.InactiveAccounts > 0:
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = fmt.Sprintf("%d compte(s) dormant(s) restant(s) ; désactivation après inactivité à formaliser et attester (part organisationnelle).", ev.InactiveAccounts)
	default:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = "Aucun compte dormant actif ; délai d'inactivité documenté à attester (part organisationnelle)."
	}
	return assess.HostAssessment{Host: raw.Host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- PR.AA-02.2 (Essential, non-KM, MIXTE) — identifiants uniques par utilisateur ---
// L'UNICITÉ réelle (aucun compte générique/partagé) n'est PAS prouvable côté hôte :
// le scan ne peut qu'énumérer les comptes. Preuve la plus faible de la famille —
// une énumération réussie ouvre à Defined/Partial, à charge d'attester l'absence de
// comptes partagés ; sans énumération, on ne peut rien affirmer => Initial/Fail.

// PRAA0202Meta : texte officiel du CCB (Essential, non Key Measure).
var PRAA0202Meta = cyfun.ControlMeta{
	ID: "PR.AA-02.2", Function: cyfun.Protect, Category: "PR.AA", Subcategory: "PR.AA-02",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "The organisation shall ensure that unique credentials are used for each authenticated user, device, and process interacting with the organisation's critical systems. These credentials shall be verified, and the unique identifiers shall be captured during system interactions. Exceptions may be made for emergency access (\"break-glass\" procedures), provided such access is strictly controlled, logged, and reviewed.",
}

// PRAA0202Questions : volet Documentation (l'unicité s'atteste par procédure).
var PRAA0202Questions = []survey.Question{
	survey.Ask("PR.AA-02.2", survey.Documentation, "policy",
		"L'usage d'identifiants UNIQUES par utilisateur/appareil/processus (pas de comptes génériques/partagés) est-il documenté, vérifié et revu ?"),
}

// UniqueAccounts0202Evaluator (PR.AA-02.2) — réutilise AccessReviewEvidence, plafond Defined.
type UniqueAccounts0202Evaluator struct{}

func (UniqueAccounts0202Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeAccessReview(raw)
	if errHA != nil {
		return *errHA
	}
	f := assess.Finding{HostID: raw.Host.ID, Detail: map[string]any{
		"total_local_accounts": ev.TotalLocalAccounts,
	}}
	var lvl cyfun.MaturityLevel
	if ev.TotalLocalAccounts > 0 {
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = fmt.Sprintf("%d comptes énumérés ; absence de comptes génériques/partagés à attester (part organisationnelle).", ev.TotalLocalAccounts)
	} else {
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Énumération des comptes impossible ; unicité des identifiants non vérifiable."
	}
	return assess.HostAssessment{Host: raw.Host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- PR.AA-01.4 (Essential, non-KM, MIXTE) — MFA / certificats d'authentification ---
// La MFA/les certificats vivent au niveau IdP, pas sur l'hôte. Le scan ne constate
// que le durcissement de l'exposition distante (NLA/clé) via RemoteMFAEvidence :
// nécessaire mais pas suffisant. Plafond Defined ; message renvoyant vers l'IdP.

// PRAA0104Meta : texte officiel du CCB (Essential, non Key Measure).
var PRAA0104Meta = cyfun.ControlMeta{
	ID: "PR.AA-01.4", Function: cyfun.Protect, Category: "PR.AA", Subcategory: "PR.AA-01",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "For transactions within the organisation's critical systems, the organisation shall implement Multi Factor Authentication (MFA), cryptographic certificates, identity tokens, cryptographic keys and other credentials as appropriate and where feasible.",
}

// PRAA0104Questions : volet Documentation (la MFA/les certificats s'attestent à l'IdP).
var PRAA0104Questions = []survey.Question{
	survey.Ask("PR.AA-01.4", survey.Documentation, "policy",
		"La MFA, les certificats cryptographiques ou jetons d'identité sont-ils exigés pour les transactions des systèmes critiques (documenté et appliqué) ?"),
}

// AuthFactor0104Evaluator (PR.AA-01.4) — réutilise RemoteMFAEvidence, plafond Defined.
type AuthFactor0104Evaluator struct{}

func (AuthFactor0104Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeRemoteMFA(raw)
	if errHA != nil {
		return *errHA
	}
	f := assess.Finding{HostID: raw.Host.ID, Detail: map[string]any{
		"remote_access_enabled": ev.RemoteAccessEnabled,
		"hardened":              ev.Hardened,
	}}
	var lvl cyfun.MaturityLevel
	switch {
	case !ev.RemoteAccessEnabled:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = "Aucun accès distant exposé côté hôte ; MFA/certificats à attester au niveau IdP (part organisationnelle)."
	case ev.Hardened:
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = "Accès distant durci (NLA/clé) ; MFA/certificats à attester au niveau IdP (part organisationnelle)."
	default:
		lvl, f.Status = cyfun.Repeatable, assess.StatusFail
		f.Message = "Accès distant exposé sans durcissement ni preuve de facteur fort ; MFA/certificats à attester au niveau IdP (part organisationnelle)."
	}
	return assess.HostAssessment{Host: raw.Host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}
