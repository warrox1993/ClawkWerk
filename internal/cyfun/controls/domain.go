package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Famille ANNUAIRE CENTRALISÉ / GESTION AUTOMATISÉE DES COMPTES.
// Sonde SCANNABLE unique (DomainEvidence : l'hôte est-il rattaché à un annuaire
// centralisé — domaine AD côté Windows, realm/SSSD/Winbind côté Linux). Le
// rattachement est un PROXY technique de la gestion automatisée des identités et
// des comptes : sa présence indique qu'un mécanisme centralisé existe, mais la
// GESTION et la REVUE formelles (provisioning/déprovisioning documenté, cycles de
// vie) restent organisationnelles. Ces contrôles sont donc MIXTES → plafond
// Defined (3) : le scan constate l'annuaire, le formalisme s'atteste au
// questionnaire (override tracé pour aller au-delà). Aucun n'est Key Measure.

// DomainEvidence = fait brut (lecture seule) : l'hôte est rattaché ou non à un
// annuaire centralisé. C'est le contenu attendu de RawEvidence.Data.
type DomainEvidence struct {
	DomainJoined bool `json:"domain_joined"`
}

// DomainWinCmd : collecte Windows LECTURE SEULE. Interroge WMI pour savoir si la
// machine fait partie d'un domaine et émet du JSON {domain_joined:bool}.
const DomainWinCmd = WinPre + `$t=$null; try{$j=(Get-CimInstance Win32_ComputerSystem -EA Stop).PartOfDomain}catch{$t=(dsregcmd /status 2>$null) -join ' '; if($t -match 'DomainJoined\s*:\s*(YES|NO)'){$j=($Matches[1] -eq 'YES')}else{F 'appartenance au domaine (WMI)' $_}}; if(-not $j){if($t -eq $null){$t=(dsregcmd /status 2>$null) -join ' '}; if($t -match 'AzureAdJoined\s*:\s*YES'){$j=$true}}; [pscustomobject]@{domain_joined=$j}|ConvertTo-Json`

// DomainLinuxCmd : collecte Linux LECTURE SEULE. Un annuaire est considéré présent
// si realm liste au moins un domaine, OU si un démon d'intégration (sssd/winbind)
// est actif ; émet "yes" ou "no" (une seule ligne).
const DomainLinuxCmd = `(realm list 2>/dev/null | grep -q . || systemctl is-active sssd winbind 2>/dev/null | grep -q '^active') && echo yes || echo no`

// decodeDomain factorise le décodage commun aux évaluateurs de la famille : gère
// la collecte échouée et la preuve illisible via errorAssessment (renvoyé si non nil).
func decodeDomain(raw assess.RawEvidence) (DomainEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return DomainEvidence{}, &ha
	}
	var ev DomainEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return DomainEvidence{}, &ha
	}
	return ev, nil
}

// evalDirectory note la présence d'un annuaire centralisé, plafonnée à cap.
// Fonction PURE. Le statut reste Partial dans les deux cas : le scan ne peut
// jamais prouver seul la gestion/revue formelle des identités et des comptes.
func evalDirectory(host assess.HostRef, ev DomainEvidence, cap cyfun.MaturityLevel, label string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"domain_joined": ev.DomainJoined,
	}}
	var lvl cyfun.MaturityLevel
	if ev.DomainJoined {
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = label + " : annuaire centralisé détecté — gestion/revue formelle à attester."
	} else {
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = label + " : pas d'annuaire centralisé détecté — gestion/revue formelle à attester."
	}
	if lvl > cap { // plafond de niveau : un contrôle MIXTE ne dépasse pas Defined par scan seul.
		lvl = cap
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- Normalisation brut → DomainEvidence ---

// DomainWindowsNormalizer parse le JSON émis côté Windows : {"domain_joined":bool}.
// Le champ est requis (déréférencé via derefBool) : son absence est une erreur.
func DomainWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		DomainJoined *bool `json:"domain_joined"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie annuaire illisible : %w", err)
	}
	if w.DomainJoined == nil {
		return nil, errors.New("champ domain_joined absent")
	}
	return json.Marshal(DomainEvidence{DomainJoined: derefBool(w.DomainJoined)})
}

// DomainLinuxNormalizer parse une seule ligne "yes"/"no" (annuaire présent ou non).
func DomainLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie annuaire vide")
	}
	return json.Marshal(DomainEvidence{DomainJoined: ls[0] == "yes"})
}

// --- PR.AA-01.2 (Important, MIXTE) — identités gérées par mécanismes centralisés/automatisés ---
// Le scan constate le rattachement à un annuaire centralisé ; la GESTION
// automatisée documentée des identités reste organisationnelle → plafond Defined.

// PRAA0102Meta : texte officiel du CCB (Important, non Key Measure).
var PRAA0102Meta = cyfun.ControlMeta{
	ID: "PR.AA-01.2", Function: cyfun.Protect, Category: "PR.AA", Subcategory: "PR.AA-01",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "Identities and credentials for authorised users, services and hardware shall be managed through automated mechanisms whenever feasible.",
}

// PRAA0102Questions : volet Documentation (le scan couvre l'Implementation).
var PRAA0102Questions = []survey.Question{
	survey.Ask("PR.AA-01.2", survey.Documentation, "policy",
		"La gestion des identités et des accréditations via des mécanismes centralisés/automatisés est-elle documentée, approuvée et revue ?"),
}

// Directory0102Evaluator (PR.AA-01.2) — MIXTE, plafond Defined.
type Directory0102Evaluator struct{}

func (Directory0102Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeDomain(raw)
	if errHA != nil {
		return *errHA
	}
	return evalDirectory(raw.Host, ev, cyfun.Defined, "Identités centralisées")
}

// --- PR.AA-05.5 (Important, MIXTE) — gestion automatisée des comptes ---
// Même sonde : la présence d'un annuaire centralisé indique un mécanisme de
// gestion automatisée des comptes ; le processus documenté reste au questionnaire.

// PRAA0505Meta : texte officiel du CCB (Important, non Key Measure).
var PRAA0505Meta = cyfun.ControlMeta{
	ID: "PR.AA-05.5", Function: cyfun.Protect, Category: "PR.AA", Subcategory: "PR.AA-05",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "Where technically, operationally, and economically feasible—without compromising system integrity, safety, or compliance—automated mechanisms shall be implemented to manage user accounts on critical ICT and OT systems. Feasibility shall be determined based on system capabilities, integration potential, risk assessment, and business impact.",
}

// PRAA0505Questions : volet Documentation (le scan couvre l'Implementation).
var PRAA0505Questions = []survey.Question{
	survey.Ask("PR.AA-05.5", survey.Documentation, "policy",
		"La gestion automatisée des comptes utilisateurs (provisioning/déprovisioning) est-elle documentée, approuvée et revue ?"),
}

// Directory0505Evaluator (PR.AA-05.5) — MIXTE, plafond Defined.
type Directory0505Evaluator struct{}

func (Directory0505Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeDomain(raw)
	if errHA != nil {
		return *errHA
	}
	return evalDirectory(raw.Host, ev, cyfun.Defined, "Comptes centralisés")
}
