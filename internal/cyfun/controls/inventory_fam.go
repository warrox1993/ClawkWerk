package controls

import (
	"encoding/json"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// Famille INVENTAIRE-LOGICIEL — incrément « sonde de famille » : plusieurs
// contrôles Important/Essential RÉUTILISENT la sonde d'énumération logicielle
// (SoftwareInventoryEvidence : nombre de logiciels installés énumérés) déjà
// écrite pour ID.AM-02.1 (Basic). Une seule collecte alimente plusieurs
// contrôles.
//
// Ces contrôles sont MIXTES : énumérer LOCALEMENT les logiciels installés
// CORROBORE l'existence d'un inventaire, mais ne prouve NI qu'un inventaire est
// tenu/approuvé/à jour, NI qu'une liste autorisée existe, NI que les logiciels
// non autorisés sont mis en quarantaine (allowlisting/quarantaine = processus
// organisationnel). Le scan PLAFONNE donc à Defined(3) et reste au statut
// Partial : la preuve documentaire (inventaire tenu + gestion des logiciels non
// autorisés) doit compléter l'attestation via le questionnaire.

// decodeSoftwareInventory factorise le décodage commun aux évaluateurs de la
// famille : gère la collecte échouée et la preuve illisible via errorAssessment
// (défini dans decm0102.go, réutilisé — jamais redéfini). Renvoie un pointeur
// non nil sur le HostAssessment d'erreur en cas d'échec.
func decodeSoftwareInventory(raw assess.RawEvidence) (SoftwareInventoryEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return SoftwareInventoryEvidence{}, &ha
	}
	var ev SoftwareInventoryEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return SoftwareInventoryEvidence{}, &ha
	}
	return ev, nil
}

// evalInventoryFam note l'énumérabilité logicielle, plafonnée à cap. Fonction
// PURE. Deux issues : énumération impossible (Initial/Fail) ou énumérable
// (Defined/Partial, plafonnée). Le statut reste Partial car le scan seul ne
// prouve pas l'inventaire tenu ni la liste autorisée (axe Documentation).
func evalInventoryFam(host assess.HostRef, ev SoftwareInventoryEvidence, cap cyfun.MaturityLevel, label string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"installed_count": ev.InstalledCount,
	}}
	var lvl cyfun.MaturityLevel
	if ev.InstalledCount <= 0 {
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("%s : énumération des logiciels impossible (aucune entrée) — base d'inventaire non fondable sur cet hôte.", label)
	} else {
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = fmt.Sprintf("%s : inventaire énumérable (%d) — à recouper avec l'inventaire documenté et la liste autorisée.", label, ev.InstalledCount)
	}
	if lvl > cap { // plafond : un contrôle MIXTE ne dépasse pas Defined par scan seul.
		lvl = cap
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- ID.AM-02.2 (Important) — inventaire logiciel tenu à jour (MIXTE) ---

// SwInv0202Meta : texte officiel du CCB (Important). Non Key Measure.
var SwInv0202Meta = cyfun.ControlMeta{
	ID: "ID.AM-02.2", Function: cyfun.Identify, Category: "ID.AM", Subcategory: "ID.AM-02",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "The inventory reflecting which software, services and systems are used in the organisation shall reflect changes in the  organisation’s context and include all information necessary for effective accountability.",
}

// SwInv0202Questions : volet Documentation (le scan corrobore l'énumérabilité).
var SwInv0202Questions = []survey.Question{
	survey.Ask("ID.AM-02.2", survey.Documentation, "policy",
		"L'inventaire des logiciels, services et systèmes est-il tenu à jour, reflète-t-il les changements de contexte et contient-il l'information nécessaire à la traçabilité ?"),
}

// SwInv0202Evaluator (ID.AM-02.2) — MIXTE, plafond Defined.
type SwInv0202Evaluator struct{}

func (SwInv0202Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeSoftwareInventory(raw)
	if errHA != nil {
		return *errHA
	}
	return evalInventoryFam(raw.Host, ev, cyfun.Defined, "Inventaire logiciel tenu à jour")
}

// --- ID.AM-02.4 (Important) — comparaison à une liste autorisée (MIXTE) ---

// SwInv0204Meta : texte officiel du CCB (Important). Non Key Measure.
var SwInv0204Meta = cyfun.ControlMeta{
	ID: "ID.AM-02.4", Function: cyfun.Identify, Category: "ID.AM", Subcategory: "ID.AM-02",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "When unauthorised software is detected, it shall be quarantined for possible exception handling, removed, or replaced, and the inventory shall be updated accordingly.",
}

// SwInv0204Questions : volet Documentation. Le scan énumère l'installé ; la
// détection/quarantaine des logiciels NON AUTORISÉS reste un processus.
var SwInv0204Questions = []survey.Question{
	survey.Ask("ID.AM-02.4", survey.Documentation, "policy",
		"Les logiciels installés sont-ils comparés à une liste autorisée, et les logiciels non autorisés détectés sont-ils mis en quarantaine, retirés ou remplacés, l'inventaire étant mis à jour ?"),
}

// SwInv0204Evaluator (ID.AM-02.4) — MIXTE, plafond Defined.
type SwInv0204Evaluator struct{}

func (SwInv0204Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeSoftwareInventory(raw)
	if errHA != nil {
		return *errHA
	}
	return evalInventoryFam(raw.Host, ev, cyfun.Defined, "Comparaison à la liste autorisée")
}

// --- ID.AM-02.5 (Essential) — inventaire + allowlisting (MIXTE) ---

// SwInv0205Meta : texte officiel du CCB (Essential). Non Key Measure.
var SwInv0205Meta = cyfun.ControlMeta{
	ID: "ID.AM-02.5", Function: cyfun.Identify, Category: "ID.AM", Subcategory: "ID.AM-02",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "Mechanisms for detecting the presence of unauthorised software within the organisation’s ICT/OT environment shall be identified.",
}

// SwInv0205Questions : volet Documentation. Le scan prouve l'énumérabilité ;
// l'identification des MÉCANISMES de détection du logiciel non autorisé reste
// organisationnelle.
var SwInv0205Questions = []survey.Question{
	survey.Ask("ID.AM-02.5", survey.Documentation, "policy",
		"Des mécanismes de détection des logiciels non autorisés (inventaire logiciel + allowlisting) sont-ils identifiés et documentés dans l'environnement ICT/OT ?"),
}

// SwInv0205Evaluator (ID.AM-02.5) — MIXTE, plafond Defined.
type SwInv0205Evaluator struct{}

func (SwInv0205Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeSoftwareInventory(raw)
	if errHA != nil {
		return *errHA
	}
	return evalInventoryFam(raw.Host, ev, cyfun.Defined, "Inventaire logiciel + allowlisting")
}
