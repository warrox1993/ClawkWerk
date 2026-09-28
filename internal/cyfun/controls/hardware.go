package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Famille INVENTAIRE MATÉRIEL — sonde Hardware. Une seule collecte LECTURE SEULE
// énumère les composants matériels PRÉSENTS SUR L'HÔTE LUI-MÊME (énumération
// LOCALE : Win32_PnPEntity côté Windows, lspci/lsusb côté Linux). Elle NE FAIT
// AUCUNE découverte réseau — règle absolue du projet : le périmètre est la
// machine interrogée, jamais un balayage de plage IP.
//
// Les trois contrôles ci-dessous sont MIXTES : le scan prouve seulement qu'on
// peut ÉNUMÉRER techniquement le matériel local (la base factuelle), mais
// l'inventaire DOCUMENTÉ, sa tenue à jour et la DÉTECTION du matériel NON
// AUTORISÉ restent des attributs ORGANISATIONNELS (axe Documentation via
// questionnaire). Le scan PLAFONNE donc à Defined (3) : énumérer atteste d'un
// processus formel implémenté, jamais des métriques/revues (Managed/Optimizing)
// ni de la détection du non-autorisé, qui relèvent de la preuve organisationnelle.

// HardwareEvidence = fait brut (lecture seule) : nombre de composants matériels
// énumérés LOCALEMENT sur l'hôte.
type HardwareEvidence struct {
	ItemsEnumerated int `json:"items_enumerated"` // nb de composants matériels locaux énumérés
}

// HardwareWinCmd : collecte Windows LECTURE SEULE. Énumère les entités PnP
// (Win32_PnPEntity) présentes sur l'hôte via CIM — une simple requête WMI de
// LECTURE, aucun effet de bord. Émet du JSON {items_enumerated}.
const HardwareWinCmd = `$n=@(Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue).Count; [pscustomobject]@{items_enumerated=$n} | ConvertTo-Json`

// HardwareLinuxCmd : collecte Linux LECTURE SEULE. Énumère les composants PCI et
// USB LOCAUX ; chaque ligne = un composant, `grep -c .` en donne le nombre.
// Émet UNE ligne entière = le nombre de composants matériels locaux. Le
// `|| true` neutralise le code 1 de `grep -c` quand il ne compte rien ; si ni
// lspci ni lsusb n'est installé, la sonde échoue explicitement (outil absent,
// pas « zéro composant »).
const HardwareLinuxCmd = `export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"; ` +
	`{ command -v lspci >/dev/null 2>&1 || command -v lsusb >/dev/null 2>&1; } || { echo 'lspci et lsusb introuvables (paquets pciutils, usbutils)' >&2; exit 2; }; ` +
	`{ lspci 2>/dev/null; lsusb 2>/dev/null; } | grep -c . || true`

// evaluateHardware contient la règle de décision (pure), commune aux trois
// contrôles de la famille. Deux issues seulement : soit l'énumération échoue
// (aucun composant remonté => on ne peut même pas fonder d'inventaire matériel),
// soit elle réussit et PLAFONNE à Defined (3) — le recoupement avec l'inventaire
// documenté et la détection du non-autorisé restent organisationnels.
func evaluateHardware(host assess.HostRef, ev HardwareEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"items_enumerated": ev.ItemsEnumerated,
		},
	}
	var lvl cyfun.MaturityLevel
	if ev.ItemsEnumerated <= 0 {
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Énumération matérielle impossible (aucun composant local remonté) : inventaire non fondable sur cet hôte."
	} else {
		// MIXTE => plafond Defined : au mieux Partial, jamais un Pass complet, car
		// la couverture organisationnelle (documenté + détection du non-autorisé)
		// n'est pas prouvable par un scan hôte.
		lvl, f.Status = cyfun.Defined, assess.StatusPartial
		f.Message = fmt.Sprintf("%d composants énumérés localement — à recouper avec l'inventaire documenté et la détection du non-autorisé, organisationnelle.", ev.ItemsEnumerated)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// decodeHardware factorise le décodage commun aux évaluateurs de la famille :
// gère la collecte échouée et la preuve illisible via errorAssessment (renvoyé
// si non nil).
func decodeHardware(raw assess.RawEvidence) (HardwareEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return HardwareEvidence{}, &ha
	}
	var ev HardwareEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return HardwareEvidence{}, &ha
	}
	return ev, nil
}

// --- ID.AM-01.2 (Important) — inventaire des actifs matériels ---

// IDAM0102Meta : texte officiel du CCB (Important). Non Key Measure.
var IDAM0102Meta = cyfun.ControlMeta{
	ID: "ID.AM-01.2", Function: cyfun.Identify, Category: "ID.AM", Subcategory: "ID.AM-01",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "The inventory of enterprise assets associated with information and information processing facilities shall reflect changes in the organisation’s context and include all information necessary for effective accountability.",
}

// IDAM0102Questions : volet Documentation. Le scan ne prouve QUE l'énumérabilité
// locale du matériel ; le caractère « documenté/tenu à jour » se constate ici.
var IDAM0102Questions = []survey.Question{
	survey.Ask("ID.AM-01.2", survey.Documentation, "policy",
		"Un inventaire des actifs matériels (poste, propriétaire, localisation) est-il documenté, tenu à jour et reflétant les changements du contexte ?"),
}

// HwInv0102Evaluator implémente assess.Evaluator pour ID.AM-01.2.
type HwInv0102Evaluator struct{}

func (HwInv0102Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeHardware(raw)
	if errHA != nil {
		return *errHA
	}
	return evaluateHardware(raw.Host, ev)
}

// --- ID.AM-01.3 (Important) — inventaire des périphériques/matériels connectés ---

// IDAM0103Meta : texte officiel du CCB (Important). Non Key Measure.
var IDAM0103Meta = cyfun.ControlMeta{
	ID: "ID.AM-01.3", Function: cyfun.Identify, Category: "ID.AM", Subcategory: "ID.AM-01",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "When unauthorised hardware is detected, it shall be quarantined for possible exception handling, removed, or replaced, and the inventory shall be updated accordingly.",
}

// IDAM0103Questions : volet Documentation. Le scan énumère les périphériques
// LOCAUX ; le traitement du matériel non autorisé (quarantaine/retrait) est
// organisationnel et se constate ici.
var IDAM0103Questions = []survey.Question{
	survey.Ask("ID.AM-01.3", survey.Documentation, "policy",
		"Le traitement du matériel non autorisé détecté (quarantaine, retrait ou remplacement) et la mise à jour de l'inventaire sont-ils documentés et appliqués ?"),
}

// HwInv0103Evaluator implémente assess.Evaluator pour ID.AM-01.3.
type HwInv0103Evaluator struct{}

func (HwInv0103Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeHardware(raw)
	if errHA != nil {
		return *errHA
	}
	return evaluateHardware(raw.Host, ev)
}

// --- ID.AM-01.4 (Essential) — détection du matériel/firmware non autorisé ---

// IDAM0104Meta : texte officiel du CCB (Essential). Non Key Measure.
var IDAM0104Meta = cyfun.ControlMeta{
	ID: "ID.AM-01.4", Function: cyfun.Identify, Category: "ID.AM", Subcategory: "ID.AM-01",
	Level: cyfun.LevelEssential, KeyMeasure: false,
	Requirement: "Mechanisms for detecting the presence of unauthorised hardware and firmware components within the organisation’s ICT/OT environment shall be identified.",
}

// IDAM0104Questions : volet Documentation. L'énumération locale fournit une base
// factuelle ; l'existence de MÉCANISMES de détection du non-autorisé (matériel +
// firmware) est organisationnelle et se constate ici.
var IDAM0104Questions = []survey.Question{
	survey.Ask("ID.AM-01.4", survey.Documentation, "policy",
		"Des mécanismes de détection du matériel et firmware non autorisés dans l'environnement ICT/OT sont-ils identifiés et documentés ?"),
}

// HwDet0104Evaluator implémente assess.Evaluator pour ID.AM-01.4.
type HwDet0104Evaluator struct{}

func (HwDet0104Evaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeHardware(raw)
	if errHA != nil {
		return *errHA
	}
	return evaluateHardware(raw.Host, ev)
}

// --- Normalisation brut → HardwareEvidence ---

// HardwareWindowsNormalizer parse le JSON émis côté Windows :
// {"items_enumerated":int}. items_enumerated est requis (erreur si absent) pour
// ne jamais confondre « zéro composant » avec « champ non collecté ».
func HardwareWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		ItemsEnumerated *int `json:"items_enumerated"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie inventaire matériel illisible : %w", err)
	}
	if w.ItemsEnumerated == nil {
		return nil, errors.New("champ items_enumerated absent")
	}
	return json.Marshal(HardwareEvidence{
		ItemsEnumerated: derefInt(w.ItemsEnumerated),
	})
}

// HardwareLinuxNormalizer parse la sortie Linux : UNE ligne = le nombre de
// composants matériels locaux. Erreur si la sortie est vide ou non entière (on
// refuse d'inventer un compte à partir d'une sortie illisible).
func HardwareLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie inventaire matériel vide")
	}
	count, ok := atoiSafe(ls[0])
	if !ok {
		return nil, fmt.Errorf("nombre de composants matériels illisible : %q", ls[0])
	}
	return json.Marshal(HardwareEvidence{ItemsEnumerated: count})
}
