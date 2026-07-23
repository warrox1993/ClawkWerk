package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// Famille MÉDIA AMOVIBLE & DÉMARRAGE SÉCURISÉ — sonde SCANNABLE auto-contenue.
// Une seule collecte (BootDeviceEvidence) alimente trois contrôles Important de la
// sous-catégorie PR.DS-01 : intégrité au démarrage (Secure Boot), restriction du
// stockage amovible, et blocage de l'exécution automatique. C'est le modèle « sonde
// de famille » : le scan CONSTATE l'état technique de l'hôte, mais chacun de ces
// contrôles est MIXTE — l'existence d'une politique média/intégrité DOCUMENTÉE reste
// organisationnelle (axe Documentation via questionnaire). Le scan plafonne donc à
// Defined (3) : les niveaux Managed/Optimizing s'attestent par preuve organisationnelle
// (override tracé), jamais déduits d'un endpoint isolé.

// BootDeviceEvidence = faits bruts (lecture seule) sur un hôte : contenu attendu de
// RawEvidence.Data après normalisation.
type BootDeviceEvidence struct {
	SecureBootEnabled   bool `json:"secure_boot_enabled"`  // UEFI Secure Boot actif (intégrité au démarrage)
	RemovableRestricted bool `json:"removable_restricted"` // usage du stockage amovible restreint techniquement
	AutorunDisabled     bool `json:"autorun_disabled"`     // exécution automatique des médias bloquée
}

// BootDeviceWinCmd : collecte Windows LECTURE SEULE. Confirm-SecureBootUEFI pour l'état
// Secure Boot ; NoDriveTypeAutoRun (0xff/0x95/0xb5 = autorun désactivé) ; USBSTOR Start
// à 0x4 (pilote de stockage USB désactivé => média restreint). Émet du JSON canonique.
const BootDeviceWinCmd = `$sb=$false; try{$sb=Confirm-SecureBootUEFI}catch{}; $ar=(reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun 2>$null | Select-String '0xff|0x95|0xb5'); $rem=(reg query "HKLM\System\CurrentControlSet\Services\USBSTOR" /v Start 2>$null | Select-String '0x4'); [pscustomobject]@{secure_boot_enabled=[bool]$sb; removable_restricted=($rem -ne $null); autorun_disabled=($ar -ne $null)} | ConvertTo-Json`

// BootDeviceLinuxCmd : collecte Linux LECTURE SEULE, émet 3 lignes yes/no : état Secure
// Boot (mokutil), média restreint (montages usb en noexec/nodev), autorun désactivé.
// Sous Linux il n'existe pas d'autorun interactif façon Windows => la 3e ligne est
// toujours « yes ».
const BootDeviceLinuxCmd = `mokutil --sb-state 2>/dev/null | grep -qi 'enabled' && echo yes || echo no; (grep -qsE 'usb.*(noexec|nodev)' /proc/mounts 2>/dev/null && echo yes || echo no); echo yes`

// --- Normalisation brut → BootDeviceEvidence ---

// BootDeviceWindowsNormalizer parse le JSON émis côté Windows. secure_boot_enabled est
// requis (preuve de fraîcheur de la collecte) ; les deux autres champs sont optionnels.
func BootDeviceWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		SecureBootEnabled   *bool `json:"secure_boot_enabled"`
		RemovableRestricted *bool `json:"removable_restricted"`
		AutorunDisabled     *bool `json:"autorun_disabled"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie média/démarrage illisible : %w", err)
	}
	if w.SecureBootEnabled == nil {
		return nil, errors.New("champ secure_boot_enabled absent")
	}
	return json.Marshal(BootDeviceEvidence{
		SecureBootEnabled:   derefBool(w.SecureBootEnabled),
		RemovableRestricted: derefBool(w.RemovableRestricted),
		AutorunDisabled:     derefBool(w.AutorunDisabled),
	})
}

// BootDeviceLinuxNormalizer parse 3 lignes yes/no (Secure Boot, média restreint, autorun
// désactivé). Une ligne vaut true ssi elle est exactement « yes » ; une ligne absente
// vaut false (fail-safe : l'absence de preuve n'est jamais lue comme conforme).
func BootDeviceLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie média/démarrage vide")
	}
	yes := func(i int) bool { return i < len(ls) && ls[i] == "yes" }
	return json.Marshal(BootDeviceEvidence{
		SecureBootEnabled:   yes(0),
		RemovableRestricted: yes(1),
		AutorunDisabled:     yes(2),
	})
}

// --- Décodage + évaluation communs à la famille ---

// decodeBootDevice factorise le décodage : collecte échouée et preuve illisible sont
// converties en errorAssessment (renvoyé si non nil, sinon la preuve typée).
func decodeBootDevice(raw assess.RawEvidence) (BootDeviceEvidence, *assess.HostAssessment) {
	if raw.CollectErr != "" {
		ha := errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
		return BootDeviceEvidence{}, &ha
	}
	var ev BootDeviceEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		ha := errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
		return BootDeviceEvidence{}, &ha
	}
	return ev, nil
}

// evalBootControl note un contrôle booléen MIXTE de la famille, plafonné à cap.
// Fonction PURE. ok=true → Pass au niveau cap (le plafond MIXTE = niveau haut atteignable
// par scan) ; ok=false → failLvl + failStatus. Le détail reporte les trois faits pour la
// traçabilité, indépendamment du champ noté par ce contrôle.
func evalBootControl(host assess.HostRef, ev BootDeviceEvidence, ok bool,
	cap, failLvl cyfun.MaturityLevel, failStatus assess.Status, passMsg, failMsg string) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"secure_boot_enabled":  ev.SecureBootEnabled,
		"removable_restricted": ev.RemovableRestricted,
		"autorun_disabled":     ev.AutorunDisabled,
	}}
	var lvl cyfun.MaturityLevel
	if ok {
		lvl, f.Status, f.Message = cap, assess.StatusPass, passMsg
	} else {
		lvl, f.Status, f.Message = failLvl, failStatus, failMsg
	}
	if lvl > cap { // plafond de niveau : un contrôle MIXTE ne dépasse pas Defined par scan seul.
		lvl = cap
	}
	return assess.HostAssessment{Host: host, Findings: []assess.Finding{f}, ProposedImplLevel: lvl, Rationale: f.Message}
}

// --- PR.DS-01.1 (Important, MIXTE) — intégrité au démarrage / Secure Boot ---

// PRDS0101Meta : texte officiel du CCB.
var PRDS0101Meta = cyfun.ControlMeta{
	ID: "PR.DS-01.1", Function: cyfun.Protect, Category: "PR.DS", Subcategory: "PR.DS-01",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "The organisation shall implement software, firmware, and information integrity checks to detect unauthorised changes to its critical system components during storage, transport, start-up and when determined necessary.",
}

// PRDS0101Questions : volet Documentation (le scan couvre l'Implementation).
var PRDS0101Questions = []survey.Question{
	survey.Ask("PR.DS-01.1", survey.Documentation, "policy",
		"Des contrôles d'intégrité (logiciel, firmware, démarrage sécurisé) sont-ils documentés et revus pour détecter les modifications non autorisées ?"),
}

// BootIntegrityEvaluator (PR.DS-01.1) — sur SecureBootEnabled, plafond Defined.
type BootIntegrityEvaluator struct{}

func (BootIntegrityEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeBootDevice(raw)
	if errHA != nil {
		return *errHA
	}
	return evalBootControl(raw.Host, ev, ev.SecureBootEnabled,
		cyfun.Defined, cyfun.Repeatable, assess.StatusPartial,
		"Secure Boot activé : intégrité au démarrage constatée (contrôles d'intégrité organisationnels à attester).",
		"Secure Boot désactivé : intégrité au démarrage non garantie (part organisationnelle à documenter).")
}

// --- PR.DS-01.4 (Important, MIXTE) — restriction du stockage amovible ---

var PRDS0104Meta = cyfun.ControlMeta{
	ID: "PR.DS-01.4", Function: cyfun.Protect, Category: "PR.DS", Subcategory: "PR.DS-01",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "The organisation shall define and enforce clear policies and practical safeguards to manage and restrict the use of portable storage media, in order to reduce the risk of data leakage, unauthorised access, and malware introduction.",
}

var PRDS0104Questions = []survey.Question{
	survey.Ask("PR.DS-01.4", survey.Documentation, "policy",
		"Une politique de gestion et de restriction des supports de stockage amovibles est-elle documentée, approuvée et appliquée ?"),
}

// RemovableMediaEvaluator (PR.DS-01.4) — sur RemovableRestricted, plafond Defined.
type RemovableMediaEvaluator struct{}

func (RemovableMediaEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeBootDevice(raw)
	if errHA != nil {
		return *errHA
	}
	return evalBootControl(raw.Host, ev, ev.RemovableRestricted,
		cyfun.Defined, cyfun.Repeatable, assess.StatusPartial,
		"Stockage amovible restreint : mesure technique constatée (politique média organisationnelle à attester).",
		"Stockage amovible non restreint : risque de fuite/accès non autorisé/malware (part organisationnelle à documenter).")
}

// --- PR.DS-01.5 (Important, MIXTE) — exécution automatique des médias bloquée ---

var PRDS0105Meta = cyfun.ControlMeta{
	ID: "PR.DS-01.5", Function: cyfun.Protect, Category: "PR.DS", Subcategory: "PR.DS-01",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "The organisation shall only allow the use of removable media when absolutely necessary, and shall put technical measures in place to block automatic execution of files from these devices.",
}

var PRDS0105Questions = []survey.Question{
	survey.Ask("PR.DS-01.5", survey.Documentation, "policy",
		"L'usage des médias amovibles est-il limité au strict nécessaire et le blocage de l'exécution automatique est-il documenté et vérifié ?"),
}

// AutorunEvaluator (PR.DS-01.5) — sur AutorunDisabled, plafond Defined. Sur échec, le
// constat est plus dur (Fail) : l'exécution automotique active est un vecteur direct.
type AutorunEvaluator struct{}

func (AutorunEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	ev, errHA := decodeBootDevice(raw)
	if errHA != nil {
		return *errHA
	}
	return evalBootControl(raw.Host, ev, ev.AutorunDisabled,
		cyfun.Defined, cyfun.Repeatable, assess.StatusFail,
		"Exécution automatique désactivée : mesure technique constatée (politique média organisationnelle à attester).",
		"Exécution automatique non bloquée : risque d'introduction de malware (part organisationnelle à documenter).")
}
