package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"projetcyber/internal/assess"
	"projetcyber/internal/cyfun"
	"projetcyber/internal/survey"
)

// ID.AM-02.1 — « An inventory of software, digital services, and business
// systems used within the organisation shall be documented, reviewed, and
// updated as changes occur. » NON Key Measure. Contrôle FOURNISSEUR DE PREUVE :
// le scan ne juge pas la qualité de l'inventaire documenté, il prouve seulement
// qu'on peut ÉNUMÉRER techniquement les logiciels installés sur l'hôte (la base
// factuelle pour recouper un inventaire tenu à la main). Le « documenté, revu,
// tenu à jour » reste un attribut ORGANISATIONNEL (axe Documentation via
// questionnaire). Le scan PLAFONNE donc à Defined (3) : énumérer les logiciels
// atteste d'un processus formel implémenté, mais pas des métriques/revues
// (Managed/Optimizing) qui relèvent de la preuve organisationnelle.

// SoftwareInventoryEvidence = fait brut (lecture seule) : nombre de logiciels
// installés énumérés sur l'hôte.
type SoftwareInventoryEvidence struct {
	InstalledCount int `json:"installed_count"` // nb de logiciels/paquets installés énumérés
}

// IDAM0201Meta : texte officiel du CCB. Non Key Measure.
var IDAM0201Meta = cyfun.ControlMeta{
	ID:          "ID.AM-02.1",
	Function:    cyfun.Identify,
	Category:    "ID.AM",
	Subcategory: "ID.AM-02",
	Requirement: "An inventory of software, digital services, and business systems used within the organisation shall be documented, reviewed, and updated as changes occur.",
	Level:       "Basic",
	KeyMeasure:  false,
}

// IDAM0201Questions : volet Documentation. Le scan ne prouve QUE l'énumérabilité
// (base factuelle) ; le caractère « documenté/revu/à jour » se constate ici.
var IDAM0201Questions = []survey.Question{
	survey.Ask("ID.AM-02.1", survey.Documentation, "policy",
		"Un inventaire des logiciels et services (version, propriétaire, licence) est-il documenté et tenu à jour ?"),
}

// IDAM0201WinCmd : collecte Windows LECTURE SEULE via les clés de désinstallation
// du registre (natif 64 bits + WOW6432Node pour le 32 bits). On NE PASSE PAS par
// `wmic product` / `Win32_Product`, qui déclenche une reconfiguration MSI de
// chaque paquet (effet de bord destructeur) — ici on ne fait que LIRE le registre.
// Émet du JSON {installed_count}.
const IDAM0201WinCmd = `$n=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName}).Count; [pscustomobject]@{installed_count=$n} | ConvertTo-Json`

// IDAM0201LinuxCmd : collecte Linux LECTURE SEULE, multi-gestionnaire. Émet UNE
// ligne = le nombre de paquets installés, via le premier gestionnaire présent
// (dpkg, rpm, pacman, apk) ; 0 si aucun n'est disponible. Toutes les commandes
// utilisées sont des requêtes d'énumération (aucune installation/suppression).
const IDAM0201LinuxCmd = `if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -f '.\n' -W 2>/dev/null | wc -l; elif command -v rpm >/dev/null 2>&1; then rpm -qa 2>/dev/null | wc -l; elif command -v pacman >/dev/null 2>&1; then pacman -Q 2>/dev/null | wc -l; elif command -v apk >/dev/null 2>&1; then apk info 2>/dev/null | wc -l; else echo 0; fi`

// SoftwareInventoryEvaluator implémente assess.Evaluator pour ID.AM-02.1.
type SoftwareInventoryEvaluator struct{}

func (SoftwareInventoryEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev SoftwareInventoryEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateSoftwareInventory(raw.Host, ev)
}

// evaluateSoftwareInventory contient la règle de décision (pure). Deux issues
// seulement : soit l'énumération échoue (aucun logiciel remonté => on ne peut
// même pas fonder un inventaire), soit elle réussit et plafonne à Defined (3).
func evaluateSoftwareInventory(host assess.HostRef, ev SoftwareInventoryEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"installed_count": ev.InstalledCount,
		},
	}
	var lvl cyfun.MaturityLevel
	if ev.InstalledCount <= 0 {
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Énumération des logiciels impossible (aucune entrée) : inventaire non fondable sur cet hôte."
	} else {
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("Inventaire logiciel énumérable (%d entrées) — à recouper avec l'inventaire documenté.", ev.InstalledCount)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- Normalisation brut → SoftwareInventoryEvidence ---

// SoftwareInventoryWindowsNormalizer parse le JSON émis côté Windows :
// {"installed_count":int}. installed_count est requis (erreur si absent) pour ne
// jamais confondre « zéro logiciel » avec « champ non collecté ».
func SoftwareInventoryWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		InstalledCount *int `json:"installed_count"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie inventaire logiciel illisible : %w", err)
	}
	if w.InstalledCount == nil {
		return nil, errors.New("champ installed_count absent")
	}
	return json.Marshal(SoftwareInventoryEvidence{
		InstalledCount: derefInt(w.InstalledCount),
	})
}

// SoftwareInventoryLinuxNormalizer parse la sortie Linux : UNE ligne = le nombre
// de paquets installés. Erreur si la sortie est vide ou non entière (on refuse
// d'inventer un compte à partir d'une sortie illisible).
func SoftwareInventoryLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie inventaire logiciel vide")
	}
	count, ok := atoiSafe(ls[0])
	if !ok {
		return nil, fmt.Errorf("nombre de logiciels illisible : %q", ls[0])
	}
	return json.Marshal(SoftwareInventoryEvidence{InstalledCount: count})
}

// IDAM0201M365Cmd : ressource logique lue par le Microsoft365Client pour
// l'inventaire des services cloud (subscribedSkus + domains vérifiés).
const IDAM0201M365Cmd = "inventory"

// M365InventoryNormalizer transforme l'enveloppe Graph (via ParseM365Inventory) en
// SoftwareInventoryEvidence : le nombre de services cloud énumérés — preuve pour
// ID.AM-02.1 (« digital services ») et ID.AM-01.1 (environnements cloud).
func M365InventoryNormalizer(raw []byte) (json.RawMessage, error) {
	n, err := ParseM365Inventory(raw)
	if err != nil {
		return nil, fmt.Errorf("réponse Graph inventaire illisible : %w", err)
	}
	return json.Marshal(SoftwareInventoryEvidence{InstalledCount: n})
}
