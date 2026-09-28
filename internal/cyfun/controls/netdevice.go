package controls

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// === Framework d'audit des ÉQUIPEMENTS RÉSEAU ===
//
// Un équipement réseau (firewall, routeur, switch, point d'accès) est traité
// comme un hôte du périmètre dont la « plateforme » (l'OS constructeur) est
// portée par HostRef.OS. Le moteur aiguille déjà les commandes par OS : il
// suffit donc, pour chaque contrôle réseau scannable, de fournir une commande
// LECTURE SEULE et un normaliseur PAR PLATEFORME. Aucun changement de moteur.
//
// Un « adaptateur » = (plateforme, constructeur, commande read-only,
// normaliseur, statut de maturité de l'adaptateur). Chaque fichier
// adapter_<vendor>.go s'enregistre tout seul via init() : on peut ajouter une
// marque sans toucher au reste (idéal pour paralléliser et pour une matrice de
// couverture honnête).

// Plateformes (OS constructeur) portées par HostRef.OS pour les équipements.
const (
	PlatformRouterOS = "routeros" // MikroTik
	PlatformPfSense  = "pfsense"  // pfSense / OPNsense (FreeBSD + pf)
	PlatformFortiOS  = "fortios"  // Fortinet FortiGate
	PlatformCiscoIOS = "ciscoios" // Cisco IOS / IOS-XE
	PlatformUniFi    = "unifi"    // Ubiquiti UniFi
	PlatformSophosXG = "sophosxg" // Sophos Firewall (XG/XGS)
	PlatformSonicOS  = "sonicos"  // SonicWall
	PlatformFireware = "fireware" // WatchGuard
	PlatformZyNOS    = "zynos"    // Zyxel
	PlatformPanOS    = "panos"    // Palo Alto
)

// AdapterStatus qualifie honnêtement la fiabilité d'un adaptateur.
type AdapterStatus string

const (
	// StatusValidated : commandes vérifiées sur matériel réel.
	StatusValidated AdapterStatus = "validé-matériel"
	// StatusDocsUnverified : commandes écrites d'après la documentation
	// constructeur, PAS encore testées sur un équipement réel. À valider au banc.
	StatusDocsUnverified AdapterStatus = "d'après-doc-non-validé"
	// StatusStub : plateforme reconnue mais adaptateur non écrit.
	StatusStub AdapterStatus = "non-implémenté"
)

// NetAdapter branche une plateforme sur un contrôle réseau scannable.
type NetAdapter struct {
	Platform  string
	Vendor    string
	Command   string // commande CLI LECTURE SEULE
	Normalize assess.NormalizeFunc
	Status    AdapterStatus
}

// Registre GÉNÉRIQUE des adaptateurs, indexé par ID de contrôle réseau. Chaque
// fichier adapter_<vendor>.go y enregistre ses adaptateurs via init(). Rendre le
// registre générique (au lieu d'un registre par contrôle) permet d'ajouter un
// nouveau contrôle réseau (segmentation, journalisation…) sans dupliquer la
// mécanique d'enregistrement.
var netAdapters = map[string][]NetAdapter{}

// registerNetAdapter enregistre un adaptateur pour un contrôle donné.
func registerNetAdapter(controlID string, a NetAdapter) {
	netAdapters[controlID] = append(netAdapters[controlID], a)
}

// NetCoverage renvoie la matrice de couverture d'un contrôle, triée par
// plateforme — état HONNÊTE (jamais de « 100 % » implicite).
func NetCoverage(controlID string) []NetAdapter {
	cp := make([]NetAdapter, len(netAdapters[controlID]))
	copy(cp, netAdapters[controlID])
	sort.Slice(cp, func(i, j int) bool { return cp[i].Platform < cp[j].Platform })
	return cp
}

// NetCommands / NetNormalizers renvoient les commandes / normaliseurs d'un
// contrôle, indexés par plateforme.
func NetCommands(controlID string) map[string]string {
	out := make(map[string]string)
	for _, a := range netAdapters[controlID] {
		out[a.Platform] = a.Command
	}
	return out
}

func NetNormalizers(controlID string) map[string]assess.NormalizeFunc {
	out := make(map[string]assess.NormalizeFunc)
	for _, a := range netAdapters[controlID] {
		out[a.Platform] = a.Normalize
	}
	return out
}

// --- Enveloppes par contrôle (compat + lisibilité) ---

// PR.IR-01.1 — pare-feu réseau. registerNetFirewall est conservé pour ne pas
// toucher les 10 fichiers adapter_*.go existants.
func registerNetFirewall(a NetAdapter)                        { registerNetAdapter(PRIR0101Meta.ID, a) }
func NetFirewallCoverage() []NetAdapter                       { return NetCoverage(PRIR0101Meta.ID) }
func NetFirewallCommands() map[string]string                  { return NetCommands(PRIR0101Meta.ID) }
func NetFirewallNormalizers() map[string]assess.NormalizeFunc { return NetNormalizers(PRIR0101Meta.ID) }

// PR.IR-01.2 — segmentation réseau.
func registerNetSegmentation(a NetAdapter)       { registerNetAdapter(PRIR0102Meta.ID, a) }
func NetSegmentationCoverage() []NetAdapter      { return NetCoverage(PRIR0102Meta.ID) }
func NetSegmentationCommands() map[string]string { return NetCommands(PRIR0102Meta.ID) }
func NetSegmentationNormalizers() map[string]assess.NormalizeFunc {
	return NetNormalizers(PRIR0102Meta.ID)
}

// PR.PS-04.1 — journalisation, volet ÉQUIPEMENTS RÉSEAU. Les adaptateurs réseau
// produisent une LoggingEvidence (comme les sondes endpoint) : l'évaluateur est
// partagé, seules les commandes/normaliseurs par plateforme diffèrent.
func registerNetLogging(a NetAdapter)       { registerNetAdapter(PRPS0401Meta.ID, a) }
func NetLoggingCoverage() []NetAdapter      { return NetCoverage(PRPS0401Meta.ID) }
func NetLoggingCommands() map[string]string { return NetCommands(PRPS0401Meta.ID) }
func NetLoggingNormalizers() map[string]assess.NormalizeFunc {
	return NetNormalizers(PRPS0401Meta.ID)
}

// === Contrôle PR.IR-01.1 — pare-feu réseau (promu SCANNABLE) ===

// NetFirewallEvidence = posture pare-feu d'un équipement réseau, forme
// canonique commune à tous les constructeurs (chaque adaptateur y mappe sa
// sortie CLI). C'est ce que consomme l'évaluateur.
type NetFirewallEvidence struct {
	Present            bool   `json:"present"`              // l'équipement fait du filtrage
	Enabled            bool   `json:"enabled"`              // des règles de filtrage sont actives
	DefaultInboundDeny bool   `json:"default_inbound_deny"` // politique entrante = bloquer par défaut
	RuleCount          int    `json:"rule_count"`           // nb de règles de filtrage
	Firmware           string `json:"firmware,omitempty"`   // version (traçabilité)
}

// PRIR0101Meta : texte officiel du CCB. Key Measure.
var PRIR0101Meta = cyfun.ControlMeta{
	ID:          "PR.IR-01.1",
	Function:    cyfun.Protect,
	Category:    "PR.IR",
	Subcategory: "PR.IR-01",
	Requirement: "Firewalls shall be installed, configured, and actively maintained on all networks used by the organisation to protect against unauthorised  access and cyber threats.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// PRIR0101Questions : volet Documentation (le scan couvre l'Implementation).
var PRIR0101Questions = []survey.Question{
	survey.Ask("PR.IR-01.1", survey.Documentation, "policy",
		"La présence, la configuration et la maintenance de pare-feu réseau sont-elles exigées et documentées ?"),
}

// nombre de règles au-delà duquel on considère un jeu de règles « substantiel ».
const netFwSubstantiveRules = 8

// NetFirewallEvaluator implémente assess.Evaluator pour PR.IR-01.1.
type NetFirewallEvaluator struct{}

func (NetFirewallEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev NetFirewallEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateNetFirewall(raw.Host, ev)
}

func evaluateNetFirewall(host assess.HostRef, ev NetFirewallEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"present":         ev.Present,
			"enabled":         ev.Enabled,
			"default_deny_in": ev.DefaultInboundDeny,
			"rule_count":      ev.RuleCount,
			"firmware":        ev.Firmware,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case !ev.Present:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Aucune fonction de pare-feu détectée sur l'équipement."
	case !ev.Enabled:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Pare-feu présent mais aucune règle de filtrage active."
	case !ev.DefaultInboundDeny:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("Pare-feu actif (%d règles) mais pas de politique « bloquer par défaut » en entrée.", ev.RuleCount)
	case ev.RuleCount < netFwSubstantiveRules:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("Pare-feu actif, deny par défaut en entrée, jeu de règles limité (%d).", ev.RuleCount)
	default:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = fmt.Sprintf("Pare-feu actif, deny par défaut, jeu de règles substantiel (%d).", ev.RuleCount)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}
