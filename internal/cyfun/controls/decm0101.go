package controls

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// DE.CM-01.1 — pare-feu (y compris endpoint) installé et opérationnel aux
// frontières réseau. Contrôle SCANNABLE : l'Implementation vient de l'état
// réel du pare-feu local de l'hôte ; la Documentation vient du questionnaire.

// FirewallEvidence = faits bruts (lecture seule) de l'état du pare-feu local.
// Windows : profils Defender Firewall (Domain/Private/Public). Linux : ufw /
// firewalld / nftables actif + politique par défaut en entrée.
type FirewallEvidence struct {
	Present            bool   `json:"present"`              // un pare-feu est présent
	Enabled            bool   `json:"enabled"`              // au moins un profil actif
	ProfilesTotal      int    `json:"profiles_total"`       // nb de profils/zones connus
	ProfilesEnabled    int    `json:"profiles_enabled"`     // nb de profils/zones actifs
	DefaultInboundDeny bool   `json:"default_inbound_deny"` // politique entrante = bloquer par défaut
	Product            string `json:"product"`              // "Windows Defender Firewall", "ufw"...
}

// DECM0101Meta : métadonnées officielles (texte exact du CCB).
var DECM0101Meta = cyfun.ControlMeta{
	ID:          "DE.CM-01.1",
	Function:    cyfun.Detect,
	Category:    "DE.CM",
	Subcategory: "DE.CM-01",
	Requirement: "Firewalls shall be installed and operated at the network boundaries, including endpoint firewalls.",
	Level:       "Basic",
	KeyMeasure:  false,
}

// DECM0101Questions : volet Documentation (le scan couvre l'Implementation).
var DECM0101Questions = []survey.Question{
	survey.Ask("DE.CM-01.1", survey.Documentation, "policy",
		"Une règle écrite impose-t-elle l'activation d'un pare-feu (y compris pare-feu local des postes/serveurs) ?"),
}

// --- Normalisation brut → FirewallEvidence ---

// netFwProfileRaw = un profil tel que rendu par `Get-NetFirewallProfile |
// ConvertTo-Json`. Les enums Windows sortent tantôt en bool, int ou string
// selon la version : on les décode en interface{} et on interprète.
type netFwProfileRaw struct {
	Name                 string `json:"Name"`
	Enabled              any    `json:"Enabled"`
	DefaultInboundAction any    `json:"DefaultInboundAction"`
}

// FirewallWindowsNormalizer accepte un profil unique ou un tableau de profils.
func FirewallWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	var profiles []netFwProfileRaw
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &profiles); err != nil {
			return nil, fmt.Errorf("profils pare-feu illisibles : %w", err)
		}
	} else {
		var one netFwProfileRaw
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, fmt.Errorf("profil pare-feu illisible : %w", err)
		}
		profiles = []netFwProfileRaw{one}
	}
	if len(profiles) == 0 {
		return nil, errors.New("aucun profil pare-feu")
	}

	enabledCount, allBlock := 0, true
	for _, p := range profiles {
		if truthy(p.Enabled) {
			enabledCount++
		}
		if !isBlockAction(p.DefaultInboundAction) {
			allBlock = false
		}
	}
	return json.Marshal(FirewallEvidence{
		Present:            true,
		Enabled:            enabledCount > 0,
		ProfilesTotal:      len(profiles),
		ProfilesEnabled:    enabledCount,
		DefaultInboundDeny: allBlock,
		Product:            "Windows Defender Firewall",
	})
}

// FirewallLinuxCmd : collecte Linux LECTURE SEULE pour DE.CM-01.1,
// MULTI-DISTRO (ufw, firewalld, nftables, iptables). La sonde sépare deux
// questions que l'ancienne version confondait :
//   - quels outils de pare-feu sont INSTALLÉS (section « # outils ») ;
//   - quel ÉTAT a pu être lu (section « # etat »), un outil présent mais non
//     lisible par le compte de service étant signalé « illisible: <outil> ».
//
// Sans cette distinction, une machine sans aucun pare-feu produisait une
// sortie vide, classée « collecte échouée » au lieu de « aucun pare-feu ».
// PATH est complété par /usr/sbin et /sbin : un compte non root n'y a souvent
// pas accès, et un outil introuvable ne doit pas passer pour un outil absent.
const FirewallLinuxCmd = `export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"; ` +
	`echo '# outils'; for t in ufw firewall-cmd nft iptables; do command -v "$t" >/dev/null 2>&1 && echo "outil: $t"; done; ` +
	`echo '# etat'; ` +
	`if command -v ufw >/dev/null 2>&1; then ufw status verbose 2>/dev/null || echo 'illisible: ufw'; fi; ` +
	`if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --state 2>&1; firewall-cmd --list-all 2>/dev/null; fi; ` +
	`if command -v nft >/dev/null 2>&1; then if nft list ruleset >/dev/null 2>&1; then echo 'lisible: nft'; nft list ruleset 2>/dev/null | grep -E 'hook input|policy ' | head -n 20; else echo 'illisible: nft'; fi; fi; ` +
	`if command -v iptables >/dev/null 2>&1; then iptables -S INPUT 2>/dev/null || echo 'illisible: iptables'; fi; true`

// FirewallLinuxNormalizer est MULTI-DISTRO : il interprète la sortie de
// FirewallLinuxCmd. Ordre de décision :
//  1. un pare-feu ACTIF est constaté (ufw actif, firewalld en marche, chaîne
//     nftables d'entrée, règles iptables en entrée) : preuve positive ;
//  2. un outil installé n'a pas pu être lu : trou de collecte qualifié
//     « droits insuffisants » (on ne conclut pas à l'absence) ;
//  3. un outil est installé et lisible mais inactif : pare-feu présent et
//     désactivé (non-conformité) ;
//  4. aucun outil de pare-feu installé : aucun pare-feu (non-conformité).
//
// L'ancien format (sans section « # outils ») reste accepté pour les preuves
// déjà rapatriées.
func FirewallLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	t := strings.ToLower(string(raw))
	if !strings.Contains(t, "# outils") {
		return firewallLinuxLegacy(t)
	}
	tools := map[string]bool{}
	var unreadable []string
	nftReadable := false
	var iptInput []string
	for _, l := range lines(raw) {
		low := strings.ToLower(l)
		switch {
		case strings.HasPrefix(low, "outil: "):
			tools[strings.TrimPrefix(low, "outil: ")] = true
		case strings.HasPrefix(low, "illisible: "):
			unreadable = append(unreadable, strings.TrimPrefix(low, "illisible: "))
		case low == "lisible: nft":
			nftReadable = true
		case strings.HasPrefix(l, "-P INPUT ") || strings.HasPrefix(l, "-A INPUT "):
			iptInput = append(iptInput, l)
		}
	}

	// 1. Pare-feu actif constaté.
	switch {
	case strings.Contains(t, "status: active"):
		denyIn := strings.Contains(t, "deny (incoming)") || strings.Contains(t, "reject (incoming)")
		return fwLinuxEvidence(true, denyIn, "ufw")
	case firewalldRunning(t):
		return fwLinuxEvidence(true, !strings.Contains(t, "target: accept"), "firewalld")
	case strings.Contains(t, "hook input") || strings.Contains(t, "chain input"):
		denyIn := strings.Contains(t, "policy drop") || strings.Contains(t, "policy reject")
		return fwLinuxEvidence(true, denyIn, "nftables")
	case iptablesFiltersInput(iptInput):
		return fwLinuxEvidence(true, iptablesDefaultDeny(iptInput), "iptables")
	}

	// 2. Un outil installé n'a pas pu être lu : on ne conclut pas à l'absence.
	if len(unreadable) > 0 {
		return nil, fmt.Errorf("droits insuffisants : état du pare-feu illisible (%s) — le compte de service doit pouvoir lire la configuration du pare-feu", strings.Join(unreadable, ", "))
	}

	// 3. Outil installé, lisible, mais inactif.
	disabled := func(product string) (json.RawMessage, error) {
		return json.Marshal(FirewallEvidence{Present: true, Enabled: false, ProfilesTotal: 1, ProfilesEnabled: 0, Product: product})
	}
	switch {
	case strings.Contains(t, "status: inactive"):
		return disabled("ufw")
	case strings.Contains(t, "not running"):
		return disabled("firewalld")
	case nftReadable:
		return disabled("nftables")
	case len(iptInput) > 0:
		return disabled("iptables")
	}

	// 4. Aucun outil de pare-feu installé.
	if len(tools) == 0 {
		return json.Marshal(FirewallEvidence{Present: false, Product: "aucun"})
	}
	return nil, errors.New("état du pare-feu non interprétable")
}

// firewalldRunning reconnaît la ligne « running » de `firewall-cmd --state`
// (et non « not running »).
func firewalldRunning(t string) bool {
	for _, l := range strings.Split(t, "\n") {
		if strings.TrimSpace(l) == "running" {
			return true
		}
	}
	return false
}

// iptablesFiltersInput : la chaîne INPUT filtre si sa politique n'est pas
// ACCEPT ou si elle porte au moins une règle.
func iptablesFiltersInput(rules []string) bool {
	for _, r := range rules {
		if strings.HasPrefix(r, "-A INPUT ") || (strings.HasPrefix(r, "-P INPUT ") && !strings.HasSuffix(r, " ACCEPT")) {
			return true
		}
	}
	return false
}

// iptablesDefaultDeny : politique d'entrée DROP, ou dernière règle qui rejette
// tout le trafic restant.
func iptablesDefaultDeny(rules []string) bool {
	for _, r := range rules {
		if r == "-P INPUT DROP" || r == "-P INPUT REJECT" {
			return true
		}
	}
	if n := len(rules); n > 0 {
		last := rules[n-1]
		return last == "-A INPUT -j DROP" || strings.HasPrefix(last, "-A INPUT -j REJECT")
	}
	return false
}

// firewallLinuxLegacy interprète l'ancien format de sonde (ufw + firewalld +
// nftables concaténés, sans liste d'outils). Sans liste d'outils, une sortie
// vide ne permet pas de distinguer « aucun pare-feu » de « rien de lisible » :
// elle reste une erreur de collecte.
func firewallLinuxLegacy(t string) (json.RawMessage, error) {
	switch {
	case strings.Contains(t, "status: active"): // ufw actif
		denyIn := strings.Contains(t, "deny (incoming)") || strings.Contains(t, "reject (incoming)")
		return fwLinuxEvidence(true, denyIn, "ufw")
	case strings.Contains(t, "running") && !strings.Contains(t, "not running"): // firewalld actif
		// firewalld : la zone par défaut rejette tout flux non explicitement
		// autorisé, sauf si sa cible est ACCEPT.
		denyIn := !strings.Contains(t, "target: accept")
		return fwLinuxEvidence(true, denyIn, "firewalld")
	case strings.Contains(t, "hook input") || strings.Contains(t, "chain input"): // nftables
		denyIn := strings.Contains(t, "policy drop") || strings.Contains(t, "policy reject")
		return fwLinuxEvidence(true, denyIn, "nftables")
	case strings.Contains(t, "status: inactive"): // ufw présent mais désactivé
		return json.Marshal(FirewallEvidence{Present: true, Enabled: false, ProfilesTotal: 1, ProfilesEnabled: 0, Product: "ufw"})
	default:
		return nil, errors.New("aucun pare-feu reconnu (ufw/firewalld/nftables)")
	}
}

// fwLinuxEvidence construit la preuve pour un pare-feu Linux actif (un « profil »
// unique, contrairement aux 3 profils Windows).
func fwLinuxEvidence(present, denyIn bool, product string) (json.RawMessage, error) {
	return json.Marshal(FirewallEvidence{
		Present:            present,
		Enabled:            true,
		ProfilesTotal:      1,
		ProfilesEnabled:    1,
		DefaultInboundDeny: denyIn,
		Product:            product,
	})
}

// truthy interprète un booléen Windows hétérogène (true, 1, "True", "Enabled").
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "true" || s == "1" || s == "enabled"
	default:
		return false
	}
}

// isBlockAction indique si l'action entrante par défaut bloque. Valeurs
// possibles selon la version : "Block", ou l'entier 4 (NetSecurity.Block).
func isBlockAction(v any) bool {
	switch x := v.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "block")
	case float64:
		return int(x) == 4
	default:
		return false
	}
}

// FirewallEvaluator implémente assess.Evaluator pour DE.CM-01.1.
type FirewallEvaluator struct{}

// Evaluate : faits pare-feu d'UN hôte -> constat + niveau proposé. Fonction pure.
func (FirewallEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev FirewallEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateFirewall(raw.Host, ev)
}

func evaluateFirewall(host assess.HostRef, ev FirewallEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"present":          ev.Present,
			"enabled":          ev.Enabled,
			"profiles_enabled": ev.ProfilesEnabled,
			"profiles_total":   ev.ProfilesTotal,
			"default_deny_in":  ev.DefaultInboundDeny,
			"product":          ev.Product,
		},
	}
	allProfiles := ev.ProfilesTotal > 0 && ev.ProfilesEnabled == ev.ProfilesTotal

	var lvl cyfun.MaturityLevel
	switch {
	case !ev.Present:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Aucun pare-feu détecté sur l'hôte."
	case !ev.Enabled:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Pare-feu présent mais désactivé (aucun profil actif)."
	case !ev.DefaultInboundDeny:
		// Actif mais politique entrante permissive : protection incomplète.
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = "Pare-feu actif mais politique entrante non bloquante par défaut."
	case !allProfiles:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = "Pare-feu actif et bloquant, mais certains profils/zones restent inactifs."
	default:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = "Pare-feu actif sur tous les profils, politique entrante bloquante par défaut."
	}

	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}
