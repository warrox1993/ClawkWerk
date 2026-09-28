package controls

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// AntivirusEvidence = faits bruts collectés (lecture seule) pour DE.CM-01.2
// sur un hôte. C'est le contenu attendu de RawEvidence.Data.
type AntivirusEvidence struct {
	Present            bool   `json:"present"`
	Enabled            bool   `json:"enabled"`
	RealtimeProtection bool   `json:"realtime_protection"`
	Product            string `json:"product"`
	DefinitionsAgeDays int    `json:"definitions_age_days"`
}

// DECM0102Meta : métadonnées officielles du contrôle (texte exact du CCB).
var DECM0102Meta = cyfun.ControlMeta{
	ID:          "DE.CM-01.2",
	Function:    cyfun.Detect,
	Category:    "DE.CM",
	Subcategory: "DE.CM-01",
	Requirement: "Anti-virus, -spyware, and other -malware programs shall be installed and updated.",
	Level:       "Basic",
	KeyMeasure:  true,
}

// DECM0102Questions : volet DOCUMENTATION du contrôle (l'Implementation vient
// du scan antivirus). Contrôle scannable => aucune question Implementation.
var DECM0102Questions = []survey.Question{
	survey.Ask("DE.CM-01.2", survey.Documentation, "policy",
		"Existe-t-il une politique écrite imposant l'installation et la mise à jour d'un antivirus/anti-malware sur les postes et serveurs ?"),
	survey.Ask("DE.CM-01.2", survey.Documentation, "review",
		"Cette politique est-elle approuvée et revue (au moins tous les 2 ans ou à chaque changement) ?"),
}

// Seuils de fraîcheur des définitions (en jours). Isolés comme constantes
// pour être ajustés sans toucher à la logique de décision.
const (
	defsFreshDays = 7  // ≤ 7 j : définitions considérées à jour
	defsStaleDays = 30 // > 30 j : définitions périmées
)

// --- Normalisation brut → AntivirusEvidence ---

// defenderRaw = forme JSON produite par `Get-MpComputerStatus | Select ... |
// ConvertTo-Json` (noms de champs natifs Defender).
type defenderRaw struct {
	AntivirusEnabled          *bool `json:"AntivirusEnabled"`
	RealTimeProtectionEnabled *bool `json:"RealTimeProtectionEnabled"`
	AntivirusSignatureAge     *int  `json:"AntivirusSignatureAge"`
}

// AntivirusWindowsNormalizer mappe la sortie Defender vers AntivirusEvidence.
func AntivirusWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var d defenderRaw
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("sortie Defender illisible : %w", err)
	}
	if d.AntivirusEnabled == nil {
		return nil, errors.New("champ AntivirusEnabled absent")
	}
	return json.Marshal(AntivirusEvidence{
		Present:            true, // Get-MpComputerStatus a répondu => Defender présent
		Enabled:            derefBool(d.AntivirusEnabled),
		RealtimeProtection: derefBool(d.RealTimeProtectionEnabled),
		Product:            "Microsoft Defender",
		DefinitionsAgeDays: derefInt(d.AntivirusSignatureAge),
	})
}

// AntivirusLinuxCmd : collecte Linux LECTURE SEULE pour DE.CM-01.2. Émet
// toujours 4 lignes et se termine par un code de sortie nul, y compris sur une
// machine sans antivirus (auparavant, le `stat` final échouait et la machine
// était classée « collecte échouée » au lieu de « aucun antivirus ») :
//  1. état du démon ClamAV (active, inactive, failed…) ou « unknown » si
//     systemd ne répond pas ;
//  2. version de freshclam, ou « absent » ;
//  3. epoch de modification des définitions (daily.cld ou daily.cvd), ou 0 ;
//  4. « autres: » suivi des services anti-malware tiers actifs (Defender for
//     Endpoint, Sophos, ESET, CrowdStrike, SentinelOne, Trend, Bitdefender,
//     Kaspersky).
//
// PATH est complété par /usr/sbin et /sbin : un compte de service non root n'y
// a souvent pas accès par défaut, et un outil introuvable ne doit pas passer
// pour un outil absent.
const AntivirusLinuxCmd = `export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"; ` +
	`S=$(systemctl is-active clamav-daemon 2>/dev/null); echo "${S:-unknown}"; ` +
	`freshclam --version 2>/dev/null || echo absent; ` +
	`stat -c %Y /var/lib/clamav/daily.cld 2>/dev/null || stat -c %Y /var/lib/clamav/daily.cvd 2>/dev/null || echo 0; ` +
	`printf 'autres:'; for s in mdatp sophos-spl eea esets falcon-sensor sentinelone ds_agent bdsec kesl; do [ "$(systemctl is-active "$s" 2>/dev/null)" = active ] && printf ' %s' "$s"; done; echo`

// AntivirusLinuxNormalizer parse la sortie de AntivirusLinuxCmd. L'horloge est
// injectée pour le calcul d'âge (fonction restante pure et testable).
//
// Décisions :
//   - ClamAV actif : preuve complète (état + fraîcheur des définitions) ;
//   - anti-malware tiers actif : sa présence est constatée mais la fraîcheur de
//     ses définitions n'est pas lisible par cette sonde, on le signale donc
//     comme trou de collecte (le questionnaire de repli prend le relais) plutôt
//     que d'inventer un âge ;
//   - systemd muet : aucun état de service lisible, trou de collecte ;
//   - rien de tout cela : aucun antivirus (non-conformité constatée).
//
// L'ancien format sur 3 lignes (sans ligne « autres: ») reste accepté.
func AntivirusLinuxNormalizer(now func() time.Time) assess.NormalizeFunc {
	return func(raw []byte) (json.RawMessage, error) {
		ls := lines(raw)
		if len(ls) == 0 {
			return nil, errors.New("sortie ClamAV vide")
		}
		var others []string
		newFormat := false
		for _, l := range ls {
			if rest, ok := strings.CutPrefix(l, "autres:"); ok {
				newFormat = true
				others = strings.Fields(rest)
			}
		}
		active := ls[0] == "active"
		freshclam := len(ls) > 1 && strings.Contains(ls[1], "ClamAV")
		present := active || freshclam
		if !newFormat && (ls[0] == "inactive" || ls[0] == "failed") {
			present = true // ancien format : l'état du service suffisait
		}
		if newFormat && !active {
			if len(others) > 0 {
				return nil, fmt.Errorf("anti-malware tiers actif (%s) : fraîcheur des définitions non vérifiable par la sonde, attestation requise", strings.Join(others, ", "))
			}
			if ls[0] == "unknown" {
				return nil, errors.New("état des services illisible (systemd indisponible) : présence d'un antivirus indéterminable")
			}
		}
		age := defsStaleDays + 1 // pas de mtime lisible => considéré périmé
		if len(ls) > 2 {
			age = ageDaysSinceEpoch(ls[2], now(), defsStaleDays+1)
		}
		return json.Marshal(AntivirusEvidence{
			Present:            present,
			Enabled:            active,
			RealtimeProtection: active, // ClamAV on-access approximé à l'état du démon
			Product:            "ClamAV",
			DefinitionsAgeDays: age,
		})
	}
}

// AntivirusEvaluator implémente assess.Evaluator pour DE.CM-01.2.
type AntivirusEvaluator struct{}

// Evaluate traduit les faits antivirus d'UN hôte en constat + niveau
// d'Implementation proposé. Fonction pure : les seules « entrées » sont dans
// raw ; aucune I/O.
//
// Note : le niveau 5 (Optimizing) n'est pas atteignable depuis ce scan par
// hôte — il suppose une gestion/reporting centralisé, une preuve d'ordre
// organisationnel qui relève du questionnaire, pas d'un endpoint isolé.
func (AntivirusEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	// Échec de collecte : on ne score pas, on signale explicitement.
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}

	var ev AntivirusEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}

	return evaluateAntivirus(raw.Host, ev)
}

// evaluateAntivirus contient la règle de décision, séparée du (dé)codage pour
// rester trivialement testable sur des faits typés.
func evaluateAntivirus(host assess.HostRef, ev AntivirusEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"present":       ev.Present,
			"enabled":       ev.Enabled,
			"realtime":      ev.RealtimeProtection,
			"product":       ev.Product,
			"defs_age_days": ev.DefinitionsAgeDays,
		},
	}
	var lvl cyfun.MaturityLevel

	switch {
	case !ev.Present:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = "Aucun antivirus détecté."
	case !ev.Enabled:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("Antivirus %q présent mais désactivé.", ev.Product)
	case ev.DefinitionsAgeDays > defsStaleDays:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("Définitions périmées (%d j > %d j).", ev.DefinitionsAgeDays, defsStaleDays)
	case !ev.RealtimeProtection:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = "Protection en temps réel désactivée."
	case ev.DefinitionsAgeDays > defsFreshDays:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("Antivirus actif ; définitions à %d j (≤ %d j).", ev.DefinitionsAgeDays, defsStaleDays)
	default:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = fmt.Sprintf("Antivirus actif, temps réel activé, définitions fraîches (%d j ≤ %d j).", ev.DefinitionsAgeDays, defsFreshDays)
	}

	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

func errorAssessment(host assess.HostRef, msg string) assess.HostAssessment {
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{{HostID: host.ID, Status: assess.StatusError, Message: msg}},
		ProposedImplLevel: cyfun.NotAssessed,
		Rationale:         "Aucune preuve exploitable.",
	}
}
