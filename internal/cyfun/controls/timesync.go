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

// Famille SYNCHRONISATION DE TEMPS. Sonde auto-contenue (sur le modèle de
// PR.AA-05.3) : une seule collecte read-only constate si l'horloge de l'hôte est
// synchronisée sur une source de temps faisant autorité (NTP/chrony/w32time),
// et laquelle. C'est le proxy technique de PR.PS-04.2 : les journaux ne valent
// comme preuve d'audit que si leurs horodatages reposent sur une horloge fiable
// et synchronisée. Le PROCESSUS documenté (politique d'horodatage, revue) reste
// organisationnel (axe Documentation via questionnaire). Le scan plafonne donc à
// Managed (4) : Optimizing (5) s'atteste par preuve organisationnelle (override
// tracé), jamais déduit d'un endpoint isolé.

// TimeSyncEvidence = faits bruts (lecture seule) sur l'état de synchronisation.
type TimeSyncEvidence struct {
	Synchronized bool   `json:"synchronized"`     // l'horloge est-elle synchronisée ?
	Source       string `json:"source,omitempty"` // source de temps observée (serveur NTP, référence chrony…)
}

// TimeSyncWinCmd : collecte Windows LECTURE SEULE via `w32tm /query /source`.
// La synchronisation en est déduite en Go de façon NEUTRE (source externe =
// nom/IP pointé) au lieu de parser le statut w32tm dont les libellés sont
// traduits. Sans droits d'administration, w32tm répond « Accès refusé
// (0x80070005) » : la sonde le signale (droits insuffisants) au lieu d'émettre
// ce message comme « source » — l'ancienne version le prenait pour une source
// externe (il contient un point) et concluait « synchronisée ». Le journal
// System (événements 35/37) n'est pas un substitut fiable : constaté le
// 28/09/2026, des données valides reçues (37) coexistaient avec une horloge
// jamais synchronisée selon w32tm.
const TimeSyncWinCmd = WinPre + `$s=(w32tm /query /source 2>&1) -join ''; $c=$LASTEXITCODE; if($s -match '0x80070005|denied|refus|verweigert|geweigerd'){'ACCESS DENIED: w32tm (etat de synchronisation lisible par un administrateur seulement)'; exit 0}; if($s -match '0x80070426'){$s='service W32Time arrete'}elseif($c -ne 0){[Console]::Error.WriteLine("PROBE ERROR: w32tm : $s"); exit 1}; [pscustomobject]@{source=$s.Trim()}|ConvertTo-Json`

// TimeSyncLinuxCmd : collecte Linux LECTURE SEULE, émet 2 lignes : « yes »/« no »
// selon l'état de synchronisation (timedatectl, avec repli chronyc), puis la
// source de temps (référence chrony, sinon « unknown »).
const TimeSyncLinuxCmd = `timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi 'yes' && echo yes || (timedatectl 2>/dev/null | grep -qi 'synchronized: yes' && echo yes || echo no); (chronyc tracking 2>/dev/null | awk -F': ' '/Reference/{print $2; exit}' || echo unknown)`

// --- PR.PS-04.2 (Important, non-KM, SCAN) — horodatage sur source faisant autorité ---

// PRPS0402Meta : texte officiel du CCB (Important).
var PRPS0402Meta = cyfun.ControlMeta{
	ID: "PR.PS-04.2", Function: cyfun.Protect, Category: "PR.PS", Subcategory: "PR.PS-04",
	Level: cyfun.LevelImportant, KeyMeasure: false,
	Requirement: "The organisation shall ensure that logbook records contain an authoritative time source or internal clock time stamp that is compared and synchronised with an authoritative time source.",
}

// PRPS0402Questions : volet Documentation (le scan couvre l'Implementation).
var PRPS0402Questions = []survey.Question{
	survey.Ask("PR.PS-04.2", survey.Documentation, "policy",
		"La synchronisation des horloges sur une source de temps faisant autorité (NTP) est-elle documentée et revue ?"),
}

// TimeSyncEvaluator implémente assess.Evaluator pour PR.PS-04.2.
type TimeSyncEvaluator struct{}

func (TimeSyncEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev TimeSyncEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateTimeSync(raw.Host, ev)
}

// evaluateTimeSync : règle de décision pure. Plafond Managed (le scan n'atteste
// jamais Optimizing).
func evaluateTimeSync(host assess.HostRef, ev TimeSyncEvidence) assess.HostAssessment {
	f := assess.Finding{HostID: host.ID, Detail: map[string]any{
		"synchronized": ev.Synchronized,
		"source":       ev.Source,
	}}
	var lvl cyfun.MaturityLevel
	if ev.Synchronized {
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = fmt.Sprintf("Horloge synchronisée sur %s.", timeSyncSource(ev.Source))
	} else {
		lvl, f.Status = cyfun.Repeatable, assess.StatusFail
		f.Message = "Horloge non synchronisée sur une source de temps faisant autorité."
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// timeSyncSource : libellé lisible d'une source, avec repli si inconnue/absente.
func timeSyncSource(src string) string {
	if src == "" || src == "unknown" {
		return "une source de temps faisant autorité"
	}
	return src
}

// --- Normalisation brut → TimeSyncEvidence ---

// TimeSyncWindowsNormalizer parse le JSON émis côté Windows :
// {"synchronized":bool,"source":string}.
func TimeSyncWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		Source *string `json:"source"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie synchronisation de temps illisible : %w", err)
	}
	if w.Source == nil {
		return nil, errors.New("champ source absent")
	}
	// Synchronisé si la source est une horloge EXTERNE (nom/IP pointé, ex.
	// time.windows.com, 10.0.0.1) et non une horloge locale (« Local CMOS Clock »/
	// « Horloge CMOS locale »/… — traduit, mais sans point). Heuristique NEUTRE.
	src := strings.TrimSpace(*w.Source)
	if src == "" || strings.Contains(src, "0x8007") {
		return nil, fmt.Errorf("source de temps illisible : %q", src)
	}
	return json.Marshal(TimeSyncEvidence{
		// « VM IC Time Synchronization Provider » : invité Hyper-V synchronisé par son hôte.
		Synchronized: strings.Contains(src, ".") || strings.Contains(src, "VM IC Time Synchronization Provider"),
		Source:       src,
	})
}

// TimeSyncLinuxNormalizer parse 2 lignes : « yes »/« no » (synchronisé) puis la
// source de temps observée.
func TimeSyncLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie synchronisation de temps vide")
	}
	ev := TimeSyncEvidence{Synchronized: ls[0] == "yes"}
	if len(ls) > 1 && ls[1] != "unknown" {
		ev.Source = ls[1]
	}
	return json.Marshal(ev)
}
