package controls

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// PR.AA-05.3 — « Access rights, privileges and authorisations shall be
// restricted to the systems and specific information needed to perform the
// tasks (the principle of Least Privilege). » KEY MEASURE. Contrôle SCANNABLE :
// on constate sur l'hôte la surface d'exposition, proxy technique du moindre
// privilège et du durcissement — présence de services/protocoles legacy en
// clair à l'écoute (telnet, ftp, rsh/rlogin), et nombre total de ports TCP en
// écoute (plus la surface est large, plus le risque d'accès superflu est haut).
// Le PROCESSUS d'attribution/revue des droits reste organisationnel (axe
// Documentation via questionnaire). Le scan plafonne donc à Managed (4) : le
// niveau Optimizing (5) s'atteste par preuve organisationnelle (override tracé).

// HardeningEvidence = faits bruts (lecture seule) sur la surface d'exposition.
type HardeningEvidence struct {
	LegacyServices     int `json:"legacy_services"`      // protocoles legacy en clair à l'écoute (telnet 23, ftp 21, rsh/rlogin 512-514)
	OpenListeningPorts int `json:"open_listening_ports"` // nb total de ports TCP en écoute
}

// PRAA0503Meta : texte officiel du CCB. Key Measure.
var PRAA0503Meta = cyfun.ControlMeta{
	ID:          "PR.AA-05.3",
	Function:    cyfun.Protect,
	Category:    "PR.AA",
	Subcategory: "PR.AA-05",
	Requirement: "Access rights, privileges and authorisations shall be restricted to the systems and specific information needed to perform the tasks (the principle of Least Privilege).",
	Level:       "Basic",
	KeyMeasure:  true,
}

// PRAA0503Questions : volet Documentation (le scan couvre l'Implementation).
var PRAA0503Questions = []survey.Question{
	survey.Ask("PR.AA-05.3", survey.Documentation, "policy",
		"Une règle de moindre privilège et de durcissement (désactivation des services/protocoles inutiles) est-elle documentée ?"),
}

// Seuils sur le nombre de ports TCP en écoute. Isolés en constantes.
const (
	portsWideThreshold     = 15 // > 15 ports en écoute : surface d'exposition large
	portsModerateThreshold = 5  // > 5 ports : surface à surveiller ; ≤ 5 : surface minimale
)

// PRAA0503WinCmd : collecte Windows LECTURE SEULE (downlevel via netstat), émet
// du JSON {legacy_services, open_listening_ports}. Compte les lignes LISTENING
// et, parmi elles, celles exposant un port legacy en clair (21/23/512/513/514).
const PRAA0503WinCmd = `$l=@(netstat -ano | Select-String 'LISTENING'); $leg=@($l | Select-String ':21 |:23 |:512 |:513 |:514 ').Count; [pscustomobject]@{legacy_services=$leg; open_listening_ports=$l.Count} | ConvertTo-Json`

// PRAA0503LinuxCmd : collecte Linux LECTURE SEULE, émet 2 lignes : nombre total
// de ports TCP en écoute, puis nombre de ports legacy en clair (21/23/512-514).
//
// `grep -c` sort avec le code 1 quand il ne trouve RIEN, c'est-à-dire sur une
// machine saine sans protocole legacy : sans le `|| true`, la commande échouait
// et le contrôle était classé « collecte échouée ». Si `ss` est introuvable, la
// sonde échoue explicitement : zéro port lu ne doit jamais passer pour une
// surface d'exposition minimale.
const PRAA0503LinuxCmd = `export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"; ` +
	`command -v ss >/dev/null 2>&1 || { echo 'ss introuvable (paquet iproute2) : ports en écoute non énumérables' >&2; exit 2; }; ` +
	`ss -tlnH 2>/dev/null | wc -l; ss -tlnH 2>/dev/null | grep -cE ':(21|23|512|513|514) ' || true`

// HardeningEvaluator implémente assess.Evaluator pour PR.AA-05.3.
type HardeningEvaluator struct{}

func (HardeningEvaluator) Evaluate(raw assess.RawEvidence) assess.HostAssessment {
	if raw.CollectErr != "" {
		return errorAssessment(raw.Host, "Collecte échouée : "+raw.CollectErr)
	}
	var ev HardeningEvidence
	if err := json.Unmarshal(raw.Data, &ev); err != nil {
		return errorAssessment(raw.Host, "Preuve illisible : "+err.Error())
	}
	return evaluateHardening(raw.Host, ev)
}

func evaluateHardening(host assess.HostRef, ev HardeningEvidence) assess.HostAssessment {
	f := assess.Finding{
		HostID: host.ID,
		Detail: map[string]any{
			"legacy_services":      ev.LegacyServices,
			"open_listening_ports": ev.OpenListeningPorts,
		},
	}
	var lvl cyfun.MaturityLevel
	switch {
	case ev.LegacyServices > 0:
		lvl, f.Status = cyfun.Initial, assess.StatusFail
		f.Message = fmt.Sprintf("%d protocoles legacy en clair détectés — durcissement insuffisant.", ev.LegacyServices)
	case ev.OpenListeningPorts > portsWideThreshold:
		lvl, f.Status = cyfun.Repeatable, assess.StatusPartial
		f.Message = fmt.Sprintf("Surface d'exposition large (%d ports en écoute) : à réduire au strict nécessaire.", ev.OpenListeningPorts)
	case ev.OpenListeningPorts > portsModerateThreshold:
		lvl, f.Status = cyfun.Defined, assess.StatusPass
		f.Message = fmt.Sprintf("Surface maîtrisée (%d ports en écoute), aucun protocole legacy.", ev.OpenListeningPorts)
	default:
		lvl, f.Status = cyfun.Managed, assess.StatusPass
		f.Message = fmt.Sprintf("Surface minimale (%d ports en écoute), aucun protocole legacy.", ev.OpenListeningPorts)
	}
	return assess.HostAssessment{
		Host:              host,
		Findings:          []assess.Finding{f},
		ProposedImplLevel: lvl,
		Rationale:         f.Message,
	}
}

// --- Normalisation brut → HardeningEvidence ---

// HardeningWindowsNormalizer parse le JSON émis côté Windows :
// {"legacy_services":int,"open_listening_ports":int}.
func HardeningWindowsNormalizer(raw []byte) (json.RawMessage, error) {
	var w struct {
		LegacyServices     *int `json:"legacy_services"`
		OpenListeningPorts *int `json:"open_listening_ports"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("sortie surface d'exposition illisible : %w", err)
	}
	if w.OpenListeningPorts == nil {
		return nil, errors.New("champ open_listening_ports absent")
	}
	return json.Marshal(HardeningEvidence{
		LegacyServices:     derefInt(w.LegacyServices),
		OpenListeningPorts: derefInt(w.OpenListeningPorts),
	})
}

// HardeningLinuxNormalizer parse 2 lignes : nombre total de ports TCP en écoute,
// puis nombre de ports legacy en clair.
func HardeningLinuxNormalizer(raw []byte) (json.RawMessage, error) {
	ls := lines(raw)
	if len(ls) == 0 {
		return nil, errors.New("sortie surface d'exposition vide")
	}
	ports, ok := atoiSafe(ls[0])
	if !ok {
		return nil, fmt.Errorf("nombre de ports en écoute illisible : %q", ls[0])
	}
	ev := HardeningEvidence{OpenListeningPorts: ports}
	if len(ls) > 1 {
		if v, ok := atoiSafe(ls[1]); ok {
			ev.LegacyServices = v
		}
	}
	return json.Marshal(ev)
}
