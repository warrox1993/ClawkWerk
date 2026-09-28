// Package engine orchestre un audit : pour chaque contrôle et chaque hôte du
// périmètre, il collecte la preuve (Source), l'évalue (Evaluator), puis agrège
// les hôtes en un ControlResult. Il ne fait aucune I/O lui-même — il délègue à
// la Source injectée, ce qui le rend testable avec une FileSource.
package engine

import (
	"context"
	"strings"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/scan"
	"github.com/warrox1993/clawkwerk/internal/scope"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// Control lie les métadonnées d'un contrôle, son évaluateur, ses commandes de
// collecte par OS, sa fonction d'agrégation multi-hôtes et ses questions de
// questionnaire. C'est l'unité réutilisable : ajouter un contrôle = ajouter une
// entrée Control.
//
// Deux familles de contrôles cohabitent ici :
//   - SCANNABLE : Evaluator + Commands non nuls. L'Implementation vient du
//     scan (proposée puis éventuellement overridée), la Documentation du
//     questionnaire.
//   - DÉCLARATIF : Evaluator == nil, pas de Commands. Les DEUX axes viennent du
//     questionnaire (aucun hôte n'est interrogé).
type Control struct {
	Meta        cyfun.ControlMeta
	Evaluator   assess.Evaluator                // nil => contrôle déclaratif
	Commands    map[string]scan.CollectCommand  // clé = OS ("windows"|"linux")
	Normalizers map[string]assess.NormalizeFunc // clé = OS ; nil => Data déjà canonique
	Aggregate   assess.Aggregate                // nil => assess.WorstCase
	Questions   []survey.Question               // items de questionnaire (Doc et/ou Impl)
}

// declarative indique un contrôle organisationnel non scannable : il n'a pas
// d'évaluateur, sa maturité vient entièrement du questionnaire.
func (c Control) declarative() bool { return c.Evaluator == nil }

// Engine assemble les dépendances d'un run d'audit.
type Engine struct {
	Source   scan.Source
	Journal  audit.Journal
	Creds    map[string]*scope.Credential // clé = ScopedHost.CredRef
	Controls []Control                    // les contrôles à évaluer
	// DocScores = résultats du questionnaire (axe Documentation), injectés par
	// contrôle. Séparation stricte : pour les contrôles SCANNABLES, le scan
	// n'alimente que l'Implementation et le questionnaire alimente la
	// Documentation.
	DocScores map[string]cyfun.MaturityLevel
	// ImplScores = axe Implementation issu du questionnaire, utilisé UNIQUEMENT
	// par les contrôles DÉCLARATIFS (sans scan). Ignoré pour les scannables.
	ImplScores map[string]cyfun.MaturityLevel
	// Overrides = corrections consultant de l'axe Implementation, par contrôle.
	// Le score PROPOSÉ (scan/questionnaire) reste tracé dans ProposedImpl ; le
	// FINAL prend l'override, avec justification obligatoire — c'est ainsi qu'un
	// niveau 5 (non atteignable par le seul scan) peut être attesté sur PREUVE,
	// jamais forcé aveuglément. La traçabilité (ImplOverridden + OverrideReason)
	// est la garantie d'honnêteté de l'audit.
	Overrides map[string]Override
	// Capture, si non nil, reçoit la sortie BRUTE de chaque collecte réussie AVANT
	// normalisation — pour bâtir des fixtures golden en pilote sans travail manuel.
	// N'altère jamais l'audit (observateur passif).
	Capture CaptureFunc
}

// CaptureFunc reçoit une sortie brute de collecte (contrôle, hôte, OS, données).
type CaptureFunc func(controlID, hostID, osName string, raw []byte)

// Override = correction consultant d'un contrôle, assortie d'une justification
// (reprise au rapport comme preuve d'audit). Soit une correction du niveau
// d'Implementation, soit un marquage « non applicable » (NotApplicable).
type Override struct {
	Impl          cyfun.MaturityLevel
	Reason        string
	NotApplicable bool
}

// applyOverride applique l'override consultant s'il existe pour ce contrôle.
// Le ProposedImpl (valeur d'origine du scan) est toujours conservé.
func (e *Engine) applyOverride(r assess.ControlResult) assess.ControlResult {
	ov, ok := e.Overrides[r.Meta.ID]
	if !ok {
		return r
	}
	if ov.NotApplicable {
		// Non applicable attesté : on ne touche pas FinalImpl (ignoré au scoring),
		// on trace seulement le motif.
		r.NotApplicable = true
		r.OverrideReason = ov.Reason
		return r
	}
	r.FinalImpl = ov.Impl
	r.ImplOverridden = true
	r.OverrideReason = ov.Reason
	return r
}

// Run exécute l'audit sur le périmètre fourni et renvoie un ControlResult par
// contrôle. Un hôte injoignable ou une preuve absente n'interrompt pas le
// run : il est évalué comme NotAssessed et le trou de couverture est visible.
func (e *Engine) Run(ctx context.Context, sc scope.AuditScope) ([]assess.ControlResult, error) {
	results := make([]assess.ControlResult, 0, len(e.Controls))

	for _, ctrl := range e.Controls {
		// Contrôle déclaratif : aucun hôte interrogé, les deux axes viennent du
		// questionnaire. On produit un ControlResult sans volet technique.
		if ctrl.declarative() {
			results = append(results, e.applyOverride(assess.ControlResult{
				Meta:         ctrl.Meta,
				ProposedImpl: e.ImplScores[ctrl.Meta.ID],
				FinalImpl:    e.ImplScores[ctrl.Meta.ID],
				FinalDoc:     e.DocScores[ctrl.Meta.ID],
			}))
			continue
		}

		assessments := make([]assess.HostAssessment, 0, len(sc.Hosts))

		for _, host := range sc.Hosts {
			cmd, ok := ctrl.Commands[host.Ref.OS]
			if !ok {
				assessments = append(assessments, notApplicable(host.Ref, ctrl.Meta.ID))
				continue
			}

			cred := e.Creds[host.CredRef]
			raw, err := e.Source.Collect(ctx, host, cmd, cred, e.Journal)
			if err != nil {
				// Erreur de transport : on n'abandonne pas le parc, on marque
				// l'hôte comme non évalué via une preuve en erreur.
				raw = assess.RawEvidence{ControlID: ctrl.Meta.ID, Host: host.Ref, CollectErr: err.Error()}
			}
			// Détection de DROITS INSUFFISANTS : si la sortie de collecte révèle un
			// accès refusé, on en fait un trou de collecte EXPLICITE et qualifié —
			// SANS jamais tenter d'élever les privilèges (règle absolue du projet :
			// absence par conception). La couverture manquante se comble par un
			// compte de service au bon périmètre de lecture, pas par une escalade.
			if raw.CollectErr == "" {
				if reason := privilegeGap(raw.Data); reason != "" {
					raw.CollectErr = reason
				}
			}
			// Capture de la sortie BRUTE (avant normalisation) pour fixtures golden.
			if e.Capture != nil && raw.CollectErr == "" && len(raw.Data) > 0 {
				e.Capture(ctrl.Meta.ID, host.Ref.ID, host.Ref.OS, raw.Data)
			}
			// Normalisation brut → preuve canonique (si le contrôle en fournit
			// une pour cet OS). Une sortie illisible devient un trou de collecte.
			if norm := ctrl.Normalizers[host.Ref.OS]; norm != nil && raw.CollectErr == "" {
				canon, nerr := norm(raw.Data)
				if nerr != nil {
					raw.CollectErr = "normalisation : " + nerr.Error()
				} else {
					raw.Data = canon
				}
			}
			ha := ctrl.Evaluator.Evaluate(raw)
			// Le moteur journalise le RÉSULTAT d'évaluation (≠ succès de collecte).
			if e.Journal != nil {
				e.Journal.Result(host.Ref, ctrl.Meta.ID, representativeStatus(ha))
			}
			assessments = append(assessments, ha)
		}

		agg := ctrl.Aggregate
		if agg == nil {
			agg = assess.WorstCase
		}
		proposed, _ := agg(assessments)

		// DÉGRADATION GRACIEUSE : si le scan n'a rien pu constater sur AUCUN hôte
		// (OS non supporté, hôte injoignable, cmdlet indisponible…), l'Implementation
		// bascule sur l'attestation du questionnaire (question de repli) — JAMAIS un 0
		// imposé, qui déguiserait une limite d'outil en faille de sécurité. Le score
		// PROPOSÉ par le scan (NotAssessed) reste tracé ; ImplFromAttestation marque
		// la bascule. Si le questionnaire de repli n'est pas non plus rempli, le
		// contrôle reste non évalué et bloquera le verdict (session).
		finalImpl := proposed
		implFromAttestation := false
		if proposed == cyfun.NotAssessed {
			finalImpl = e.ImplScores[ctrl.Meta.ID]
			implFromAttestation = finalImpl != cyfun.NotAssessed
		}

		results = append(results, e.applyOverride(assess.ControlResult{
			Meta:            ctrl.Meta,
			HostAssessments: assessments,
			ProposedImpl:    proposed,
			// Par défaut le score final d'Implementation = proposition du scan ;
			// le consultant peut l'overrider (ImplOverridden), sur justification.
			FinalImpl:           finalImpl,
			FinalDoc:            e.DocScores[ctrl.Meta.ID],
			ImplFromAttestation: implFromAttestation,
		}))
	}
	return results, nil
}

// representativeStatus résume l'évaluation d'un hôte pour le journal : le
// premier constat fait foi (nos contrôles en produisent un par hôte).
func representativeStatus(ha assess.HostAssessment) assess.Status {
	if len(ha.Findings) > 0 {
		return ha.Findings[0].Status
	}
	return assess.StatusError
}

// gapInsufficientPrivileges est le préfixe stable des trous de collecte dus à un
// manque de droits (repéré par le rapport de couverture pour les distinguer d'un
// OS non supporté ou d'un hôte injoignable).
const gapInsufficientPrivileges = "droits insuffisants"

// privilegeGap détecte, dans une sortie de collecte, les marqueurs d'un accès
// REFUSÉ faute de droits (Windows « Access is denied », Linux « Permission
// denied », « must be root »…). Il ne fait que CONSTATER : jamais d'élévation
// automatique (règle de sécurité absolue). Renvoie le motif du trou, ou "".
func privilegeGap(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	low := strings.ToLower(string(data))
	markers := []string{
		"access is denied", "access denied", "permission denied",
		"requires elevation", "not authorized", "operation not permitted",
		"must be root", "are you root", "refusé", "permission non accordée",
	}
	for _, m := range markers {
		if strings.Contains(low, m) {
			return gapInsufficientPrivileges + " : lecture refusée — fournir un compte de service " +
				"read-only avec accès à cette ressource (aucune élévation automatique, par conception)"
		}
	}
	return ""
}

func notApplicable(host assess.HostRef, controlID string) assess.HostAssessment {
	return assess.HostAssessment{
		Host: host,
		Findings: []assess.Finding{{
			HostID:  host.ID,
			Status:  assess.StatusNA,
			Message: "Contrôle non applicable à l'OS " + host.OS,
		}},
		ProposedImplLevel: cyfun.NotAssessed,
		Rationale:         "Aucune commande de collecte pour cet OS.",
	}
}
