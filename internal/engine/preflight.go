package engine

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

// Readiness = état d'ACCÈS d'un contrôle scannable sur un hôte, constaté par le
// preflight. Il répond à la seule question « le compte de service read-only fourni
// par le client peut-il LIRE ce dont ce contrôle a besoin ? » — pour provisionner
// le bon périmètre AVANT l'audit et rendre les runs suivants autonomes. Le
// preflight ne tente JAMAIS d'élever les privilèges (règle de sécurité absolue,
// absence par conception) : il CONSTATE, il ne s'arroge rien.
type Readiness string

const (
	ReadyOK          Readiness = "lisible"
	ReadyPrivilege   Readiness = "droits insuffisants"
	ReadyUnsupported Readiness = "OS non supporté"
	ReadyUnreachable Readiness = "injoignable"
	// ReadyUnreadable : la collecte a abouti mais sa sortie n'est pas une preuve
	// exploitable (le normaliseur du contrôle la rejette). Le scan de ce contrôle
	// basculerait sur l'attestation du questionnaire.
	ReadyUnreadable Readiness = "preuve illisible"
)

// PreflightRow = résultat du preflight pour un couple (hôte, contrôle scannable).
type PreflightRow struct {
	Host      string
	ControlID string
	Status    Readiness
	Detail    string
}

// readiness classe l'accès à partir du résultat de collecte. Fonction PURE,
// testable : elle ne déclenche aucune action, elle interprète.
func readiness(hasCmd bool, transportErr error, raw assess.RawEvidence) (Readiness, string) {
	if !hasCmd {
		return ReadyUnsupported, "aucune commande de collecte pour cet OS"
	}
	if transportErr != nil {
		return ReadyUnreachable, transportErr.Error()
	}
	// Accès refusé faute de droits : détecté dans la sortie OU le message d'erreur
	// de collecte, sans jamais tenter de le contourner par une élévation.
	if reason := privilegeGap([]byte(string(raw.Data) + " " + raw.CollectErr)); reason != "" {
		return ReadyPrivilege, reason
	}
	if raw.CollectErr != "" {
		return ReadyUnreachable, raw.CollectErr
	}
	if len(bytes.TrimSpace(raw.Data)) == 0 {
		return ReadyOK, "accès établi (sortie vide)"
	}
	return ReadyOK, "accès établi"
}

// Preflight teste, pour chaque contrôle SCANNABLE et chaque hôte, si le compte de
// service fourni peut lire la preuve — en lecture seule, sans aucune élévation.
// Il ne calcule AUCUN score : c'est une reconnaissance de périmètre de droits, à
// lancer une fois pour provisionner le compte, après quoi les audits sont autonomes.
func (e *Engine) Preflight(ctx context.Context, sc scope.AuditScope) []PreflightRow {
	var rows []PreflightRow
	for _, ctrl := range e.Controls {
		if len(ctrl.Commands) == 0 {
			continue // les contrôles déclaratifs n'exigent aucun droit de lecture
		}
		for _, host := range sc.Hosts {
			cmd, ok := ctrl.Commands[host.Ref.OS]
			var raw assess.RawEvidence
			var err error
			if ok {
				raw, err = e.Source.Collect(ctx, host, cmd, e.Creds[host.CredRef], e.Journal)
			}
			st, detail := readiness(ok, err, raw)
			// Lire n'est pas tout : la sortie doit aussi être une preuve que le
			// normaliseur du contrôle sait interpréter, sinon l'audit n'en tirera rien.
			if st == ReadyOK {
				if norm := ctrl.Normalizers[host.Ref.OS]; norm != nil {
					if _, nerr := norm(raw.Data); nerr != nil {
						st, detail = normalizeReadiness(nerr)
					}
				}
			}
			rows = append(rows, PreflightRow{Host: host.Ref.ID, ControlID: ctrl.Meta.ID, Status: st, Detail: detail})
		}
	}
	return rows
}

// normalizeReadiness classe un rejet du normaliseur : une sonde qui signale
// elle-même un manque de droits (« droits insuffisants ») relève du
// provisionnement ; tout autre rejet est une preuve illisible.
func normalizeReadiness(err error) (Readiness, string) {
	msg := err.Error()
	if strings.Contains(strings.ToLower(msg), gapInsufficientPrivileges) {
		return ReadyPrivilege, msg
	}
	return ReadyUnreadable, "normalisation : " + msg
}

// PreflightSummary = bilan du preflight. Sufficient n'est vrai que si au moins
// une collecte applicable a été testée et que TOUTES les collectes applicables
// sont lisibles et interprétables. « OS non supporté » ne compte pas comme un
// échec : c'est un contrôle qui ne s'applique pas à cette plateforme.
type PreflightSummary struct {
	Counts           map[Readiness]int
	Applicable       int      // lignes hors « OS non supporté »
	ProvisionHosts   []string // hôtes avec droits insuffisants (à provisionner côté client)
	UnreachableHosts []string // hôtes injoignables ou sans preuve
	UnreadableHosts  []string // hôtes dont une sortie n'est pas interprétable
	Sufficient       bool
	Verdict          string
}

// SummarizePreflight calcule le bilan du preflight. Fonction pure.
func SummarizePreflight(rows []PreflightRow) PreflightSummary {
	s := PreflightSummary{Counts: map[Readiness]int{}}
	for _, r := range rows {
		s.Counts[r.Status]++
		if r.Status != ReadyUnsupported {
			s.Applicable++
		}
	}
	s.ProvisionHosts = HostsNeedingProvisioning(rows)
	s.UnreachableHosts = hostsWithStatus(rows, ReadyUnreachable)
	s.UnreadableHosts = hostsWithStatus(rows, ReadyUnreadable)
	ok := s.Counts[ReadyOK]

	switch {
	case s.Applicable == 0:
		s.Verdict = "Aucune collecte applicable à ce périmètre : rien n'a pu être vérifié."
	case ok == 0:
		s.Verdict = fmt.Sprintf("Périmètre de droits NON vérifié : aucune des %d collectes applicables n'a abouti.", s.Applicable)
	case ok < s.Applicable:
		s.Verdict = fmt.Sprintf("Périmètre de droits incomplet : %d collectes lisibles sur %d applicables.", ok, s.Applicable)
	default:
		s.Sufficient = true
		s.Verdict = fmt.Sprintf("Périmètre de droits suffisant : %d collectes lisibles sur %d applicables ; les audits suivants seront autonomes.", ok, s.Applicable)
	}
	return s
}

// hostsWithStatus renvoie, sans doublon et triés, les hôtes ayant au moins une
// ligne dans l'état demandé.
func hostsWithStatus(rows []PreflightRow, st Readiness) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, r := range rows {
		if r.Status == st && !seen[r.Host] {
			seen[r.Host] = true
			hosts = append(hosts, r.Host)
		}
	}
	sort.Strings(hosts)
	return hosts
}

// HostsNeedingProvisioning renvoie, sans doublon et triés, les hôtes sur lesquels
// au moins un contrôle a rencontré un manque de droits : la liste à provisionner
// côté client (accès read-only), jamais à forcer côté outil.
func HostsNeedingProvisioning(rows []PreflightRow) []string {
	return hostsWithStatus(rows, ReadyPrivilege)
}
