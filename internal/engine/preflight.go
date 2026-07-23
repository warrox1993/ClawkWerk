package engine

import (
	"bytes"
	"context"
	"sort"

	"projetcyber/internal/assess"
	"projetcyber/internal/scope"
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
			rows = append(rows, PreflightRow{Host: host.Ref.ID, ControlID: ctrl.Meta.ID, Status: st, Detail: detail})
		}
	}
	return rows
}

// HostsNeedingProvisioning renvoie, sans doublon et triés, les hôtes sur lesquels
// au moins un contrôle a rencontré un manque de droits : la liste à provisionner
// côté client (accès read-only), jamais à forcer côté outil.
func HostsNeedingProvisioning(rows []PreflightRow) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, r := range rows {
		if r.Status == ReadyPrivilege && !seen[r.Host] {
			seen[r.Host] = true
			hosts = append(hosts, r.Host)
		}
	}
	sort.Strings(hosts)
	return hosts
}
