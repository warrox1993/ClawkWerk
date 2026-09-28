package scan

import (
	"context"
	"errors"
	"fmt"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/audit"
	"github.com/warrox1993/clawkwerk/internal/scope"
)

// RemoteSource est la Source d'accès distant sans agent. Elle ne parle aucun
// protocole elle-même : elle AIGUILLE chaque hôte vers le transport adapté à
// son mode d'accès (SSH pour Linux, WinRM pour Windows). Les garde-fous
// (périmètre fourni, credentials read-only jamais sérialisés, journal requis,
// commande read-only) sont portés par les couches sous-jacentes et par les
// types partagés — aucune primitive d'écriture/élévation/mouvement latéral
// n'existe ici, par conception.
type RemoteSource struct {
	SSH   *SSHSource   // transport SSH (Linux). nil => SSH indisponible.
	WinRM *WinRMSource // transport WinRM (Windows). nil => WinRM indisponible.
	API   *APISource   // transport API (Sophos, UniFi…). nil => API indisponible.
}

// ErrWinRMNotImplemented signale que le transport Windows reste à écrire.
var ErrWinRMNotImplemented = errors.New("scan: transport WinRM (Windows) non implémenté")

// ErrTransportUnavailable signale un transport non configuré sur ce RemoteSource.
var ErrTransportUnavailable = errors.New("scan: transport non configuré")

func (r RemoteSource) Collect(ctx context.Context, host scope.ScopedHost, cmd CollectCommand, cred *scope.Credential, j audit.Journal) (assess.RawEvidence, error) {
	switch host.Transport {
	case scope.SSH:
		if r.SSH == nil {
			return assess.RawEvidence{}, fmt.Errorf("%w : ssh", ErrTransportUnavailable)
		}
		return r.SSH.Collect(ctx, host, cmd, cred, j)
	case scope.WinRM:
		if r.WinRM != nil {
			return r.WinRM.Collect(ctx, host, cmd, cred, j)
		}
		// Transport Windows non configuré sur ce RemoteSource : on le signale
		// comme trou de collecte (non fatal) pour que le pipeline continue et que
		// le rapport montre la couverture réelle.
		if j != nil {
			j.Connection(host.Ref, host.Transport, credUser(cred))
		}
		return assess.RawEvidence{
			ControlID:  cmd.ControlID,
			Host:       host.Ref,
			Source:     "winrm",
			CollectErr: ErrWinRMNotImplemented.Error(),
		}, nil
	case scope.API:
		if r.API == nil {
			return assess.RawEvidence{}, fmt.Errorf("%w : api", ErrTransportUnavailable)
		}
		return r.API.Collect(ctx, host, cmd, cred, j)
	default:
		return assess.RawEvidence{}, fmt.Errorf("%w : %q", ErrTransportUnavailable, host.Transport)
	}
}

func credUser(cred *scope.Credential) string {
	if cred == nil {
		return ""
	}
	return cred.Username
}
