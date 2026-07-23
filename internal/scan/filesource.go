package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"projetcyber/internal/assess"
	"projetcyber/internal/audit"
	"projetcyber/internal/scope"
)

// FileSource lit des preuves déjà collectées depuis un répertoire local :
// un fichier `<hostID>.<controlID>.json` par hôte et par contrôle. C'est une
// Source réelle et déterministe, utile pour le mode « script exécuté sur le
// poste puis sortie rapatriée », et idéale pour les tests (aucun réseau).
type FileSource struct {
	Dir string
	now func() time.Time // injectable pour les tests
}

// NewFileSource crée une FileSource horodatée par l'horloge système.
func NewFileSource(dir string) *FileSource {
	return &FileSource{Dir: dir, now: time.Now}
}

func (s *FileSource) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Collect lit le fichier de preuve de l'hôte pour le contrôle demandé. Une
// preuve absente ou illisible n'est PAS une erreur fatale : elle est reportée
// dans RawEvidence.CollectErr pour que le pipeline continue et que le rapport
// signale le trou de couverture.
func (s *FileSource) Collect(ctx context.Context, host scope.ScopedHost, cmd CollectCommand, cred *scope.Credential, j audit.Journal) (assess.RawEvidence, error) {
	if j == nil {
		return assess.RawEvidence{}, errors.New("scan: journal requis (collecte non journalisée interdite)")
	}
	if !cmd.IsReadOnly() {
		return assess.RawEvidence{}, fmt.Errorf("scan: commande non lecture seule refusée pour %s", cmd.ControlID)
	}

	user := ""
	if cred != nil {
		user = cred.Username
	}
	j.Connection(host.Ref, host.Transport, user)
	j.Command(host.Ref, cmd.ControlID, cmd.Script)

	ev := assess.RawEvidence{
		ControlID:   cmd.ControlID,
		Host:        host.Ref,
		Source:      "file",
		CollectedAt: s.clock(),
	}

	// La Source journalise ses ACTIONS (connexion, commande). Le RÉSULTAT
	// d'évaluation (conformité) est journalisé par le moteur, après analyse —
	// pour ne pas confondre « collecte réussie » et « contrôle conforme ».
	path := filepath.Join(s.Dir, fmt.Sprintf("%s.%s.json", host.Ref.ID, cmd.ControlID))
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		ev.CollectErr = fmt.Sprintf("preuve absente (%s)", path)
	case err != nil:
		ev.CollectErr = "lecture preuve : " + err.Error()
	default:
		ev.Data = data
	}
	return ev, nil
}
