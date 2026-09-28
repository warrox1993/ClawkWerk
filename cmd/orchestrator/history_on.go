//go:build history

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/warrox1993/clawkwerk/internal/session"
	"github.com/warrox1993/clawkwerk/internal/store"
)

// saveHistory — variante « poste consultant » (build `-tags history`).
//
// Enregistre la session dans la base SQLite d'historique (hors clé USB) et
// affiche la progression depuis l'audit précédent. C'est CETTE variante qui
// tire la dépendance modernc.org/sqlite ; elle est absente du binaire de la clé.
func saveHistory(dbPath string, sess session.AuditSession, clientRef string) error {
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.SaveSession(context.Background(), sess); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Audit enregistré dans l'historique %s\n", dbPath)
	if delta, comparable, err := st.Progression(context.Background(), clientRef); err == nil && comparable {
		fmt.Fprintf(os.Stderr, "Progression depuis l'audit précédent : %+.2f de maturité totale\n", float64(delta))
	}
	return nil
}
