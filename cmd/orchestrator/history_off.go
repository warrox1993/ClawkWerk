//go:build !history

package main

import (
	"errors"

	"projetcyber/internal/session"
)

// saveHistory — variante par DÉFAUT (binaire de la clé bootable).
//
// L'historique consultant (SQLite) NE VIT JAMAIS sur la clé USB (contrainte
// stateless). On ne l'embarque donc pas dans le binaire par défaut : celui-ci
// reste INDÉPENDANT de modernc.org/sqlite (moteur volumineux inutile sur la
// clé). Pour activer le suivi historique côté poste consultant, recompiler
// avec `go build -tags history`.
func saveHistory(_ string, _ session.AuditSession, _ string) error {
	return errors.New("support historique non compilé dans ce binaire (recompiler avec : go build -tags history)")
}
