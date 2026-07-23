// Package store assure la persistance CÔTÉ CONSULTANT du suivi multi-clients
// dans le temps (historique des scores, progression, échéances CCB). Il repose
// sur SQLite via modernc.org/sqlite — un driver PUR GO (sans CGo), ce qui
// préserve la compilation en binaire statique unique.
//
// CONTRAINTE FORTE : cette base ne vit JAMAIS sur la clé USB bootable (qui est
// stateless). Elle réside sur le poste du consultant. On n'y enregistre QUE des
// données non sensibles — métadonnées d'audit et scores agrégés par contrôle.
// Aucun secret (les credentials ne sont de toute façon pas sérialisables),
// aucune preuve brute, aucune donnée personnelle superflue (RGPD, minimisation).
package store

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"

	"projetcyber/internal/cyfun"
	"projetcyber/internal/session"
)

// Store encapsule la base SQLite d'historique.
type Store struct {
	db *sql.DB
}

// Open ouvre (ou crée) la base au chemin donné et applique le schéma. Utiliser
// un chemin de fichier sur le poste consultant — jamais sur la clé USB.
func Open(ctx context.Context, dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("ouverture base : %w", err)
	}
	// SQLite n'aime pas les écritures concurrentes : une seule connexion évite
	// les « database is locked » sur ce petit usage mono-utilisateur.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close ferme la base.
func (s *Store) Close() error { return s.db.Close() }

// migrate crée les tables si elles n'existent pas. Idempotent.
func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS audits (
    id             TEXT PRIMARY KEY,
    client_ref     TEXT NOT NULL,
    level          TEXT NOT NULL,
    exported_at    INTEGER NOT NULL,   -- epoch (UTC)
    total_maturity REAL NOT NULL,
    conform        INTEGER NOT NULL     -- 0/1
);
CREATE INDEX IF NOT EXISTS idx_audits_client ON audits(client_ref, exported_at);

CREATE TABLE IF NOT EXISTS control_scores (
    audit_id    TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    control_id  TEXT NOT NULL,
    function    TEXT NOT NULL,
    key_measure INTEGER NOT NULL,   -- 0/1
    doc         INTEGER NOT NULL,
    impl        INTEGER NOT NULL,
    maturity    REAL NOT NULL,
    conform     INTEGER NOT NULL,   -- 0/1
    PRIMARY KEY (audit_id, control_id)
);`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migration schéma : %w", err)
	}
	return nil
}

// SaveSession enregistre une session d'audit et ses scores par contrôle, de
// façon transactionnelle (tout ou rien). Ré-enregistrer le même SessionID
// remplace l'entrée précédente (idempotent sur ré-export).
func (s *Store) SaveSession(ctx context.Context, sess session.AuditSession) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op après Commit

	// Remplace une éventuelle version antérieure du même audit. On supprime
	// explicitement les scores liés : SQLite n'applique pas ON DELETE CASCADE
	// tant que le PRAGMA foreign_keys n'est pas activé, donc on ne s'y fie pas.
	if _, err := tx.ExecContext(ctx, `DELETE FROM control_scores WHERE audit_id = ?`, sess.SessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM audits WHERE id = ?`, sess.SessionID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audits (id, client_ref, level, exported_at, total_maturity, conform)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sess.SessionID, sess.Scope.ClientRef, sess.Framework.Level,
		sess.ExportedAt.UTC().Unix(), float64(sess.Conformity.TotalMaturity), boolToInt(sess.Conformity.Conform),
	); err != nil {
		return fmt.Errorf("insertion audit : %w", err)
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO control_scores (audit_id, control_id, function, key_measure, doc, impl, maturity, conform)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range sess.Results {
		if _, err := stmt.ExecContext(ctx,
			sess.SessionID, r.Meta.ID, string(r.Meta.Function), boolToInt(r.Meta.KeyMeasure),
			int(r.FinalDoc), int(r.FinalImpl), float64(r.Maturity()), boolToInt(r.ConformBasic()),
		); err != nil {
			return fmt.Errorf("insertion score %s : %w", r.Meta.ID, err)
		}
	}
	return tx.Commit()
}

// AuditSummary = une ligne d'historique (sans le détail des contrôles).
type AuditSummary struct {
	SessionID     string
	ClientRef     string
	Level         string
	ExportedAt    int64 // epoch UTC
	TotalMaturity cyfun.MaturityScore
	Conform       bool
}

// History renvoie les audits d'un client, du plus ancien au plus récent (pour
// visualiser la progression dans le temps).
func (s *Store) History(ctx context.Context, clientRef string) ([]AuditSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_ref, level, exported_at, total_maturity, conform
		   FROM audits WHERE client_ref = ? ORDER BY exported_at ASC`, clientRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditSummary
	for rows.Next() {
		var a AuditSummary
		var total float64
		var conform int64
		if err := rows.Scan(&a.SessionID, &a.ClientRef, &a.Level, &a.ExportedAt, &total, &conform); err != nil {
			return nil, err
		}
		a.TotalMaturity = cyfun.MaturityScore(total)
		a.Conform = conform == 1
		out = append(out, a)
	}
	return out, rows.Err()
}

// Progression compare les deux derniers audits d'un client et renvoie le delta
// de maturité totale (récent - précédent) et un booléen indiquant s'il existe
// au moins deux audits à comparer.
func (s *Store) Progression(ctx context.Context, clientRef string) (delta cyfun.MaturityScore, comparable bool, err error) {
	h, err := s.History(ctx, clientRef)
	if err != nil {
		return 0, false, err
	}
	if len(h) < 2 {
		return 0, false, nil
	}
	last := h[len(h)-1]
	prev := h[len(h)-2]
	return last.TotalMaturity - prev.TotalMaturity, true, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
