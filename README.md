# projetCyber

Outil d'audit et de remédiation cybersécurité pour PME belges, basé sur le
référentiel officiel **CyFun 2025** (CCB), niveau **Basic**.

> Auto-évaluation assistée — **ne constitue pas** une certification officielle
> CyFun (réservée aux CAB accrédités BELAC). Voir `CLAUDE.md` pour le contexte
> complet, le positionnement légal et le barème officiel.

## État (PoC)

Moteur de scan + scoring pour le contrôle **DE.CM-01.2** (« Anti-virus,
-spyware, and other -malware programs shall be installed and updated »),
conçu comme patron réutilisable pour les 33 autres contrôles Basic.

## Lancer la démo de bout en bout

```bash
# Depuis la racine du projet
go run ./cmd/orchestrator -evidence ./sample/evidence            # JSON sur stdout
go run ./cmd/orchestrator -evidence ./sample/evidence -out rapport.json
```

La sortie est un rapport JSON (`AuditSession`) : périmètre, résultats par hôte,
journal d'audit, et verdict de conformité Basic.

## Tests

```bash
go test ./...          # 22 tests, 7 paquets
go vet ./... && gofmt -l .
```

## Architecture

Trois coutures réutilisables, du pur/testable vers l'I/O :

```
scope ─┐
        ├─► engine ──► [ Source.Collect → Evaluator.Evaluate → Aggregate ] ──► session (JSON)
audit ─┘                (I/O, read-only)   (fonction pure)      (multi-hôtes)
```

| Paquet | Rôle |
|--------|------|
| `internal/cyfun`          | Référentiel : types, barème officiel 1-5, seuils Basic (≥ 2,5) |
| `internal/cyfun/controls` | Un évaluateur (fonction pure) par contrôle — ici DE.CM-01.2 |
| `internal/scope`          | Périmètre explicite + credentials (secret non sérialisable) |
| `internal/audit`          | Journal inaltérable, non désactivable |
| `internal/scan`           | `Source` lecture seule + `FileSource` (testable) + `RemoteSource` (WinRM/SSH, à implémenter) |
| `internal/engine`         | Orchestration + registre des contrôles |
| `internal/session`        | Calcul de conformité + enveloppe JSON de sortie |
| `cmd/orchestrator`        | Câblage exécutable |

## Invariants de sécurité (portés par le code)

- **Aucune découverte réseau** : les hôtes ne viennent que d'un `AuditScope` fourni.
- **Secrets jamais sérialisés** : champ `secret` non exporté → invisible en JSON.
- **Journal obligatoire** : paramètre requis de `Source.Collect`, pas d'option pour l'éteindre.
- **Lecture seule** : `CollectCommand` ne peut être créée qu'en read-only ; aucune
  primitive d'écriture, d'élévation ou de mouvement latéral n'existe.
- **Remédiation** : jamais auto-exécutée (générée pour validation humaine — hors PoC).
