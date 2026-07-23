# Journal de développement — projetCyber

Outil d'audit + remédiation cybersécurité pour PME belges, basé sur le
référentiel officiel **CyFun 2025** (CCB), aligné NIST CSF 2.0 / NIS2.
Positionnement : **préparateur à la conformité**, jamais organisme de
certification. Écrit en **Go**, livré en **binaire statique unique CGo-free**,
destiné à une clé USB bootable stateless.

## État actuel

- **Référentiel complet, 3 niveaux** : Basic (34 contrôles), Important (133),
  Essential (218). Textes officiels du CCB ; seuils officiels **non uniformes**
  (Basic KM/total 2,5 ; Important 3/3 ; Essential KM 3 / catégorie 3 / total 3,5).
- **Scoring** : Documentation (questionnaire) + Implementation (scan) par
  contrôle, moyenne = maturité. **Agrégation HIÉRARCHIQUE identique au barème
  officiel CCB** (requirement → sous-catégorie → catégorie → total, moyenne de
  moyennes ; Doc/Impl combinés au niveau catégorie), reproduite depuis les
  formules Excel du xlsx, **y compris le traitement du « N/A »** (substitution
  par le seuil, comme la CCB). Override consultant tracé (proposé vs final +
  justification, ou marquage « non applicable ») — seul chemin honnête vers un
  5/5. **Aucune falsification.** Parité de calcul CCB : **contrôles + Key
  Measures + seuils + agrégation + N/A = identiques** ; en plus = le scan.
- **7 contrôles scannables** (antivirus, pare-feu, correctifs, journalisation,
  comptes admin, + réseau) ; le reste déclaratif (questionnaire).
- **Framework réseau** : 3 contrôles (pare-feu PR.IR-01.1, segmentation
  PR.IR-01.2, journalisation PR.PS-04.1) × ~10 marques (RouterOS, pfSense,
  FortiOS, Cisco, PAN-OS, SonicWall, WatchGuard, Zyxel, Sophos, UniFi).
- **Transports** : File (dev), SSH, WinRM, API (UniFi/Sophos) — tous lecture
  seule, journal requis, credentials en RAM jamais sérialisés.
- **Sondes endpoint multi-distro** : ufw/firewalld/nftables, apt/dnf/zypper.
- **Rapports** : JSON, HTML (6 sections + objectif 5/5), XLSX, PDF.
- **Historique consultant** SQLite (hors clé USB).
- **Live-boot** : recette Debian live-build (`live/`, boot toram stateless).

## Garanties de sécurité (prouvées par des tests, pas seulement affirmées)

- **Lecture seule** : toutes les commandes du registre sont `IsReadOnly` (test) ;
  aucune primitive d'écriture/élévation/mouvement latéral n'existe.
- **Remédiation JAMAIS auto-exécutée** : générée pour validation humaine.
- **Secret jamais sérialisé** (champ non exporté, test à canari).
- **Journal d'audit infalsifiable** : chaîne de hachage SHA-256, `audit.Verify`
  détecte toute modification/réordonnancement/suppression.
- **Périmètre = input explicite** : aucune découverte réseau autonome.

## Qualité

- **155 fonctions de test + fuzz**, 12 paquets, tout vert.
- Fuzzing des normaliseurs (aucune panique sur entrée arbitraire).
- Tests de propriété (monotonie du scoring) + goldens (non-régression du verdict).
- `gofmt`, `go vet`, `staticcheck` : 0 signalement. `govulncheck` : 0 vuln.
- **Build reproductible** (SHA-256 identique) et statique (`CGO_ENABLED=0`).
- CI (`.github/workflows/ci.yml`) + `Makefile`.

## Indépendance / build

- **Runtime** : binaire **statique CGo-free** — aucune dépendance dynamique
  (« not a dynamic executable »). Tourne seul, hors-ligne, stateless.
- **Deux profils de build** :
  - *appliance* (défaut, `make build`) : binaire de la clé, **INDÉPENDANT de
    SQLite** (l'historique ne vit jamais sur la clé) — ~16 Mo.
  - *consultant* (`make build-consultant`, `-tags history`) : ajoute le suivi
    SQLite hors clé — ~22 Mo.
- Le découplage via *build tag* garde le binaire de la clé lean et sans le
  moteur DB `modernc.org/sqlite` (129 Mo de source) qu'il n'utilise jamais.

## Dépendances (toutes pur-Go, binaire statique préservé)

`golang.org/x/crypto/ssh`, `github.com/go-pdf/fpdf`, `github.com/masterzen/winrm`
(appliance) ; `modernc.org/sqlite` uniquement en build `-tags history`.
Règle : jamais de CGo (jamais `mattn/go-sqlite3`).

## Utilisation

```sh
# audit local (preuves de démo), niveau Basic, tous les rapports
go run ./cmd/orchestrator -level basic -html r.html -xlsx r.xlsx -pdf r.pdf -history suivi.db

# audit distant réel (SSH/WinRM/API)
go run ./cmd/orchestrator -transport remote -creds creds.json -known-hosts ~/.ssh/known_hosts -level important

# matrice de couverture (statut honnête par marque réseau)
go run ./cmd/orchestrator -coverage

# questionnaire web local
go run ./cmd/questionnaire    # http://127.0.0.1:8099
```

Cibles `make check` (fmt, vet, staticcheck, test, vuln, verify) et `make build`.

## Limites connues / à faire (honnête)

- **Validation matérielle** : TOUS les adaptateurs réseau sont « d'après-doc »,
  écrits depuis la documentation constructeur, **non testés sur équipement
  réel**. Le fuzzing garantit l'absence de crash, pas la justesse des commandes.
  La matrice `-coverage` dit toujours la vérité sur ce statut.
- **Firmware réseau** : « à jour ? » indéductible hors-ligne (pas de base
  « dernière version ») → à traiter en collecte de version + jugement consultant.
- **Live-boot** : recette non booté-testée (produire l'ISO sur machine Debian).

## Journal des sessions

1. Brainstorming + archi (3 coutures Source→Evaluator→Aggregate) + PoC DE.CM-01.2.
2. Pipeline complet, session JSON, conformité Basic.
3. Questionnaire déclaratif, 34 contrôles, rapport HTML/XLSX/PDF, SQLite, SSH/WinRM.
4. Couche de normalisation brut→preuve ; référentiel Basic complet.
5. Transport SSH/WinRM câblé dans l'orchestrateur.
6. Framework réseau (pare-feu) + 10 adaptateurs constructeur.
7. Multi-distro endpoint + live-boot.
8. Scoring 5/5 honnête (override tracé) + objectif excellence au rapport.
9. Journalisation réseau + niveau IMPORTANT (level-aware).
10. Transport API (Sophos/UniFi).
11. Renforcement : fuzzing, journal infalsifiable, garanties sécurité prouvées.
12. Golden/property tests du scoring + chaîne de confiance (CI, build reproductible).
13. Niveau Essential + correction des seuils non uniformes (KM/catégorie/total).
