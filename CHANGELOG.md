# Journal des modifications

Format inspiré de « Keep a Changelog ». Les chiffres sont mesurés sur le code
de la version concernée.

## [1.0.0] - 2026-09-28

Première version publiée avec intégration continue et binaires.

### Ajouté

- Drapeau `-scope` : le périmètre d'audit (client, machines, OS, transport,
  port, compte de service) est lu depuis un fichier JSON validé strictement
  (champs inconnus, doublons, plages réseau et plateformes inconnues
  refusés). Exemple fourni : `sample/scope.json`. L'identifiant de session est
  horodaté (`<client>-AAAAMMJJ-HHMMSS`).
- Mode remote : `-creds` obligatoire et vérifié contre chaque `cred_ref` du
  périmètre avant toute connexion.
- Questionnaire web : drapeau `-level basic|important|essential` (71, 269 ou
  439 questions), jeton anti-CSRF, contrôle des en-têtes Origin et Host,
  en-têtes anti-clickjacking, écriture des réponses uniquement après une
  soumission acceptée.
- Démo complète : preuves pour les 16 contrôles scannables Basic sur deux
  machines Windows, une machine Linux (sorties réelles capturées sur un
  conteneur Debian) et un pare-feu MikroTik ; questionnaire rempli pour les
  trois niveaux. Le verdict est complet à chaque niveau.
- Support d'iptables dans la sonde pare-feu Linux ; détection des
  anti-malwares tiers courants dans la sonde antivirus Linux.
- Intégration continue (`.github/workflows/ci.yml`) : gofmt, go mod verify,
  go vet, staticcheck, tests `-race` avec et sans `-tags history`,
  govulncheck, build statique et reproductible, démo de bout en bout.
- Publication (`.github/workflows/release.yml`) : sur un tag `v*`, binaires
  statiques Linux et Windows amd64 (orchestrateur, orchestrateur consultant,
  questionnaire) et fichier `SHA256SUMS`.
- README orienté présentation, captures du rapport et du questionnaire.

### Corrigé

- PR.AA-05.3 sur Linux : `grep -c` sortait avec le code 1 quand aucun
  protocole legacy n'écoutait, et une machine saine était classée « collecte
  échouée ». Sans `ss`, la sonde échoue désormais explicitement.
- DE.CM-01.1 sur Linux : une machine sans aucun pare-feu était classée
  « collecte échouée » ; c'est maintenant une non-conformité (niveau 1). Un
  pare-feu présent mais illisible pour le compte de service devient un trou
  de collecte « droits insuffisants ».
- DE.CM-01.2 sur Linux (Key Measure) : même défaut de code de sortie sans
  ClamAV, et une unité systemd inconnue passait pour ClamAV installé.
- ID.AM-01.x (inventaire matériel) : même défaut de `grep -c` ; échec
  explicite si ni `lspci` ni `lsusb` n'est installé.
- PR.DS-11.1 : le minuteur système `dpkg-db-backup` n'est plus pris pour une
  sauvegarde des données.
- Les sondes concernées complètent PATH avec `/usr/sbin` et `/sbin`, absents
  du PATH d'un compte de service non root sur Debian.
- Preflight : « Périmètre de droits suffisant » s'affichait même quand toutes
  les collectes échouaient. Le verdict n'est désormais suffisant que si toutes
  les collectes applicables sont lisibles, et le preflight vérifie aussi que
  la sortie est interprétable.

### Sécurité

- Go 1.26.4 vers 1.26.8, `golang.org/x/crypto` 0.53.0 vers 0.57.0,
  `github.com/Azure/go-ntlmssp` vers 0.1.1 : govulncheck passe de 10
  vulnérabilités atteignables à 0.

### Modifié

- Module Go renommé `github.com/warrox1993/clawkwerk` ; recette live-boot
  renommée (`/opt/clawkwerk`, service `clawkwerk-questionnaire`).
- Outils d'analyse épinglés dans le Makefile (staticcheck 2026.2.1,
  govulncheck 1.8.0) ; `make check` inclut les tests `-tags history`.
- Documentation : README et CHANGELOG réécrits (l'ancienne version annonçait
  une CI inexistante, 7 contrôles scannables et 155 tests) ; source publique
  du référentiel citée ; documents de conception regroupés dans
  `docs/methode`.

### Mesures

- 371 tests et 282 sous-tests, verts avec et sans `-tags history` et sous
  `-race` (version initiale : 339 et 238).
- 200 fichiers Go, 22 750 lignes dont 8 612 de tests.

## [0.1.0] - 2026-07-23

Publication initiale du code (commit `29f6411`), sans intégration continue.

- Référentiel CyFun 2025 complet : Basic (34 exigences, 13 Key Measures),
  Important (133, 22), Essential (218, 29), avec les seuils officiels et
  l'agrégation hiérarchique de l'outil Excel du CCB, traitement des « non
  applicable » compris.
- 16 contrôles scannables au niveau Basic, 66 au niveau Essential ; sondes
  Windows et Linux multi-distributions ; 10 familles d'équipements réseau
  écrites d'après la documentation ; Microsoft 365 en lecture via Graph.
- Transports fichier, SSH (clé d'hôte obligatoire), WinRM et API.
- Journal d'audit chaîné par SHA-256, secrets non sérialisables, test de
  lecture seule sur toutes les commandes, dégradation vers le questionnaire
  quand un scan est impossible, verdict bloqué tant qu'un contrôle reste non
  évalué, mode `-preflight` sans élévation.
- Rapports JSON, HTML, XLSX et PDF ; historique SQLite hors clé (build
  `-tags history`) ; recette de clé USB live (jamais démarrée).
- 339 tests et 238 sous-tests.

### Étapes de développement

1. Architecture en trois coutures (collecte, évaluation, agrégation) et
   preuve de concept sur DE.CM-01.2.
2. Pipeline complet, session JSON, conformité Basic.
3. Questionnaire déclaratif, 34 contrôles, rapports HTML, XLSX et PDF,
   SQLite, SSH et WinRM.
4. Couche de normalisation (sortie brute vers preuve) ; référentiel Basic
   complet.
5. Transports distants câblés dans l'orchestrateur.
6. Adaptateurs de pare-feu réseau pour dix familles d'équipements.
7. Sondes Linux multi-distributions et recette live-boot.
8. Note 5/5 réservée à une correction consultant justifiée et tracée.
9. Journalisation réseau et niveau Important.
10. Transport API (Sophos, UniFi).
11. Fuzzing, journal chaîné, garanties de sécurité prouvées par des tests.
12. Tests de propriété et verdicts de référence, build reproductible.
13. Niveau Essential et seuils non uniformes (Key Measure, catégorie, total).
