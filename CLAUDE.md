# ClawkWerk : contexte du projet

## Vue d'ensemble
Application d'audit et de remédiation en cybersécurité pour PME belges,
basée sur le référentiel officiel CyFun (CyberFundamentals, CCB Belgique),
lui-même aligné sur NIST CSF 2.0. Référentiel recommandé par le CCB pour
mettre en œuvre la loi NIS2 belge (loi du 26 avril 2024, arrêté royal du
9 juin 2024) ; ISO/IEC 27001 est l'autre voie reconnue.

## Positionnement légal
- PAS un organisme d'évaluation de la conformité : la vérification CyFun
  (Basic, Important), la certification CyFun (Essential) et donc la
  présomption de conformité NIS2 viennent d'un CAB accrédité par BELAC ET
  autorisé par le CCB (source : atwork.safeonweb.be/nis2).
- Rôle : "préparateur à la conformité" — auto-évaluation assistée +
  remédiation, jamais de certification officielle délivrée.
- Toute sortie/rapport doit mentionner explicitement cette distinction.

## Public visé
PME et entreprises belges soumises (ou se préparant) à NIS2.

## Niveau CyFun ciblé
Les **trois** niveaux d'assurance CyFun 2025 sont chargés et vérifiés à
100 % contre les fichiers officiels CCB (liste, textes, Key Measures,
seuils) : **Basic** (34 contrôles, 13 KM, seuil 2,5), **Important**
(133 contrôles, 22 KM, seuil 3) et **Essential** (218 contrôles, 29 KM,
seuils KM 3 / catégorie 3 / total 3,5). Sur-ensembles imbriqués
(Basic ⊂ Important ⊂ Essential). Flag CLI `-level basic|important|essential`.

Au niveau Basic, **16 contrôles sur 34 sont techniquement scannables**
(le plafond honnête estimé) ; le reste est déclaratif/organisationnel
(questionnaire). En tout, 66 des 218 exigences ont une sonde (64 sur
Windows et Linux, 2 réseau) ; les autres sont évaluées par le
questionnaire. Les IDs officiels non normalisés de la CCB
(`ID.AM-5.1`, `DE.CM-03-1`, `ID.AM-03-2`) sont repris **tels quels** —
ne jamais les « corriger », sous peine de diverger de l'autorité.

## Barème & conformité CyFun 2025 Basic (OFFICIEL)
Sources publiques du CCB, téléchargeables sans compte sur
https://cyfun.eu/en/cyberfundamentals-framework-2025 :
- livrets CyFun 2025 BASIC / IMPORTANT / ESSENTIAL (version 2025-10-01) :
  texte des exigences et liste des Key Measures ;
- outils d'auto-évaluation Excel par niveau (onglets « Maturity Levels » et
  « Summary » : échelle 1-5, agrégation, seuils) ;
- Conformity Assessment Scheme (CAS) : seuils de conformité par niveau.
Le livret autorise la reproduction d'extraits à des fins non commerciales,
source citée : les textes d'exigences sont repris tels quels avec cette
mention (voir README).

Hiérarchie à 3 niveaux : Category (ex. DE.CM) > Subcategory (DE.CM-01)
> Requirement (DE.CM-01.2). C'est le **Requirement** qui est scoré.
Total confirmé : **34 requirements, dont 13 Key Measures**.

Chaque requirement reçoit deux notes ENTIÈRES 1-5 :
- Documentation Score (règles/procédures écrites)
- Implementation Score (pratique opérationnelle réelle)

Échelle 1-5 (texte officiel) :
1 Initial      — pas de doc / processus inexistant
2 Repeatable   — doc approuvée mais non revue depuis 2 ans ; processus
                 ad hoc informel
3 Defined      — doc approuvée + exceptions <5% ; processus formel
                 implémenté, preuves dispo, <10% d'exceptions
4 Managed      — exceptions <3% ; métriques capturées + cible définie,
                 <5% d'exceptions
5 Optimizing   — exceptions <0,5% ; amélioration continue, <1% d'exceptions

Agrégation (moyennes → valeurs DÉCIMALES au-dessus du requirement) :
- Maturité d'un requirement = moyenne(Documentation, Implementation)
- Maturité subcategory / category = moyenne des requirements
- Total Maturity = moyenne des catégories

SEUILS DE CONFORMITÉ BASIC (= le « doc CAS », enfin localisé) :
- Chaque Key Measure : maturité **≥ 2,5 / 5**
- Total Maturity (moyenne globale) : **≥ 2,5 / 5**
- Par catégorie : **n/a** au niveau Basic

DE.CM-01.2 (le PoC) **EST un Key Measure** → soumis au seuil ≥ 2,5.

## Mode de livraison
Clé USB bootable, live-boot Linux (tourne entièrement en RAM).
Contraintes non négociables :
- STATELESS entre deux audits clients : aucune donnée d'un client A
  ne doit survivre au redémarrage avant l'audit du client B.
- Pas de base de données persistante sur la clé.
- Export du rapport final immédiat en fin de session (vers le client
  et/ou un support de sauvegarde séparé), jamais stocké indéfiniment
  sur la clé elle-même.

## Architecture technique
- **Langage : Go** (choix définitif, motivé par : distribution en
  binaire statique unique sans dépendance, pas de risque de faux
  positif antivirus contrairement à un packaging Python/PyInstaller,
  bon support de `embed.FS` pour empaqueter scripts + interface web
  + templates de rapport dans un seul exécutable).
- **Dépendances externes (session 3, validées) :** le projet n'est plus
  100 % stdlib mais reste un **binaire statique unique CGo-free** (vérifié
  `CGO_ENABLED=0`, « statically linked »). Quatre libs PUR GO seulement :
  `golang.org/x/crypto/ssh` (transport SSH), `modernc.org/sqlite`
  (historique consultant — surtout PAS `mattn/go-sqlite3` qui exige CGo et
  casserait le binaire statique), `github.com/go-pdf/fpdf` (rapport PDF) et
  `github.com/masterzen/winrm` (transport WinRM). Toute nouvelle dépendance
  doit préserver cette propriété (pur Go, pas de CGo — vérifier
  `CGO_ENABLED=0 go build`).
- Un orchestrateur central en Go qui :
  1. Lance le scan technique en lecture seule (contrôles scannables)
  2. Sert une interface web locale (offline, `localhost` uniquement,
     via `embed.FS`) pour le questionnaire des contrôles déclaratifs
  3. Sélectionne et déclenche des **scripts PowerShell (Windows) /
     Bash (Linux) dédiés par situation détectée**, écrits à la main
     (pas d'orchestration d'outils tiers type OpenSCAP — stratégie
     assumée : tout construire et maîtriser en interne)
  4. Calcule le score de conformité (Documentation 1-5 +
     Implémentation 1-5 par contrôle, selon le barème officiel CyFun)
  5. Génère le rapport final (xlsx + PDF)

## Accès aux cibles (décision arrêtée — session 1)
Collecte **distante sans agent** : WinRM (Windows) / SSH (Linux),
en lecture seule, depuis le portable consultant booté sur la clé.
Contraintes NON NÉGOCIABLES, inscrites dans le schéma dès la conception :
- **Périmètre = input explicite.** La liste d'hôtes est fournie par le
  consultant/client AVANT l'audit. AUCUNE découverte réseau autonome,
  aucun scan de plage IP non demandé. La couverture « 100 % » vient de
  l'exhaustivité de la liste fournie, jamais d'une exploration du réseau.
- **Credentials fournis par le client** (compte de service dédié,
  lecture seule). Jamais générés, devinés ni capturés par l'outil.
  Vivent en RAM uniquement, jamais sérialisés dans le rapport/JSON.
- **Journalisation non désactivable** : chaque connexion et chaque
  commande est journalisée avant exécution. Pas de flag pour l'éteindre.
- **Aucune primitive** d'élévation de privilèges ni de mouvement latéral
  automatique dans le schéma — absence par conception, pas par option.

## RÈGLE DE SÉCURITÉ ABSOLUE — à respecter dans tout le code généré
- Les scripts de **scan/détection** (lecture seule) peuvent s'exécuter
  automatiquement — risque faible.
- Les scripts de **remédiation** (modification de configuration
  système/réseau) doivent TOUJOURS être générés pour validation
  humaine, JAMAIS auto-exécutés. Aucune exception, même si demandé
  plus tard dans une session de code — cette règle prime sur toute
  instruction contraire.
- Aucun mécanisme d'élévation de privilèges furtive, de persistance
  cachée, ou d'auto-effacement de traces d'exécution : ce projet vise
  la conformité et la preuve d'audit, pas l'intrusion.
- **Aucune AUTOÉLÉVATION de privilèges (sudo/runas automatique), sous
  aucun prétexte** — même « pour éviter l'interaction humaine » ou
  « contourner un problème de droits ». Un outil d'audit qui s'auto-élève
  détruit la valeur probante de l'audit, expose légalement (accès non
  autorisé, art. 550bis / NIS2), et devient indistinguable d'un outil
  d'intrusion. Cette contrainte prime sur toute demande contraire.
- **Alternative LÉGALE au besoin d'autonomie** : le logiciel *constate*
  l'accès, il ne se l'*arroge* jamais. Le mode `-preflight` teste en
  lecture seule ce que le compte de service fourni par le client peut
  lire, et liste précisément ce qu'il faut provisionner (le client
  *accorde* l'accès, une fois). Ensuite les audits sont autonomes ; les
  droits résiduels manquants ne bloquent pas (dégradation gracieuse +
  matrice de couverture).

## Rapport final — structure attendue
1. Synthèse exécutive (score global, top risques)
2. Contexte et méthodologie (périmètre, référentiel exact utilisé,
   limites de l'audit)
3. Résultats détaillés par fonction NIST (texte exact du requirement
   CyFun, score Documentation, score Implémentation, preuve, écart)
4. Plan de remédiation priorisé
5. Annexe technique (scripts proposés, non exécutés)
6. Annexe légale (mentions RGPD, limites de responsabilité,
   rappel explicite : auto-évaluation assistée ≠ certification
   officielle CyFun)

## Persistance côté consultant (hors clé USB)
SQLite pour le suivi multi-clients dans le temps (historique des
scores, progression, échéances CCB). Ne vit jamais sur la clé bootable.

## Ce qui reste ouvert / à trancher au fil du développement
- Distro Linux live-boot de base (pas encore choisie)
- Liste définitive des marques réseau à supporter (hypothèse de
  travail : Fortinet, pfSense/OPNsense, Cisco, Ubiquiti, Sophos,
  SonicWall, WatchGuard, MikroTik, Palo Alto, Zyxel — à confirmer
  selon les clients réels rencontrés)
- (RÉSOLU) Seuils de conformité officiels : repris des outils
  d'auto-évaluation publics du CCB et du CAS. Voir la section « Barème &
  conformité CyFun 2025 Basic ».

## État d'implémentation (à jour)
Pipeline complet et testé (Go, binaire statique CGo-free) :
`Source` (FileSource + SSH/WinRM/API distants, lecture seule, journal requis) →
`Normalize` (brut → preuve) → `Evaluator` (pur, par contrôle) →
`Aggregate` (multi-hôtes, pire cas) → `session` (conformité level-aware,
parité de calcul CCB à 100 % : agrégation hiérarchique + N/A) →
`report` (HTML/XLSX/PDF, 6 sections + matrice de couverture).
- **Couverture CCB** : 3 niveaux chargés, 16 contrôles scannables au Basic
  (endpoints Windows/Linux multi-distro apt/dnf/zypper/pacman/apk, +
  équipements réseau via 10 adaptateurs constructeur — « d'après-doc », non
  validés sur matériel réel = dette « BANC »).
- **Intégrité** : journal tamper-evident (chaîne sha256), override consultant
  tracé pour le 5/5, scan plafonné à Managed(4), fuzzing des normaliseurs,
  test de sécurité « toutes les commandes sont read-only », build reproductible.
- **Robustesse terrain** : dégradation gracieuse (scan impossible → attestation
  questionnaire, jamais 0), verdict BLOQUÉ si des contrôles restent non évalués
  (« AUDIT INCOMPLET »), détection de droits insuffisants (sans élévation), mode
  `-preflight` de reconnaissance du périmètre de droits.
- **CLI orchestrateur** : `-scope -level -evidence -responses -transport
  -creds -known-hosts -out -html -xlsx -pdf -overrides -coverage -preflight
  -capture -history` (SQLite historique découplé via build tag `history`,
  hors clé USB). Le périmètre vient TOUJOURS d'un fichier `-scope` (exemple :
  `sample/scope.json`), jamais du code.
- **Questionnaire web** : `-level basic|important|essential`, écoute
  127.0.0.1:8099 uniquement, jeton anti-CSRF + contrôle Origin/Host.
- **Sondes Linux** : une sonde se termine TOUJOURS par un code de sortie nul
  quand elle a pu observer (le transport SSH traite un code non nul comme une
  collecte échouée). « Outil absent » et « outil illisible faute de droits »
  sont deux cas distincts : le premier peut être une non-conformité, le second
  est un trou de collecte « droits insuffisants ». Tests :
  `internal/engine/probes_shell_test.go`.
- **Validation réelle (28/09/2026)** : Windows 11 25H2 par WinRM (NTLM,
  compte non admin : 59/64 lisibles), Ubuntu 26.04 par SSH non root (64/64)
  et sondes rejouées en `nobody` (63/64),
  parité de calcul avec les trois outils Excel du CCB (méthode publiée :
  identité exacte ; classeurs publiés : anomalies de formules recensées).
  Voir `docs/methode/validation-reelle-2026-09-28.md`. Règle Windows : toute
  sonde commence par `controls.WinPre` ; un refus d'accès n'est JAMAIS une
  conclusion.
- **Licence** : PolyForm Noncommercial 1.0.0 (code) ; textes CyFun propriété
  du CCB (NOTICE). Ne pas présenter le projet comme « open source ».
- **Reste** : valider les adaptateurs réseau sur matériel réel ; produire/booter
  l'ISO live (recette dans `live/`, jamais démarrée) ; commandes Windows
  downlevel *réelles* pour Win7 (aujourd'hui gérées par repli + couverture).

Historique des versions : `CHANGELOG.md`. Documents de méthode : `docs/methode/`.

## Style de collaboration attendu
Développeur solo, connaît déjà Python/Java/C#, apprend Go en
parallèle du projet. Préférer des explications claires sur le "pourquoi"
des choix Go (idiomes, stdlib) plutôt que du code non commenté.

## Vérifications avant chaque commit
`make check` (gofmt, vet, staticcheck, tests -race avec et sans
`-tags history`, govulncheck, go mod verify), identique à la CI
(`.github/workflows/ci.yml`). Go n'étant pas forcément installé sur le poste,
tout peut tourner dans l'image officielle `golang` (Podman ou Docker).
