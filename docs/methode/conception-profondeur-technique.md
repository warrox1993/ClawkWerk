# Profondeur technique Important + Essential — Design

Date : 2026-07-04
Statut : design validé (brainstorming), en attente de relecture avant plan d'implémentation.
Chantier : #3 « Profondeur technique » de la feuille de route du projet.

## 1. Objectif

Rendre **scannables** un maximum de contrôles CyFun aux niveaux **Important**
(99 contrôles propres, aujourd'hui tous déclaratifs) et **Essential** (85 propres,
tous déclaratifs) — le **plafond honnête** : tout ce qu'un scan lecture-seule peut
prouver, Key Measures d'abord. Chaque contrôle rendu scannable remplace une
déclaration par une preuve mesurée.

Objectif de puissance associé : un **score de risque technique par hôte**
(corrélation inter-contrôles), livré dans cette spec.

## 2. Périmètre / hors-périmètre

**Dans le périmètre :**
- Toutes les familles de signaux techniques honnêtement scannables sur
  Important + Essential (livrées par lots successifs jusqu'à épuisement).
- Score de risque technique par hôte (indicateur de triage).

**Hors périmètre (invariants) :**
- Les contrôles **organisationnels** (gouvernance, formation, plans, contrats,
  accès physique, RH…) restent au questionnaire. Aucun faux scan — jamais.
- **Aucune élévation de privilèges** (règle absolue) : on constate l'accès, on ne
  se l'arroge pas. Le `-preflight` et la dégradation gracieuse gèrent les droits.
- Validation des commandes sur **matériel/OS réels** : reportée aux pilotes
  (chantier #1). On ne prétend jamais qu'une commande non éprouvée est validée.
- **Déduplication de collecte** par signal : optimisation future (YAGNI). Si N
  contrôles partagent une sonde, la collecte tourne N fois — accepté (lecture seule,
  léger). Les signaux ont un ID stable pour rendre la dédup triviale plus tard.

## 3. Architecture — le modèle « sonde de famille »

Découplage **signal ↔ contrôle**, sans modifier le moteur (donc faible risque) :

- **Sonde de famille** = un signal réutilisable défini UNE fois : type `Evidence`
  riche + normaliseurs (windows/linux/…) + commandes lecture-seule. 11 sondes
  existent déjà (identités, pare-feu, correctifs, journalisation, sauvegardes, EDR,
  durcissement, comptes admin, MFA, filtres web, segmentation).
- **Contrôle promu** = `Evaluator` propre + `Meta` + entrée registre, qui
  **consomme l'`Evidence` d'une sonde** avec des seuils **adaptés au niveau**. La
  Documentation vient du questionnaire ; le scan alimente l'Implementation.

Réutilisation au niveau du code : un nouveau contrôle Important/Essential sur un
signal déjà capté n'ajoute qu'un `Evaluator` + `Meta` + câblage — pas de nouvelle
sonde. Une sonde à durcir, pas trente.

### 3.1 Richesse des signaux — « collecter une fois, évaluer beaucoup »

Chaque sonde capture une preuve **riche et structurée**, pas un booléen minimal
(ex. « identités » = politique MDP complète + inventaire comptes + verrouillage +
comptes dormants + indices MFA + comptes de service). Une collecte alimente alors
tous les contrôles de la famille aux 3 niveaux **et les futurs contrôles CCB**.

### 3.2 Évaluateurs conscients du niveau

Même `Evidence`, seuils plus stricts par tier : Essential exige davantage
qu'Important pour le même palier de maturité. Un seul scan → verdict juste à chaque
niveau. **Invariant testé** : monotonie (un parc conforme Essential l'est à
Important puis Basic).

### 3.3 Nouvelles familles probables (signaux absents de Basic)

Chiffrement au repos (BitLocker/LUKS), centralisation des logs (SIEM / forward
syslog), gestion des vulnérabilités (scanner présent + fréquence), certificats/TLS,
MDM/mobile, durcissement avancé (services, GPO). Liste **confirmée par la phase de
découverte**, pas figée a priori.

## 4. Score de risque technique par hôte

Indicateur de **triage**, dérivé UNIQUEMENT des constats **scannés** (`StatusPass/
Partial/Fail` mesurés), **jamais** des attestations de repli ni du questionnaire.

- **Calcul** : par hôte, agrégation pondérée des constats scannés — Key Measures
  plus lourdes, `Fail` > `Partial` > `Pass` — normalisée en indice transparent
  (ex. 0–100 + lettre A–E) avec pondérations documentées.
- **Intégrité — non négociable** : cet indice est **explicitement distinct** du
  score de maturité/conformité CyFun. Il est labellisé « indicateur de risque
  technique (constats scannés) — n'est pas un verdict de conformité CCB ». Il ne
  substitue jamais un score, ne comble jamais un trou, et n'apparaît pas dans le
  calcul de conformité. C'est une aide à la priorisation, pas une note d'audit.
- **Restitution** : une ligne par hôte dans le rapport (section dédiée), triée du
  plus risqué au moins risqué, avec le top des constats contributeurs.

## 5. Phase de découverte

Identique à la méthode éprouvée pour Basic, à l'échelle des 184 contrôles :
1. Fan-out d'agents extrayant la guidance des Booklets IMPORTANT + ESSENTIAL +
   Key_Measures PDF (documents CyFun 2025 publiés par le CCB sur cyfun.eu).
2. Chaque contrôle classé **SCAN / MIXTE / ORG** ET **rattaché à une famille**
   (sonde existante ou à créer).
3. Sortie = **backlog priorisé** : Key Measures d'abord, puis par valeur de preuve,
   groupé par famille.

## 6. Invariants d'intégrité (toute la spec)

- On ne promeut QUE le volet techniquement prouvable ; l'organisationnel reste
  questionnaire.
- Le scan plafonne à **Managed (4)** ; le niveau **Optimizing (5)** s'atteste par
  override tracé.
- La **matrice de couverture** (déjà livrée) rend visible, contrôle par contrôle,
  ce qui est scanné vs attesté vs non évalué.
- **Dégradation gracieuse** (déjà livrée) : scan impossible ⇒ attestation
  questionnaire, jamais 0 ; verdict BLOQUÉ tant qu'il reste des trous.
- Binaire **statique CGo-free** préservé ; commandes **lecture seule** (test de
  sécurité automatique) ; **aucune** élévation de privilèges.

## 7. Stratégie de test

- **Unitaire** : normaliseurs (parsing de preuve riche ; invariant no-panic via
  fuzz déjà en place), `Evaluator` par contrôle × niveau (tables), mapping
  signal→contrôles, calcul du score de risque (pondérations, exclusion des
  attestations).
- **Propriété** : monotonie inter-niveaux + goldens figés.
- **Limite assumée** : les *commandes* ne sont pas testables sans hôtes réels →
  mitigée par (a) couverture + dégradation déjà en place, (b) une **bibliothèque de
  sorties réelles** capturées en pilotes (chantier #1) servant de fixtures golden.

## 8. Découpage & livraison

- **Phase 0 — Découverte** (fan-out) : backlog classé + rattaché aux familles.
- **Phase 1 — Score de risque** : socle transparent, testé, labellisé (petit lot,
  indépendant des familles).
- **Phases suivantes — une par FAMILLE** (cycle spec → plan → implémentation) :
  sonde riche + tous ses contrôles across niveaux + tests, en un lot cohérent,
  livrable seul. Fan-out d'agents pour les `Evaluator` ; câblage registre +
  couverture fait à la main. **Boucle famille par famille jusqu'à épuisement du
  scannable.**
- La prod n'attend pas que tout soit fini : chaque lot est autonome.

## 9. Critères de succès

- Découverte : les 184 contrôles Important/Essential classés SCAN/MIXTE/ORG +
  rattachés à une famille ; backlog priorisé KM d'abord.
- Chaque famille livrée : sonde riche + évaluateurs par niveau + tests verts,
  couverture honnête au rapport, `vet`/`gofmt` clean, statique préservé.
- Score de risque par hôte au rapport, clairement séparé de la conformité.
- « Fait » = il ne reste plus, dans le non-scanné, que de l'organisationnel assumé.

## 10. Ce qui rend le système « le plus puissant » (synthèse)

Automatisation honnête maximale + *collecter-une-fois-évaluer-beaucoup* (signaux
riches) + verdicts conscients du niveau + score de risque parc + intégrité prouvable
(tamper-evident, reproductible, sans escalade) + transparence de couverture. Aucun
consultant-tableur ni GRC générique ne réunit cela sur le référentiel CCB belge.
