# Phase 0 — Backlog de scannabilité Important + Essential

Date : 2026-07-04
Méthode : 6 agents ont classé les 184 contrôles propres à Important (99) et
Essential (85) en **SCAN / MIXTE / ORG** + **famille**, à partir du texte des
requirements, avec garde-fou d'intégrité (jamais de faux scan d'un contrôle
organisationnel ; doute SCAN/ORG → MIXTE ; découverte réseau autonome interdite).

## Totaux

| Classe | Nombre | Sens |
|---|---|---|
| **SCAN** (pur) | **6** | entièrement observable en lecture seule |
| **MIXTE** | **61** | preuve technique PARTIELLE honnête, fond organisationnel |
| **ORG** | **117** | purement documentaire → reste au questionnaire |
| **Total** | 184 | |

**67 contrôles scannables** (SCAN + MIXTE), dont **9 Key Measures** :
PR.AA-03.3, PR.PS-01.1, DE.CM-01.3, RS.MI-01.2, PR.DS-02.1, PR.IR-01.3,
PR.IR-01.4, ID.AM-03.3, ID.AM-08.9.

Rappel intégrité : les MIXTE sont plafonnés (le scan prouve une partie, l'axe
organisationnel reste au questionnaire + override) ; les 117 ORG ne seront JAMAIS
scannés. La matrice de couverture rend tout cela visible.

## Backlog par famille (SCAN + MIXTE ; ★ = Key Measure)

### durcissement-config — 10 (3 SCAN, 1 KM)
SCAN : PR.PS-01.2, PR.PS-01.3, PR.PS-01.4 (E — services/ports inutiles, allowlisting deny-all).
MIXTE : PR.PS-01.1★(I baseline durcie), PR.DS-01.1/04/05 (I — Secure Boot/FIM, stockage amovible, autorun), PR.PS-02.1/05.2 (I — AppLocker/WDAC), PR.PS-01.5 (E — audit de config).
Réutilise/étend la sonde **Hardening** existante (PR.AA-05.3). Forte densité SCAN.

### identites-acces — 12 (1 KM)
MIXTE : PR.AA-03.3★(I accès distant/NLA), PR.AA-01.2/05.5/05.7 (I), ID.AM-08.12 (I),
PR.AA-01.3/01.4/02.2/03.4/04.1/05.8/05.9 (E — comptes dormants, MFA/certs, comptes
partagés, chiffrement accès distant, assertions IdP, restrictions horaires, privilèges).
Réutilise/étend la sonde **Identity** existante (PR.AA-01.1). Plus gros saut de couverture.

### journalisation-detection — 13 (1 SCAN, 2 KM)
SCAN : PR.PS-04.2 (I — synchro NTP).
MIXTE : DE.CM-01.3★(I connexions), RS.MI-01.2★(I détection frontières), PR.PS-04.3 (I forward),
DE.CM-09.1/AE-02.1/AE-03.2 (I — SIEM/corrélation), PR.AA-01.5/PS-04.4 (E),
DE.CM-01.4/AE-02.2/AE-03.3 (E), RS.MA-02.2 (E forensic).
Réutilise/étend les sondes **Logging** / **DetLogging** existantes.

### reseau-segmentation — 9 (3 KM) — ⚠️ DÉPEND DU BANC
MIXTE : PR.IR-01.3★/01.4★(I), ID.AM-03.3★(E), ID.AM-04.2, PR.DS-10.1, PR.IR-01.5/07/08/09 (E).
Lisible via les adaptateurs constructeur, mais ceux-ci sont « d'après-doc, non
validés sur matériel réel » → **à traiter APRÈS le chantier #1 (BANC)**.

### chiffrement — 2 (2 SCAN)
SCAN : PR.DS-01.6 (E chiffrement au repos BitLocker/LUKS), PR.DS-02.2 (E en transit TLS/SMB/IPsec).
**Signal NEUF**, absent de Basic, très visible côté client → différenciateur.

### protection-endpoint — 4 (1 KM)
MIXTE : ID.AM-08.9★(E anti-malware supports), DE.CM-03.2 (I EDR), DE.CM-09.2/09.4 (E — intégrité matérielle/TPM, EDR+tuning). Réutilise/étend la sonde **EndpointMonitor**.

### gestion-actifs — 6
MIXTE : ID.AM-01.2/01.3/02.2/02.4 (I), ID.AM-01.4/02.5 (E — inventaires matériel/logiciel locaux).
Réutilise/étend la sonde **SoftwareInventory**.

### vulnerabilites-correctifs — 4
MIXTE : ID.RA-01.2/01.6 (I), ID.RA-08.2/IM-03.9 (E — versions obsolètes, présence d'un scanner de vuln).
Réutilise/étend la sonde **Patch**.

### protection-donnees — 3 (1 KM)
MIXTE : PR.DS-02.1★(E supports amovibles chiffrés), PR.DS-01.2/01.3 (E — FIM, réponse intégrité).

### sauvegardes-reprise — 2
MIXTE : PR.DS-11.2/11.3 (I — sauvegarde testée, emplacement distinct). Réutilise la sonde **Backup**.

### continuite-resilience — 2
MIXTE : PR.IR-04.1 (I capacité), GV.OC-04.3 (E redondance).

## Ordre d'implémentation recommandé (valeur × réutilisation × non-bloqué)

1. **durcissement-config** — 3 SCAN purs + 1 KM, étend la sonde Hardening. Densité de preuve max.
2. **identites-acces** — 12 contrôles + 1 KM, étend Identity. Plus gros saut de couverture.
3. **journalisation-detection** — 13 contrôles + 2 KM, étend Logging/DetLogging.
4. **chiffrement** — 2 SCAN neufs, différenciateur client.
5. **protection-endpoint** — 1 KM, étend EndpointMonitor.
6. **gestion-actifs** — étend SoftwareInventory.
7. **vulnerabilites-correctifs** — étend Patch.
8. **protection-donnees**, **sauvegardes-reprise**, **continuite-resilience** — petits lots.
9. **reseau-segmentation** — 3 KM mais **différé après le BANC** (adaptateurs à valider sur matériel réel).

## Suite

Chaque famille = son propre cycle spec → plan → implémentation (sonde riche +
évaluateurs par niveau + tests). Le score de risque par hôte (plan déjà écrit)
reste indépendant et livrable quand voulu.
