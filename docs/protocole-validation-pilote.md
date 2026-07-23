# Protocole de validation en pilote — projetCyber

Date : 2026-07-04
Statut : protocole de référence pour les campagnes pilotes.
Public : consultant projetCyber (dev solo) menant des audits pilotes en Wallonie/Bruxelles.

## 0. Pourquoi ce protocole

Le **cerveau** de l'outil est prouvé (couverture CCB 100 %, scoring à parité, intégrité,
dégradation gracieuse, normaliseurs/évaluateurs testés sur des centaines de cas). Mais
**aucune commande de collecte n'a encore tourné sur une vraie machine** : les ~64 sondes
et adaptateurs sont « d'après-doc ». Ce protocole transforme ce statut en « validé
terrain » de façon **honnête** — sans jamais franchir les garanties de sécurité — et
produit une **bibliothèque de fixtures golden** qui verrouille les acquis contre toute
régression.

Principe directeur : *une sonde n'est « validée » que lorsqu'on a vu sa sortie sur une
vraie machine, confirmé que le normaliseur la lit correctement, et figé cette sortie
comme test de non-régression.*

## 1. Objectif & critères de sortie

**Par sonde**, on statue l'un de trois états :
- **VALIDÉ** — la commande tourne en lecture seule, renvoie la donnée attendue, le
  normaliseur la parse correctement, et le score reflète la réalité observée.
- **À CORRIGER** — la commande tourne mais la sortie diffère de l'attendu (ex. libellé
  localisé, format inattendu) ; on capture la vraie sortie, on corrige, on re-teste.
- **TROU** — la commande ne s'applique pas / n'est pas disponible sur cet environnement ;
  la dégradation gracieuse + la matrice de couverture le rendent honnêtement visible.

**Sortie globale (definition of done)** :
1. Chaque **Key Measure** scannable validé sur ≥ 1 hôte réel par OS/locale supporté.
2. Bibliothèque de **fixtures golden** committée (une par sonde × environnement observé).
3. **Matrice de couverture** mise à jour : les statuts « d'après-doc » deviennent
   « validé-matériel » là où c'est le cas ; les trous restants sont documentés, jamais
   maquillés en « 100 % ».
4. Liste des écarts/bugs corrigés + CLAUDE.md/mémoire à jour.

## 2. Périmètre à valider (inventaire)

| Bloc | À valider | Comment obtenir la liste exacte |
|---|---|---|
| **Endpoints Windows/Linux** | Toutes les sondes scannables (Identity, Hardening, Patch, Firewall, AV, Logging, LocalAdmin, Backup, EDR, Encryption, AppControl, BootDevice, TimeSync, LogMgmt, FIM, Domain, Hardware, Capacity, VulnScanner, AccessReview, RemoteMFA…) | Section « Couverture de collecte » du rapport HTML ; `internal/engine/registry.go` |
| **Transports** | SSH (Linux), WinRM (Windows), API (UniFi/Sophos) — flux auth + exécution réels | `internal/scan/` |
| **Équipements réseau** | 10 marques × 3 contrôles (pare-feu, segmentation, journalisation) | `projetcyber -coverage` |
| **Locales** | Windows **FR, NL, DE, EN** ; Linux apt/dnf/zypper/pacman/apk | — |
| **Livraison** | ISO live-boot (stateless, toram) | `live/` |

## 3. Prérequis — GATE (ne pas démarrer sans)

**Légal / consentement :**
- [ ] **Autorisation écrite** du client : périmètre (liste d'hôtes explicite), fenêtre
  temporelle, personnes contacts. Aucune découverte réseau — la liste est fournie.
- [ ] **Compte de service read-only** fourni par le client (jamais généré/deviné par nous).
- [ ] **RGPD** : aucune donnée personnelle capturée ; hôtes pseudonymisés ; les fixtures
  golden sont **anonymisées** (retirer noms de machines, IP, utilisateurs réels).

**Technique / sécurité (déjà garanti par l'outil, à re-confirmer) :**
- [ ] Toutes les commandes sont **lecture seule** (test automatique `security_test`).
- [ ] **Aucune élévation de privilèges** (par conception). Manque de droits ⇒ `-preflight`
  le signale, on provisionne, on ne force jamais.
- [ ] **Journal** non désactivable actif ; chaîne d'intégrité vérifiée en fin de run.

**Conditions d'arrêt (abort) :** comportement système inattendu, refus du client,
indisponibilité du compte de service, ou tout doute sur le caractère read-only.

## 4. Matrice d'environnements à couvrir (prioriser, pas tout d'un coup)

| Environnement | Priorité | Note |
|---|---|---|
| Windows 10/11 **FR** | P1 | locale dominante cible belge |
| Windows 10/11 **NL** | P1 | Flandre |
| Windows 10/11 **DE** | P2 | cantons de l'Est |
| Windows **EN** | P2 | référence |
| Windows **7 / Server 2012** | P3 | héritage (sondes downlevel) |
| Ubuntu/Debian (apt) | P1 | — |
| Fedora/RHEL (dnf) | P2 | — |
| openSUSE (zypper), Arch (pacman), Alpine (apk) | P3 | multi-distro déjà codé |
| Équipements réseau (par marque) | P2-P3 | track dédié §8 |

## 5. Procédure par sonde (le cœur du protocole)

Pour **chaque** sonde, sur **chaque** environnement pertinent :

1. **Preflight** — lancer `projetcyber -preflight -transport remote -creds <json> -known-hosts <path>`
   sur le périmètre. Confirmer que le compte lit la ressource (statut « lisible »). Si
   « droits insuffisants » → provisionner côté client, jamais escalader.
2. **Capturer la sortie BRUTE** — exécuter la commande de la sonde (elle est dans le code,
   ex. `PRAA0101WinCmd`) telle quelle sur l'hôte, et **enregistrer la sortie exacte**
   (copier-coller ou redirection fichier). C'est la vérité terrain.
3. **Vérifier read-only & plausibilité** — confirmer qu'aucun état système n'a changé et
   que la donnée renvoyée a du sens.
4. **Comparer au résultat de l'outil** — lancer l'audit et comparer le constat/score de la
   sonde à ce qu'on observe *manuellement* sur la machine (ex. la vraie longueur minimale
   de mot de passe vs celle rapportée).
5. **En cas d'écart** — enregistrer la vraie sortie, **corriger** le normaliseur (ex.
   ajouter le libellé FR/NL/DE réel), puis **ajouter la sortie brute comme fixture golden**
   (§6). Re-tester jusqu'à concordance.
6. **Statuer** VALIDÉ / À CORRIGER / TROU dans la fiche (§11).

**Point d'attention locale (Windows FR/NL/DE)** : vérifier en priorité les sondes qui
lisaient des libellés traduits — `PR.AA-01.1` (`net accounts`), journalisation, NTP. Les
libellés multilingues codés sont **best-effort** : ce pilote sert à **confirmer les chaînes
FR/NL/DE réelles** et à corriger le cas échéant.

## 6. Boucle de rétroaction « fixtures golden »

Chaque sortie réelle capturée devient un **test permanent** :
1. Anonymiser la sortie brute (retirer données personnelles/IP/hostnames réels).
2. La placer en `testdata` du paquet de la sonde.
3. Ajouter un test Go qui **feed la sortie brute au normaliseur** et assert l'`Evidence`
   attendue (comme les tests multilingues existants de `PR.AA-01.1`).

Effet : chaque machine réelle vue en pilote **protège l'outil contre toute régression**
future, et la couverture réelle croît de façon **prouvée**, pas déclarée.

> **Outillage disponible** : lancer l'orchestrateur avec `-capture <dir>` enregistre
> AUTOMATIQUEMENT, pendant le run, la sortie BRUTE de chaque collecte réussie dans
> `<dir>/<hôte>.<contrôle>.<os>.raw` (redaction best-effort IPv4/MAC + README RGPD).
> Zéro capture manuelle : il ne reste qu'à RELIRE/anonymiser (noms d'utilisateurs) et à
> déposer le fichier en `testdata` avec un test de normaliseur. Observateur passif :
> n'altère jamais l'audit.

## 7. Ordre des vagues

- **Vague 1 (P1)** : les **13 Key Measures** scannables sur Windows **FR** + un Linux apt.
  (Ce sont elles qui gouvernent la conformité — priorité absolue.)
- **Vague 2** : reste des scannables Basic + locales **NL/DE**.
- **Vague 3** : promotions Important/Essential.
- **Vague 4** : **équipements réseau** (track §8).
- **Vague 5** : **ISO live-boot** (track §9).

## 8. Track réseau (BANC) — spécifique

Le matériel réel étant rare, valider par marque via des **images/VM d'évaluation** quand
c'est possible, sinon matériel emprunté :
- RouterOS → **CHR** (image gratuite), pfSense/OPNsense → VM, VyOS → VM, FortiGate → VM
  d'éval, Cisco → CML/IOSv, PAN-OS → VM d'éval, SonicOS/Fireware/Zyxel → matériel emprunté,
  UniFi/Sophos → contrôleur/appliance d'éval (track API).
- Pour chaque marque : exécuter la commande CLI SSH read-only de l'adaptateur, capturer la
  sortie, valider le normaliseur, **passer le statut de couverture** de « d'après-doc » à
  « validé-matériel ». **Aucune marque n'est déclarée validée sans capture réelle.**

## 9. Track ISO live-boot

- Construire l'ISO sur une machine Debian (`live/build.sh`).
- Booter `toram`, vérifier : **stateless** (rien ne survit au reboot entre client A et B),
  questionnaire servi sur `127.0.0.1:8099`, exports en tmpfs, export final immédiat, aucune
  persistance sur la clé.
- Tester le cycle complet d'un audit de bout en bout depuis la clé.

## 10. Livrables du pilote

1. **Rapport de validation** : tableau par sonde × environnement (VALIDÉ/À CORRIGER/TROU).
2. **Bibliothèque de fixtures golden** committée (tests de non-régression).
3. **Matrice de couverture** actualisée (statuts réels).
4. **Liste des écarts** rencontrés + correctifs appliqués.
5. Mise à jour `CLAUDE.md` + mémoire (`projetcyber-design-decisions`).

## 11. Annexe — Fiche de validation par sonde (modèle à remplir)

```
Sonde / contrôle : ______________________ (ID CCB : __________)
Environnement    : Windows [FR|NL|DE|EN|7] / Linux [apt|dnf|zypper|pacman|apk] / Réseau [marque]
Compte de service: read-only ? [O/N]   Preflight « lisible » ? [O/N]
Commande exécutée: __________________________________________
Sortie brute (anonymisée, jointe en fixture) : fichier ______________
Read-only confirmé (aucun changement d'état) : [O/N]
Donnée observée manuellement                 : __________________
Constat/score rendu par l'outil              : __________________
Concordance                                  : [OUI | ÉCART: ______]
Correctif appliqué (si écart)                : __________________
Fixture golden ajoutée                       : [O/N] test : ______
STATUT : [ VALIDÉ | À CORRIGER | TROU ]   Date : ________  Par : ________
```

---

**Rappel d'intégrité** : ce protocole ne « termine » pas le produit d'un coup — il le rend
*honnêtement validé*, sonde par sonde, avec preuve. Tant qu'une sonde n'a pas sa fixture
golden issue d'une vraie machine, elle reste « d'après-doc » et la couverture le dit.
