# Validation en conditions réelles (28/09/2026)

Ce document consigne la première validation de ClawkWerk hors banc de test :
un vrai Windows, un vrai Linux, et une comparaison de calcul avec les outils
officiels du Centre pour la Cybersécurité Belgique (CCB). Chaque défaut trouvé
a été corrigé et couvert par un test (version 1.1.0).

## 1. Windows 11 réel (WinRM)

**Machine** : Windows 11 Professionnel 25H2, langue fr-BE, machine virtuelle de
test (BitLocker actif, Secure Boot actif, Defender actif, pare-feu d'origine,
hors domaine, compte Microsoft). Audit par WinRM HTTPS depuis l'hôte, certificat
de l'hôte vérifié par `-winrm-ca`, authentification NTLM.

**Compte d'audit** : compte local NON administrateur, membre de
« Utilisateurs de gestion à distance » (S-1-5-32-580) et « Lecteurs des
journaux d'événements » (S-1-5-32-573). Un second passage a été fait avec un
compte administrateur local pour comparer.

### Provisionnement côté client (constaté)

1. Écouteur WinRM HTTPS (port 5986) avec un certificat dont le client fournit
   l'autorité (`-winrm-ca`). WinRM d'origine n'accepte pas Basic : ClawkWerk
   utilise NTLM par défaut (`-winrm-auth ntlm`), qui fonctionne aussi avec un
   compte de domaine.
2. Le groupe « Utilisateurs de gestion à distance » donne accès à PowerShell
   Remoting, pas au shell WinRS qu'utilise ClawkWerk : il faut aussi autoriser
   ce groupe dans le descripteur racine de WinRM (lecture + exécution) :

   ```powershell
   Set-Item WSMan:\localhost\Service\RootSDDL -Force -Value `
     "O:NSG:BAD:P(A;;GA;;;BA)(A;;GR;;;IU)(A;;GXGR;;;RM)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"
   ```

   Sur une machine dont une interface est en profil réseau « Public », cette
   commande est refusée ; la valeur `rootSDDL` peut alors être posée dans
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service`, suivie d'un
   redémarrage du service WinRM.
3. « Lecteurs des journaux d'événements » pour les journaux Security et System.

### Défauts constatés et corrigés

| Défaut | Effet avant correction |
|---|---|
| Authentification Basic uniquement | 64/64 collectes en erreur 401 |
| Faute WS-Management non détaillée | « received error response » au lieu de « Accès refusé » |
| Refus d'accès masqués (`-ErrorAction SilentlyContinue`, `2>$null`) | BitLocker actif rapporté « volume non chiffré », Secure Boot actif « désactivé », disque « 0 % », aucune sauvegarde/EDR/SIEM « détecté » faute de pouvoir lister les services |
| `w32tm` refusé | « Horloge synchronisée sur L'erreur suivante s'est produite… » |
| API Windows Update refusée à toute session WinRM | ID.AM-08.2 et ID.RA-01.x en collecte échouée |
| Rétention des journaux codée en dur (90 j) | 20 j réels |
| `DefaultInboundAction = NotConfigured` classé « autoriser » | pare-feu d'origine sous-évalué |
| Services intégrés pris pour des outils (wbengine, CloudBackupRestoreSvc, WdNisSvc) | faux positifs sauvegarde et EDR |
| Politique d'intégrité du noyau prise pour un allowlisting | faux positif allowlisting |
| Compte Microsoft compté comme dormant | faux positif |
| `net accounts` lu dans la mauvaise page de codes | libellés accentués illisibles |
| Sonde plus longue que la ligne de commande cmd.exe | « La ligne de commande est trop longue » |

La règle portée désormais par toutes les sondes (préambule `WinPre`) : une
source refusée devient « droits insuffisants » avec la ressource nommée au
preflight, jamais une conclusion.

### Résultat

- Compte non administrateur : 57 collectes lisibles sur 64, 7 « droits
  insuffisants » nommés (BitLocker pour PR.DS-01.6, PR.DS-02.1, PR.DS-02.2 ;
  Device Guard pour PR.PS-01.4, PR.PS-02.1, PR.PS-05.2 ; w32tm pour
  PR.PS-04.2). Ces trois sources exigent un administrateur local sous Windows.
- Compte administrateur local : 64/64.
- Constats recoupés avec l'état relevé directement sur la machine (compte
  SYSTEM) : pare-feu actif sur les trois profils, Defender actif et à jour,
  BitLocker actif sur C:, Secure Boot actif, dernier correctif installé le jour
  même, horloge jamais synchronisée (source « Local CMOS Clock »), hors
  domaine, deux administrateurs dont le compte intégré désactivé, 30 %
  d'occupation disque, journal Security de 20 Mo conservant 20 jours.
- Audits complets aux trois niveaux, journal d'audit vérifié (42, 126 et 192
  entrées), rapports HTML, PDF, XLSX et JSON produits.

## 2. Linux réel (SSH)

**Machine** : Ubuntu 26.04 (poste de développement), audit en lecture seule
par SSH sur 127.0.0.1 avec un compte NON root, clé et démon SSH temporaires
(aucune modification du système audité).

| Défaut | Effet avant correction |
|---|---|
| ufw, nft et iptables illisibles sans root | pare-feu « droits insuffisants » ; désormais constaté par `/etc/ufw/ufw.conf` et `/etc/default/ufw`, lisibles par tous |
| Rétention codée en dur (90 j) | 22 j réels (plus ancien enregistrement du journal systemd) |
| Seul `PASS_MIN_LEN` lu | « longueur minimale 0 » alors que PAM impose 8 |
| `passwd -S root` exige root | root verrouillé rapporté « actif » |
| `lastlog` absent d'Ubuntu 26.04 | « aucun compte dormant » sans aucune mesure |
| Timers systemd utilisateur et Timeshift ignorés | « aucune sauvegarde planifiée » |
| Exécution automatique émise « yes » en dur | « désactivée » sans constat |
| Absence de Samba lue comme « flux non chiffrés » | faux négatif |
| AppArmor compté comme allowlisting applicatif | faux positif |

Résultat : preflight 64/64 lisibles avec un compte non root ; constats
recoupés un à un (ufw actif, entrée DROP ; aucun correctif en attente ;
unattended-upgrades actif ; NTP synchronisé ; Secure Boot actif ; disque
système non chiffré ; 17 ports TCP en écoute ; pas d'antivirus).

## 3. Calcul : comparaison avec les outils officiels du CCB

**Sources** : outils d'auto-évaluation publiés sur
<https://cyfun.eu/en/cyberfundamentals-framework-2025> :
`CyFun2025_ Self-Assessment_tool_BASIC_v2026_02_20.xlsx`,
`CyFun2025_ Self-Assessment_tool_IMPORTANT_v2026_02_20.xlsx`,
`CyFun2025_Self-Assessment_tool_ESSENTIAL_v3.1.xlsx`.

**Protocole** (`docs/methode/validation/parite.py`) : pour chaque niveau, quatre
jeux de notes (tout conforme, tout non conforme, mixte avec Key Measures en
échec et 10 % d'exigences non applicables, valeurs aux seuils). Les mêmes
notes sont saisies dans ClawkWerk (questionnaire, overrides N/A) et dans le
classeur officiel, recalculé par LibreOffice (le fichier n'est jamais
modifié sur disque). Comparaison des maturités Documentation, Implementation
et de catégorie pour chaque catégorie, de la maturité totale, des Key
Measures sous le seuil, des catégories sous le seuil (Essential) et du verdict.

**Défaut ClawkWerk trouvé et corrigé** : ID.AM-03-2 était rangée dans une
sous-catégorie à part au lieu de ID.AM-03 ; au niveau Essential, la maturité
ID.AM s'en trouvait faussée.

**Résultat** :

- Méthode de calcul publiée par le CCB (moyenne par sous-catégorie, puis par
  catégorie, N/A remplacé par le seuil) : identité exacte (écart < 1e-9) sur
  les 12 jeux, pour toutes les valeurs comparées.
- Classeurs tels que publiés : verdict identique sur les 12 jeux ; maturités
  identiques au niveau Basic ; aux niveaux Important et Essential, les seuls
  écarts viennent d'anomalies de formules des classeurs, recensées par
  `docs/methode/validation/anomalies.py` :

| Classeur | Cellules | Anomalie |
|---|---|---|
| IMPORTANT | PROTECT!I45:J45 | PR.IR-02.1 et PR.IR-04.1 moyennées comme une seule sous-catégorie |
| IMPORTANT | GOVERN!I15:J15, RECOVER!J4:J7 | N/A non remplacé par le seuil (RC.CO entièrement N/A : #DIV/0! et maturité totale illisible) |
| ESSENTIAL | PROTECT!L3 | maturité d'implémentation PR.AA calculée sur J3:J24, sans PR.AA-06 |
| ESSENTIAL | PROTECT!I80:J80 | PR.IR-03.1 et PR.IR-04.1 moyennées comme une seule sous-catégorie |
| ESSENTIAL | RECOVER lignes 8 à 10 | RC.CO-04 éclatée en trois sous-catégories |
| ESSENTIAL | GOVERN!I27:J27 | GV.OV-02.1 et GV.OV-03.1 regroupées (sans effet : seules sous-catégories de GV.OV) |
| ESSENTIAL | GOVERN!I12:J13, I29:J29, IDENTIFY!I43:J43 | N/A non remplacé par le seuil |
| les trois | onglet Summary, colonnes KM | une Key Measure marquée N/A donne #DIV/0! ; ClawkWerk la traite comme conforme (valeur du seuil, comme les autres exigences N/A) |

ClawkWerk suit la méthode publiée et ne reproduit pas ces anomalies ; elles
méritent d'être signalées au CCB.

## 4. Couverture et textes

- Les 34, 133 et 218 exigences des outils officiels sont évaluées par
  ClawkWerk (sonde ou questionnaire), sans oubli ni doublon ; niveau, Key
  Measure et sous-catégorie identiques pour chacune (13, 22 et 29 Key
  Measures).
- Identifiants : les outils n'écrivent pas tous les identifiants de la même
  façon (ID.AM-5.1 et DE.CM-03-1 dans BASIC, ID.AM-05.1 et DE.CM-03.1 dans
  ESSENTIAL ; GV.RR-03-1 dans le livret) ; ClawkWerk garde une écriture par
  exigence.
- Textes comparés aux trois outils et au livret CyberFundamentals 2025
  ESSENTIAL (version 2025-10-01, 218 exigences) : DE.AE-03.1 et GV.OC-03.2
  alignés sur la version la plus récente (outil ESSENTIAL v3.1 et livret).
  Les autres écarts sont typographiques ou propres à une seule source (par
  exemple « rmonitored », « must » au lieu de « shall » dans l'outil
  ESSENTIAL) ; chaque texte de ClawkWerk est identique à au moins une source
  officielle.

## 5. NIS2

Source : page NIS2 du CCB, <https://atwork.safeonweb.be/nis2> (consultée le
28/09/2026). En Belgique (loi du 26 avril 2024, arrêté royal du 9 juin 2024),
une entité essentielle se soumet à une évaluation de conformité régulière au
choix : vérification CyFun (niveaux Basic, Important) ou certification CyFun
(niveau Essential) par un organisme d'évaluation de la conformité (CAB)
accrédité par BELAC et autorisé par le CCB, certification ISO/IEC 27001
auprès d'un CAB accrédité et autorisé, ou inspection du CCB. L'attestation
obtenue donne une présomption de conformité. Une entité importante peut
s'y soumettre volontairement.

ClawkWerk est un outil d'AUTO-évaluation : il prépare ces démarches et ne
délivre ni vérification, ni certification, ni présomption de conformité. Les
rapports et le questionnaire le disent désormais dans ces termes.

## 6. Ce qui reste non validé

- Adaptateurs des dix familles d'équipements réseau : jamais exécutés sur du
  matériel réel.
- Windows : un seul poste (Windows 11 25H2 fr-BE) ; ni Windows Server, ni
  Windows en néerlandais ou en allemand, ni machine jointe à un domaine
  (Kerberos non proposé ; NTLM avec un compte de domaine non essayé).
- Linux : une seule distribution réelle (Ubuntu 26.04) en plus des
  conteneurs Debian ; dnf, zypper, pacman et apk seulement testés sur
  sorties simulées.
- Microsoft 365 (API Graph) : jamais exécuté contre un vrai tenant.
- Clé USB live : jamais démarrée.
- Le questionnaire reste déclaratif : 152 des 218 exigences (Essential)
  reposent sur les réponses de l'organisation.

## Reproduire

```sh
# outils officiels téléchargés dans $CYFUN_OUTILS ; openpyxl et LibreOffice (UNO)
CYFUN_OUTILS=~/cyfun CLAWKWERK_BIN=bin/orchestrator python3 docs/methode/validation/parite.py
CYFUN_OUTILS=~/cyfun python3 docs/methode/validation/anomalies.py
```
