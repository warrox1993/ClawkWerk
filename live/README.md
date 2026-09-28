# Clé USB bootable — ClawkWerk (live, stateless)

Recette de construction d'une image **live Debian** qui démarre entièrement en
RAM, exécute l'outil d'audit CyFun, puis ne laisse **aucune trace** entre deux
clients (contrainte stateless de la clé).

> ⚠️ **Statut : squelette non booté-testé.** Les scripts sont écrits d'après la
> documentation `live-build`. À valider en construisant l'ISO sur une machine
> Debian, puis en bootant sur un poste de test.

## Principes (conformes au CLAUDE.md)

- **Stateless** : boot avec `toram` → tout le système vit en RAM, on peut
  retirer la clé après le boot ; rien n'est réécrit dessus. Les répertoires de
  travail sont des tmpfs. Aucune base persistante sur la clé (l'historique
  SQLite consultant vit **hors clé**, sur le poste du consultant).
- **Lecture seule** : l'audit collecte à distance en lecture seule (SSH/WinRM).
  Aucune remédiation n'est exécutée automatiquement — jamais.
- **Local uniquement** : le questionnaire web écoute sur `127.0.0.1:8099`
  (loopback strict), jamais exposé au réseau.
- **Binaire statique** : `orchestrator` et `questionnaire` sont compilés en
  `CGO_ENABLED=0` (aucune dépendance système), copiés dans `/opt/clawkwerk`.

## Prérequis (sur une machine Debian/Ubuntu de build)

```sh
sudo apt update && sudo apt install -y live-build golang
```

## Construire l'image

```sh
cd live
./build.sh
```

Le script :
1. compile les binaires statiques dans `config/includes.chroot/opt/clawkwerk/` ;
2. configure `live-build` (Debian bookworm, amd64, boot `toram`) ;
3. lance `sudo lb build` → produit `live-image-amd64.hybrid.iso`.

## Écrire sur la clé USB

```sh
sudo dd if=live-image-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress && sync
```

(remplacer `/dev/sdX` par la clé cible — **vérifier deux fois**, `dd` écrase tout.)

## À l'usage

- Le service `clawkwerk-questionnaire` démarre au boot et sert le
  questionnaire déclaratif sur `http://127.0.0.1:8099` (ouvrir un navigateur
  local si l'image est graphique ; sinon utiliser l'orchestrateur en CLI).
- Scan technique : `orchestrator -scope /run/clawkwerk/scope.json -transport remote -creds /run/clawkwerk/creds.json -known-hosts /run/clawkwerk/known_hosts -pdf /run/clawkwerk/rapport.pdf`.
- **Exporter le rapport en fin de session** (vers le client / un support séparé)
  avant d'éteindre : rien n'est conservé sur la clé.

## Limites connues / à faire

- Non booté-testé (produire l'ISO et valider sur banc).
- Image console par défaut : pour le questionnaire web, ajouter un environnement
  graphique minimal + navigateur (voir `config/package-lists`).
- Durcissement (pas de services réseau entrants, montages read-only) à affiner.
