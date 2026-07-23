package controls

import (
	"encoding/json"
	"strings"
)

// Adaptateur Cisco IOS / IOS-XE pour PR.IR-01.1 (pare-feu réseau).
//
// STATUT : d'après la documentation Cisco, NON validé sur matériel réel.
// La commande retenue est en LECTURE SEULE : `show ip access-lists` affiche
// les ACL IPv4 et leurs entrées (ACE) sans jamais rien modifier. C'est
// l'équivalent Cisco de « lister les règles de filtrage ».
//
// SUBTILITÉ IOS — l'« implicit deny any ». Sur IOS, toute ACL se termine par
// un `deny any` IMPLICITE, jamais affiché et jamais écrit par l'admin. Si on
// se contentait de « ça se termine par un deny », DefaultInboundDeny serait
// TOUJOURS vrai — preuve sans valeur puisqu'elle n'atteste d'aucune intention.
// On exige donc un `deny` EXPLICITE portant sur `any` (ex. `deny ip any any`,
// `deny   any`) : c'est le signe qu'un opérateur a délibérément posé une
// politique « bloquer par défaut », et c'est d'ailleurs la bonne pratique
// Cisco (une ligne deny explicite est comptabilisée dans les compteurs, pas
// l'implicite). Interprétation assumée et documentée.

func init() {
	registerNetFirewall(NetAdapter{
		Platform:  PlatformCiscoIOS,
		Vendor:    "Cisco",
		Command:   "show ip access-lists",
		Normalize: ciscoiosFirewallNormalize,
		Status:    StatusDocsUnverified,
	})
}

// ciscoiosFirewallNormalize parse la sortie de `show ip access-lists`.
//
// Forme typique :
//
//	Extended IP access list BLOCK-WEB
//	    10 permit tcp any any eq www
//	    20 deny ip any any
//	Standard IP access list 1
//	    10 permit 10.1.1.0, wildcard bits 0.0.0.255
//	    20 deny   any
//
// Les lignes « … access list … » sont des EN-TÊTES (une ACL) ; les autres
// lignes contenant permit/deny sont des ACE que l'on compte.
func ciscoiosFirewallNormalize(raw []byte) (json.RawMessage, error) {
	aceCount := 0
	explicitDefaultDeny := false

	for _, l := range lines(raw) {
		low := strings.ToLower(l)

		// En-tête d'ACL (« Standard/Extended IP access list … ») : on saute.
		if strings.Contains(low, "access list") {
			continue
		}

		isPermit := ciscoiosHasToken(low, "permit")
		isDeny := ciscoiosHasToken(low, "deny")
		if !isPermit && !isDeny {
			continue // ligne parasite (compteurs isolés, etc.)
		}
		aceCount++

		// deny EXPLICITE sur « any » = politique « bloquer par défaut » voulue.
		if isDeny && ciscoiosHasToken(low, "any") {
			explicitDefaultDeny = true
		}
	}

	return json.Marshal(NetFirewallEvidence{
		Present:            true, // un IOS filtrant embarque toujours le moteur d'ACL
		Enabled:            aceCount > 0,
		DefaultInboundDeny: explicitDefaultDeny,
		RuleCount:          aceCount,
		Firmware:           "", // dispo via `show version` (adaptateur ultérieur)
	})
}

// ciscoiosHasToken teste la présence d'un mot ENTIER (évite qu'un « deny »
// caché dans un nom d'ACL ne fausse le comptage). low est déjà en minuscules.
func ciscoiosHasToken(low, token string) bool {
	for _, f := range strings.Fields(low) {
		if f == token {
			return true
		}
	}
	return false
}
