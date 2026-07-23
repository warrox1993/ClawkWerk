package controls

import (
	"encoding/json"
	"fmt"
)

// ParseM365Inventory — fonction PURE de comptage des services cloud d'un tenant
// Microsoft 365, base factuelle des contrôles CyFun ID.AM-02.1 (« digital
// services ») et ID.AM-01.1 (« cloud-hosted environments »). Elle n'effectue
// AUCUNE I/O : elle reçoit une enveloppe JSON déjà collectée (lecture seule via
// Microsoft Graph) et se contente d'en dériver un compte.
//
// L'enveloppe agrège deux réponses Graph telles quelles :
//   - subscribed_skus : GET /subscribedSkus  → les licences/plans souscrits
//   - domains         : GET /domains         → les domaines rattachés au tenant
//
// Décodage TOLÉRANT : les champs sont optionnels (pointeurs + omitempty), les
// deux clés peuvent être absentes ou vides, et rien ne panique. Une enveloppe
// vide « {} » vaut donc serviceCount == 0 sans erreur. La SEULE cause d'erreur
// est un JSON syntaxiquement invalide.
//
// Le choix des pointeurs (*string, *bool) est délibéré : il distingue « champ
// absent » (nil) de « valeur zéro explicite » (false / ""), ce qui évite de
// compter un SKU sans capabilityStatus ou un domaine sans isVerified — un
// champ manquant n'est jamais interprété comme « Enabled » ou « vérifié ».
func ParseM365Inventory(envelope []byte) (serviceCount int, err error) {
	// Schéma fidèle à Graph : chaque endpoint renvoie un objet { "value": [...] }.
	var env struct {
		SubscribedSkus struct {
			Value []struct {
				SkuID            *string `json:"skuId,omitempty"`
				SkuPartNumber    *string `json:"skuPartNumber,omitempty"`
				CapabilityStatus *string `json:"capabilityStatus,omitempty"`
			} `json:"value,omitempty"`
		} `json:"subscribed_skus,omitempty"`
		Domains struct {
			Value []struct {
				ID         *string `json:"id,omitempty"`
				IsVerified *bool   `json:"isVerified,omitempty"`
			} `json:"value,omitempty"`
		} `json:"domains,omitempty"`
	}

	if err := json.Unmarshal(envelope, &env); err != nil {
		return 0, fmt.Errorf("enveloppe inventaire M365 illisible : %w", err)
	}

	// Un SKU compte s'il est explicitement « Enabled » (Graph : capabilityStatus
	// ∈ {Enabled, Warning, Suspended, Deleted, LockedOut}). On ne compte que
	// l'état actif, jamais un champ absent.
	for _, s := range env.SubscribedSkus.Value {
		if s.CapabilityStatus != nil && *s.CapabilityStatus == "Enabled" {
			serviceCount++
		}
	}

	// Un domaine compte s'il est explicitement vérifié (isVerified == true).
	for _, d := range env.Domains.Value {
		if derefBool(d.IsVerified) {
			serviceCount++
		}
	}

	return serviceCount, nil
}
