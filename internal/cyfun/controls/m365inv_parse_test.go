package controls

import "testing"

// Fixture FIDÈLE au schéma Graph : deux objets { "value": [...] } imbriqués sous
// les clés d'agrégation subscribed_skus / domains. 2 SKUs Enabled + 1 Disabled,
// 3 domaines vérifiés + 1 non vérifié → 2 + 3 = 5.
func TestParseM365Inventory_NominalCount(t *testing.T) {
	envelope := []byte(`{
		"subscribed_skus": { "value": [
			{"skuId":"c7df2760-2c81-4ef7-b578-5b5392b571df","skuPartNumber":"ENTERPRISEPREMIUM","capabilityStatus":"Enabled"},
			{"skuId":"6fd2c87f-b296-42f0-b197-1e91e994b900","skuPartNumber":"ENTERPRISEPACK","capabilityStatus":"Enabled"},
			{"skuId":"f30db892-07e9-47e9-837c-80727f46fd3d","skuPartNumber":"FLOW_FREE","capabilityStatus":"Suspended"}
		] },
		"domains": { "value": [
			{"id":"contoso.com","isVerified":true},
			{"id":"contoso.onmicrosoft.com","isVerified":true},
			{"id":"mail.contoso.com","isVerified":true},
			{"id":"pending.contoso.com","isVerified":false}
		] }
	}`)

	got, err := ParseM365Inventory(envelope)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if got != 5 {
		t.Fatalf("serviceCount = %d, attendu 5", got)
	}
}

// Enveloppe vide : les deux clés sont absentes → 0, sans erreur (décodage
// tolérant, pas de nil-panic sur les slices absentes).
func TestParseM365Inventory_EmptyEnvelope(t *testing.T) {
	got, err := ParseM365Inventory([]byte(`{}`))
	if err != nil {
		t.Fatalf("erreur inattendue sur enveloppe vide : %v", err)
	}
	if got != 0 {
		t.Fatalf("serviceCount = %d, attendu 0", got)
	}
}

// Clés présentes mais listes vides → 0, sans erreur.
func TestParseM365Inventory_EmptyValues(t *testing.T) {
	got, err := ParseM365Inventory([]byte(`{"subscribed_skus":{"value":[]},"domains":{"value":[]}}`))
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if got != 0 {
		t.Fatalf("serviceCount = %d, attendu 0", got)
	}
}

// JSON syntaxiquement invalide : SEULE cause d'erreur.
func TestParseM365Inventory_InvalidJSON(t *testing.T) {
	if _, err := ParseM365Inventory([]byte(`{ this is not json `)); err == nil {
		t.Fatal("attendu une erreur pour un JSON invalide, obtenu nil")
	}
}

// Tolérance : un SKU sans capabilityStatus et un domaine sans isVerified ne sont
// PAS comptés (champ absent ≠ actif/vérifié). Ici seul le SKU Enabled compte → 1.
func TestParseM365Inventory_MissingFieldsNotCounted(t *testing.T) {
	envelope := []byte(`{
		"subscribed_skus": { "value": [
			{"skuId":"a","skuPartNumber":"ENTERPRISEPACK","capabilityStatus":"Enabled"},
			{"skuId":"b","skuPartNumber":"NO_STATUS"}
		] },
		"domains": { "value": [
			{"id":"contoso.com"}
		] }
	}`)

	got, err := ParseM365Inventory(envelope)
	if err != nil {
		t.Fatalf("erreur inattendue : %v", err)
	}
	if got != 1 {
		t.Fatalf("serviceCount = %d, attendu 1 (champs absents non comptés)", got)
	}
}
