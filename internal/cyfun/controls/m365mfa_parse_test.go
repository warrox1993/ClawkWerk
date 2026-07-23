package controls

import "testing"

// Fixtures fidèles au schéma Microsoft Graph réel (GET seulement).

// Security Defaults activé : la MFA est imposée globalement, sans aucune
// politique d'accès conditionnel.
const fxSecurityDefaultsOn = `{
  "security_defaults": { "isEnabled": true },
  "conditional_access": { "value": [] }
}`

// Politique d'accès conditionnel active exigeant la MFA pour "All".
const fxCAMfaAll = `{
  "security_defaults": { "isEnabled": false },
  "conditional_access": { "value": [
    {
      "state": "enabled",
      "conditions": {
        "users": { "includeUsers": ["All"] },
        "clientAppTypes": ["all"]
      },
      "grantControls": { "operator": "OR", "builtInControls": ["mfa"] }
    }
  ] }
}`

// Politique correcte sur le fond mais désactivée -> n'enforce rien.
const fxCADisabled = `{
  "security_defaults": { "isEnabled": false },
  "conditional_access": { "value": [
    {
      "state": "disabled",
      "conditions": {
        "users": { "includeUsers": ["All"] },
        "clientAppTypes": ["all"]
      },
      "grantControls": { "operator": "OR", "builtInControls": ["mfa"] }
    }
  ] }
}`

// Politique active mais ciblant un seul utilisateur (pas "All") -> n'enforce pas
// au sens du contrôle (qui exige la couverture de tous les utilisateurs).
const fxCASingleUser = `{
  "security_defaults": { "isEnabled": false },
  "conditional_access": { "value": [
    {
      "state": "enabled",
      "conditions": {
        "users": { "includeUsers": ["8f14e45f-ceea-467d-9a1e-1c1c1c1c1c1c"] },
        "clientAppTypes": ["all"]
      },
      "grantControls": { "operator": "OR", "builtInControls": ["mfa"] }
    }
  ] }
}`

// Mode audit : "enabledForReportingButNotEnforced" ne bloque personne.
const fxCAReportOnly = `{
  "security_defaults": { "isEnabled": false },
  "conditional_access": { "value": [
    {
      "state": "enabledForReportingButNotEnforced",
      "conditions": {
        "users": { "includeUsers": ["All"] },
        "clientAppTypes": ["all"]
      },
      "grantControls": { "operator": "OR", "builtInControls": ["mfa"] }
    }
  ] }
}`

// Politique bloquant l'authentification héritée (ActiveSync + "other" -> block).
const fxCALegacyBlock = `{
  "security_defaults": { "isEnabled": false },
  "conditional_access": { "value": [
    {
      "state": "enabled",
      "conditions": {
        "users": { "includeUsers": ["All"] },
        "clientAppTypes": ["exchangeActiveSync", "other"]
      },
      "grantControls": { "operator": "OR", "builtInControls": ["block"] }
    }
  ] }
}`

// Tenant nu : rien d'activé, aucune politique.
const fxEmptyTenant = `{
  "security_defaults": { "isEnabled": false },
  "conditional_access": { "value": [] }
}`

// Enveloppe où les deux clés sont absentes : doit rester false, sans erreur.
const fxNoKeys = `{}`

const fxInvalidJSON = `{ "security_defaults": ` // tronqué volontairement

func TestParseM365MFA(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantMFA    bool
		wantLegacy bool
		wantErr    bool
	}{
		{"security defaults on -> mfa", fxSecurityDefaultsOn, true, false, false},
		{"CA mfa for All -> mfa", fxCAMfaAll, true, false, false},
		{"CA disabled -> pas d'enforce", fxCADisabled, false, false, false},
		{"CA single user -> pas d'enforce", fxCASingleUser, false, false, false},
		{"CA report-only -> pas d'enforce", fxCAReportOnly, false, false, false},
		{"CA legacy block -> legacyBlocked", fxCALegacyBlock, false, true, false},
		{"tenant nu -> both false", fxEmptyTenant, false, false, false},
		{"cles absentes -> both false", fxNoKeys, false, false, false},
		{"JSON invalide -> erreur", fxInvalidJSON, false, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mfa, legacy, err := ParseM365MFA([]byte(tc.in))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("attendu une erreur, obtenu nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("erreur inattendue: %v", err)
			}
			if mfa != tc.wantMFA {
				t.Errorf("mfaEnforced = %v, attendu %v", mfa, tc.wantMFA)
			}
			if legacy != tc.wantLegacy {
				t.Errorf("legacyBlocked = %v, attendu %v", legacy, tc.wantLegacy)
			}
		})
	}
}

// Une enveloppe qui prouve les DEUX preuves à la fois (MFA globale via Security
// Defaults + blocage legacy via CA) doit rendre les deux booléens vrais.
func TestParseM365MFA_bothProofs(t *testing.T) {
	const combined = `{
      "security_defaults": { "isEnabled": true },
      "conditional_access": { "value": [
        {
          "state": "enabled",
          "conditions": {
            "users": { "includeUsers": ["All"] },
            "clientAppTypes": ["exchangeActiveSync"]
          },
          "grantControls": { "operator": "OR", "builtInControls": ["block"] }
        }
      ] }
    }`
	mfa, legacy, err := ParseM365MFA([]byte(combined))
	if err != nil {
		t.Fatalf("erreur inattendue: %v", err)
	}
	if !mfa || !legacy {
		t.Errorf("attendu mfa=true legacy=true, obtenu mfa=%v legacy=%v", mfa, legacy)
	}
}

// Robustesse : une valeur inattendue (ex. clientAppTypes reçu comme objet au
// lieu d'un tableau) doit produire une erreur de décodage propre, jamais une
// panique.
func TestParseM365MFA_noPanicOnUnexpectedShape(t *testing.T) {
	const weird = `{ "conditional_access": { "value": [ { "conditions": { "clientAppTypes": {} } } ] } }`
	mfa, legacy, err := ParseM365MFA([]byte(weird))
	if err == nil {
		// Selon la forme, json peut soit refuser (type mismatch) soit tolérer ;
		// dans les deux cas on exige l'absence de panique et des booléens sûrs.
		if mfa || legacy {
			t.Errorf("forme imprévue: attendu false/false, obtenu mfa=%v legacy=%v", mfa, legacy)
		}
	}
}
