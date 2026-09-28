package controls

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// Tests issus de la validation réelle sur Windows 11 25H2 fr-BE (28/09/2026).
// Chaque cas reprend une sortie constatée sur la machine de validation.

func TestIsBlockAction_NotConfiguredEstBloquant(t *testing.T) {
	// Windows d'origine : DefaultInboundAction « NotConfigured » (0) = défaut
	// Windows, c'est-à-dire bloquer. L'ancienne version le classait « autoriser ».
	for _, v := range []any{"Block", "NotConfigured", float64(4), float64(0)} {
		if !isBlockAction(v) {
			t.Errorf("isBlockAction(%v) = false, attendu true", v)
		}
	}
	for _, v := range []any{"Allow", float64(2), nil} {
		if isBlockAction(v) {
			t.Errorf("isBlockAction(%v) = true, attendu false", v)
		}
	}
}

func TestFirewallWindowsNormalizer_SortieRegistre(t *testing.T) {
	// Sortie de la sonde registre (compte non administrateur), constatée.
	raw := `[ { "Name": "Domain", "Enabled": true, "DefaultInboundAction": "Block" }, { "Name": "Private", "Enabled": true, "DefaultInboundAction": "Block" }, { "Name": "Public", "Enabled": true, "DefaultInboundAction": "Block" } ]`
	out, err := FirewallWindowsNormalizer([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	var ev FirewallEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.Enabled || ev.ProfilesEnabled != 3 || !ev.DefaultInboundDeny {
		t.Fatalf("pare-feu mal interprété : %+v", ev)
	}
}

func TestPatchWindowsNormalizer_AncienneteSansNombreEnAttente(t *testing.T) {
	// L'API Windows Update refuse la session WinRM : seule l'ancienneté du
	// dernier correctif OS installé (journal System) est connue.
	out, err := PatchWindowsNormalizer([]byte(`{ "pending": null, "auto": true, "days_since_last_install": 3 }`))
	if err != nil {
		t.Fatal(err)
	}
	var ev PatchEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.PendingUnknown || ev.DaysSinceLastUpdate != 3 || !ev.AutoUpdateEnabled {
		t.Fatalf("preuve mal normalisée : %+v", ev)
	}
	ha := evaluatePatch(assess.HostRef{ID: "W"}, ev)
	if ha.ProposedImplLevel != cyfun.Defined || ha.Findings[0].Status != assess.StatusPass {
		t.Fatalf("à jour sans nombre en attente : attendu Defined/pass, obtenu %v/%s", ha.ProposedImplLevel, ha.Findings[0].Status)
	}
	if !strings.Contains(ha.Findings[0].Message, "non mesurables") {
		t.Errorf("le message doit dire que les correctifs en attente ne sont pas mesurés : %q", ha.Findings[0].Message)
	}

	old := evaluatePatch(assess.HostRef{ID: "W"}, PatchEvidence{PendingUnknown: true, DaysSinceLastUpdate: 90, AutoUpdateEnabled: true})
	if old.ProposedImplLevel != cyfun.Initial || old.Findings[0].Status != assess.StatusFail {
		t.Fatalf("correctif de 90 j : attendu Initial/fail, obtenu %v", old.ProposedImplLevel)
	}
	noAuto := evaluatePatch(assess.HostRef{ID: "W"}, PatchEvidence{PendingUnknown: true, DaysSinceLastUpdate: 5})
	if noAuto.ProposedImplLevel != cyfun.Repeatable {
		t.Fatalf("mises à jour automatiques désactivées : attendu Repeatable, obtenu %v", noAuto.ProposedImplLevel)
	}
}

func TestPatchWindowsNormalizer_AucuneMesureRejetee(t *testing.T) {
	// Ni nombre en attente, ni installation journalisée : pas de conclusion.
	if _, err := PatchWindowsNormalizer([]byte(`{ "pending": null, "auto": true, "days_since_last_install": null }`)); err == nil {
		t.Fatal("une preuve sans aucune mesure doit être rejetée")
	}
}

func TestEvalVuln_NombreEnAttenteInconnu(t *testing.T) {
	ha := evalVuln(assess.HostRef{ID: "W"}, PatchEvidence{PendingUnknown: true, DaysSinceLastUpdate: 0}, "ID.RA-01.6")
	if ha.ProposedImplLevel != cyfun.Repeatable {
		t.Fatalf("attendu Repeatable (processus à attester, en attente inconnu), obtenu %v", ha.ProposedImplLevel)
	}
}

func TestAntivirusWindowsNormalizer_SourcesNonAdmin(t *testing.T) {
	// Sortie registre de la sonde Defender (compte non administrateur), constatée.
	out, err := AntivirusWindowsNormalizer([]byte(`{ "AntivirusEnabled": true, "RealTimeProtectionEnabled": true, "AntivirusSignatureAge": 0, "Product": "Microsoft Defender" }`))
	if err != nil {
		t.Fatal(err)
	}
	var ev AntivirusEvidence
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.DefinitionsAgeUnknown || ev.Product != "Microsoft Defender" || !ev.RealtimeProtection {
		t.Fatalf("Defender mal normalisé : %+v", ev)
	}

	// Produit tiers repéré par son service : âge des définitions inconnu, jamais « 0 j ».
	out, err = AntivirusWindowsNormalizer([]byte(`{ "AntivirusEnabled": true, "RealTimeProtectionEnabled": true, "AntivirusSignatureAge": null, "Product": "ekrn" }`))
	if err != nil {
		t.Fatal(err)
	}
	ev = AntivirusEvidence{}
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	if !ev.DefinitionsAgeUnknown || ev.Product != "ekrn" {
		t.Fatalf("produit tiers mal normalisé : %+v", ev)
	}
	ha := evaluateAntivirus(assess.HostRef{ID: "W"}, ev)
	if ha.ProposedImplLevel != cyfun.Defined {
		t.Fatalf("âge inconnu : attendu Defined (plafond), obtenu %v", ha.ProposedImplLevel)
	}
}

func TestTimeSyncWindowsNormalizer_RefusNestPasUneSource(t *testing.T) {
	// Sortie réelle de w32tm pour un compte non administrateur : elle contient un
	// point, l'ancienne version concluait « synchronisée sur L'erreur… ».
	raw := `{ "source": "L'erreur suivante s'est produite : Accès refusé. (0x80070005)" }`
	if _, err := TimeSyncWindowsNormalizer([]byte(raw)); err == nil {
		t.Fatal("un message d'erreur w32tm ne doit jamais être pris pour une source de temps")
	}
	out, err := TimeSyncWindowsNormalizer([]byte(`{ "source": "Local CMOS Clock" }`))
	if err != nil {
		t.Fatal(err)
	}
	var ev TimeSyncEvidence
	_ = json.Unmarshal(out, &ev)
	if ev.Synchronized {
		t.Fatal("Local CMOS Clock n'est pas une source externe")
	}
}

// Les sondes qui interrogent une source susceptible d'être refusée à un compte
// non administrateur doivent embarquer le préambule WinPre (fonction F), qui
// transforme un refus en « ACCESS DENIED » au lieu d'une fausse conclusion.
func TestSondesWindows_RefusJamaisSilencieux(t *testing.T) {
	sondes := map[string]string{
		"EDR": DECM0301WinCmd, "FIM": FimWinCmd, "scanner": VulnScannerWinCmd,
		"sauvegarde": PRDS1101WinCmd, "SIEM": LogMgmtWinCmd, "journalisation": DEAE0301WinCmd,
		"capacité": CapacityWinCmd, "matériel": HardwareWinCmd, "domaine": DomainWinCmd,
		"heure": TimeSyncWinCmd, "démarrage": BootDeviceWinCmd, "chiffrement": EncryptionWinCmd,
		"allowlisting": AppControlWinCmd, "comptes": PRAA0501WinCmd, "proxy": PRPS0501WinCmd,
		"identifiants": PRAA0101WinCmd,
	}
	for nom, s := range sondes {
		if !strings.HasPrefix(s, WinPre) {
			t.Errorf("sonde %s : préambule WinPre absent", nom)
		}
		// Motifs qui masquaient un refus et produisaient une fausse conclusion.
		for _, motif := range []string{"Get-Service 2>$null", "Confirm-SecureBootUEFI}catch{}", "-ErrorAction SilentlyContinue).ProtectionStatus", "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" -ErrorAction SilentlyContinue"} {
			if strings.Contains(s, motif) {
				t.Errorf("sonde %s : motif silencieux %q", nom, motif)
			}
		}
	}
}
