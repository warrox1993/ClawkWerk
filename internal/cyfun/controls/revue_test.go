package controls

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
)

// Corrections issues de la revue indépendante du 28/09/2026 : une valeur non
// mesurée ne doit jamais devenir une conclusion.

var hr = assess.HostRef{ID: "H"}

func TestRevue_RetentionBorneInferieure(t *testing.T) {
	// Windows : journal non plein → 20 j est une borne inférieure, pas « trop court ».
	out, err := LoggingWindowsNormalizer([]byte(`{"enabled":true,"retention_days":20,"retention_is_lower_bound":true,"forwarding":false}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	_ = json.Unmarshal(out, &ev)
	ha := evaluateLogging(hr, ev)
	if ha.ProposedImplLevel != cyfun.Defined || !strings.Contains(ha.Findings[0].Message, "au moins 20 j") {
		t.Fatalf("borne inférieure : %v %q", ha.ProposedImplLevel, ha.Findings[0].Message)
	}
	// Journal plein et circulaire : 20 j est la vraie durée → trop court.
	out, _ = LoggingWindowsNormalizer([]byte(`{"enabled":true,"retention_days":20,"retention_is_lower_bound":false,"forwarding":false}`))
	ev = LoggingEvidence{}
	_ = json.Unmarshal(out, &ev)
	if ha := evaluateLogging(hr, ev); ha.ProposedImplLevel != cyfun.Repeatable {
		t.Fatalf("journal plein : Repeatable attendu, obtenu %v", ha.ProposedImplLevel)
	}
}

func TestRevue_JournalFullLinux(t *testing.T) {
	cases := map[string]bool{
		"usage=3.9G max=auto fs_kb=100000000": true,  // 10 % de 95 Gio > 4 Gio → plafond 4 Gio
		"usage=1.0G max=auto fs_kb=100000000": false, // loin du plafond
		"usage=480M max=500M fs_kb=?":         true,  // SystemMaxUse explicite
		"usage=? max=auto fs_kb=?":            false, // illisible → borne inférieure
		"":                                    false,
	}
	for line, want := range cases {
		if got := journalFull(line); got != want {
			t.Errorf("journalFull(%q) = %v, attendu %v", line, got, want)
		}
	}
	out, err := LoggingLinuxNormalizer([]byte("active\n12\nno\nusage=100M max=auto fs_kb=100000000\n"))
	if err != nil {
		t.Fatal(err)
	}
	var ev LoggingEvidence
	_ = json.Unmarshal(out, &ev)
	if !ev.RetentionLowerBound {
		t.Fatal("journal non plein : rétention = borne inférieure")
	}
}

func TestRevue_CorrectifsAucunKBSurLaPeriode(t *testing.T) {
	// Aucun correctif OS sur 75 j de journal : ancienneté > 60 j → en retard.
	out, err := PatchWindowsNormalizer([]byte(`{"pending":null,"auto":true,"days_since_last_install":null,"no_os_update_for_days":75}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev PatchEvidence
	_ = json.Unmarshal(out, &ev)
	if ha := evaluatePatch(hr, ev); ha.ProposedImplLevel != cyfun.Initial {
		t.Fatalf("75 j sans correctif OS : Initial attendu, obtenu %v", ha.ProposedImplLevel)
	}
	// Journal trop court (20 j) pour conclure : non mesurable.
	if _, err := PatchWindowsNormalizer([]byte(`{"pending":null,"auto":true,"days_since_last_install":null,"no_os_update_for_days":20}`)); err == nil {
		t.Fatal("20 j de journal sans correctif : pas de conclusion possible")
	}
}

func TestRevue_AntivirusTiersTempsReelInconnu(t *testing.T) {
	out, err := AntivirusWindowsNormalizer([]byte(`{"AntivirusEnabled":true,"RealTimeProtectionEnabled":null,"AntivirusSignatureAge":null,"Product":"SophosFS"}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev AntivirusEvidence
	_ = json.Unmarshal(out, &ev)
	ha := evaluateAntivirus(hr, ev)
	if ha.ProposedImplLevel != cyfun.Defined || !ev.RealtimeUnknown {
		t.Fatalf("temps réel illisible : Defined attendu (jamais « désactivé »), obtenu %v / %+v", ha.ProposedImplLevel, ev)
	}
	// Agent tiers installé mais arrêté : présent et désactivé.
	out, _ = AntivirusWindowsNormalizer([]byte(`{"AntivirusEnabled":false,"RealTimeProtectionEnabled":false,"AntivirusSignatureAge":null,"Product":"SophosFS"}`))
	ev = AntivirusEvidence{}
	_ = json.Unmarshal(out, &ev)
	if ha := evaluateAntivirus(hr, ev); ha.ProposedImplLevel != cyfun.Initial {
		t.Fatalf("agent arrêté : Initial attendu, obtenu %v", ha.ProposedImplLevel)
	}
}

func TestRevue_ChiffrementParControle(t *testing.T) {
	// BitLocker refusé : PR.DS-01.6 en « droits insuffisants », PR.DS-02.x évalués.
	raw := []byte(`{"at_rest_enabled":null,"at_rest_denied":"BitLocker (Win32_EncryptableVolume, reserve aux administrateurs)","in_transit_enforced":true,"removable_encrypted":false}`)
	if _, err := EncryptionWindowsNormalizerFor("at_rest")(raw); err == nil || !strings.Contains(err.Error(), "droits insuffisants") {
		t.Fatalf("au repos : « droits insuffisants » attendu, obtenu %v", err)
	}
	for _, axis := range []string{"in_transit", "removable"} {
		if _, err := EncryptionWindowsNormalizerFor(axis)(raw); err != nil {
			t.Fatalf("%s doit rester évalué : %v", axis, err)
		}
	}
	// Module BitLocker absent : pas de « non chiffré ».
	if _, err := EncryptionWindowsNormalizerFor("at_rest")([]byte(`{"at_rest_enabled":null,"in_transit_enforced":true,"removable_encrypted":false}`)); err == nil {
		t.Fatal("module BitLocker absent : pas de conclusion au repos")
	}
	// Linux : supports amovibles non mesurables → non évalué.
	lin, _ := EncryptionLinuxNormalizer([]byte("no\nunknown\nunknown\n"))
	if ha := (RemovableEncryptionEvaluator{}).Evaluate(assess.RawEvidence{Host: hr, Data: lin}); ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Fatalf("amovibles Linux : non évalué attendu, obtenu %v", ha.ProposedImplLevel)
	}
}

func TestRevue_PlanificationSauvegardeInconnue(t *testing.T) {
	out, err := BackupWindowsNormalizer([]byte(`{"solution_present":true,"scheduled_job":null,"offsite_configured":null}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev BackupEvidence
	_ = json.Unmarshal(out, &ev)
	if !ev.ScheduledUnknown {
		t.Fatal("planification illisible doit être marquée inconnue")
	}
	if ha := evaluateBackup(hr, ev); ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Fatalf("PR.DS-11.1 : non évalué attendu, obtenu %v", ha.ProposedImplLevel)
	}
	lin, _ := BackupLinuxNormalizer([]byte("yes\nunknown\nno\n"))
	if ha := (BackupTested1102Evaluator{}).Evaluate(assess.RawEvidence{Host: hr, Data: lin}); ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Fatalf("PR.DS-11.2 : non évalué attendu, obtenu %v", ha.ProposedImplLevel)
	}
}

func TestRevue_ComptesWMISansDerniereConnexion(t *testing.T) {
	out, err := AccessReviewWindowsNormalizer([]byte(`{"inactive_accounts":null,"total_local_accounts":4}`))
	if err != nil {
		t.Fatal(err)
	}
	var ev AccessReviewEvidence
	_ = json.Unmarshal(out, &ev)
	if ha := evaluateAccessReview(hr, ev); ha.ProposedImplLevel != cyfun.Repeatable || !ev.InactiveUnknown {
		t.Fatalf("repli WMI : dormance inconnue attendue, obtenu %v / %+v", ha.ProposedImplLevel, ev)
	}
}

func TestRevue_HorlogeEtSecureBoot(t *testing.T) {
	for src, want := range map[string]bool{"service W32Time arrete": false, "VM IC Time Synchronization Provider": true, "time.windows.com,0x9": true} {
		out, err := TimeSyncWindowsNormalizer([]byte(`{"source":"` + src + `"}`))
		if err != nil {
			t.Fatal(err)
		}
		var ev TimeSyncEvidence
		_ = json.Unmarshal(out, &ev)
		if ev.Synchronized != want {
			t.Errorf("source %q : synchronisé=%v, attendu %v", src, ev.Synchronized, want)
		}
	}
	boot, _ := BootDeviceLinuxNormalizer([]byte("unknown\nno\nunknown\n"))
	if ha := (BootIntegrityEvaluator{}).Evaluate(assess.RawEvidence{Host: hr, Data: boot}); ha.ProposedImplLevel != cyfun.NotAssessed {
		t.Fatalf("Secure Boot illisible : non évalué attendu, obtenu %v", ha.ProposedImplLevel)
	}
}

func TestRevue_WinPreEtServices(t *testing.T) {
	for _, m := range []string{"UnauthorizedAccess", "SecurityException", "2147217405", "not allowed", "niet toegestaan"} {
		if !strings.Contains(WinPre, m) {
			t.Errorf("WinPre : marqueur de refus %q absent", m)
		}
	}
	if !strings.Contains(WinAutoServices, "Get-Service -Name") || !strings.Contains(WinAutoServices, "$X+=") {
		t.Error("WinAutoServices doit vérifier que le service tourne et isoler les services arrêtés")
	}
}

// F elle-même ne doit jamais échouer (sinon la sonde continue avec des valeurs
// par défaut) : introspection de l'exception protégée, InnerException testée
// avant usage. Comportement vérifié sur Windows 11 le 28/09/2026 (refus CIM →
// « ACCESS DENIED », autre erreur → code 1, exception sans InnerException → code 1).
func TestRevue_FInfaillible(t *testing.T) {
	if !strings.Contains(WinPre, `try{$x=$e.Exception;`) || !strings.Contains(WinPre, `if($i){`) || strings.Contains(WinPre, "InnerException.GetType()") {
		t.Fatal("WinPre : F doit protéger l'introspection de l'exception")
	}
}
