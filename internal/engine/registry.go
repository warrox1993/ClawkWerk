package engine

import (
	"time"

	"github.com/warrox1993/clawkwerk/internal/assess"
	"github.com/warrox1993/clawkwerk/internal/cyfun"
	"github.com/warrox1993/clawkwerk/internal/cyfun/controls"
	"github.com/warrox1993/clawkwerk/internal/scan"
	"github.com/warrox1993/clawkwerk/internal/survey"
)

// ControlsForLevel renvoie le jeu de contrôles à auditer pour un NIVEAU
// d'assurance (Basic ou Important). Basic = les 34 contrôles ; Important =
// Basic + les 99 contrôles IMPORTANT supplémentaires (Important est un
// sur-ensemble de Basic). Les 7 contrôles scannables Basic s'appliquent aussi
// à Important.
func ControlsForLevel(level string) []Control { return controlsForLevel(time.Now, level) }

func controlsForLevel(now func() time.Time, level string) []Control {
	ctrls := ControlsWithClock(now) // socle Basic (scannables + déclaratifs)
	if cyfun.AppliesAt(cyfun.LevelImportant, level) {
		ctrls = append(ctrls, ImportantScannables(now)...) // contrôles Important promus scannables
		for _, d := range controls.ImportantControls {
			ctrls = append(ctrls, Control{Meta: d.Meta, Questions: d.Questions})
		}
	}
	if cyfun.AppliesAt(cyfun.LevelEssential, level) {
		ctrls = append(ctrls, EssentialScannables(now)...) // contrôles Essential promus scannables
		for _, d := range controls.EssentialControls {
			ctrls = append(ctrls, Control{Meta: d.Meta, Questions: d.Questions})
		}
	}
	return ctrls
}

// reuseControl construit un contrôle SCANNABLE réutilisant une sonde EXISTANTE
// (modèle « sonde de famille ») : commandes + normaliseurs d'une sonde déjà écrite,
// un Evaluator propre au contrôle + sa question Documentation + le repli
// d'Implementation. Une collecte, plusieurs contrôles à des niveaux différents.
func reuseControl(meta cyfun.ControlMeta, eval assess.Evaluator, winCmd, linuxCmd string, winNorm, linuxNorm assess.NormalizeFunc, questions []survey.Question) Control {
	q := append(append([]survey.Question{}, questions...), implFallbackQuestion(meta.ID))
	return Control{
		Meta:      meta,
		Evaluator: eval,
		Commands: map[string]scan.CollectCommand{
			"windows": scan.ReadOnlyCommand(meta.ID, "windows", winCmd),
			"linux":   scan.ReadOnlyCommand(meta.ID, "linux", linuxCmd),
		},
		Normalizers: map[string]assess.NormalizeFunc{"windows": winNorm, "linux": linuxNorm},
		Questions:   q,
	}
}

// ImportantScannables = contrôles propres au niveau Important PROMUS scannables
// (retirés du catalogue déclaratif), chacun réutilisant une sonde existante.
func ImportantScannables(now func() time.Time) []Control {
	return []Control{
		// durcissement-config (sonde Hardening)
		reuseControl(controls.PRPS0101Meta, controls.BaselineHardeningEvaluator{}, controls.PRAA0503WinCmd, controls.PRAA0503LinuxCmd, controls.HardeningWindowsNormalizer, controls.HardeningLinuxNormalizer, controls.PRPS0101Questions),
		// identites-acces / accès distant (sonde RemoteMFA)
		reuseControl(controls.PRAA0303Meta, controls.RemoteMFA0303Evaluator{}, controls.PRAA0302WinCmd, controls.PRAA0302LinuxCmd, controls.RemoteMFAWindowsNormalizer, controls.RemoteMFALinuxNormalizer, controls.PRAA0303Questions),
		reuseControl(controls.IDAM0812Meta, controls.RemoteMaint0812Evaluator{}, controls.PRAA0302WinCmd, controls.PRAA0302LinuxCmd, controls.RemoteMFAWindowsNormalizer, controls.RemoteMFALinuxNormalizer, controls.IDAM0812Questions),
		// privilèges (sonde LocalAdmin — commandes registre psLocalAdmins/shLocalAdmins)
		reuseControl(controls.PRAA0507Meta, controls.PrivAccounts0507Evaluator{}, psLocalAdmins, shLocalAdmins, controls.LocalAdminWindowsNormalizer, controls.LocalAdminLinuxNormalizer, controls.PRAA0507Questions),
		// gestion-actifs / inventaire logiciel (sonde SoftwareInventory)
		reuseControl(controls.SwInv0202Meta, controls.SwInv0202Evaluator{}, controls.IDAM0201WinCmd, controls.IDAM0201LinuxCmd, controls.SoftwareInventoryWindowsNormalizer, controls.SoftwareInventoryLinuxNormalizer, controls.SwInv0202Questions),
		reuseControl(controls.SwInv0204Meta, controls.SwInv0204Evaluator{}, controls.IDAM0201WinCmd, controls.IDAM0201LinuxCmd, controls.SoftwareInventoryWindowsNormalizer, controls.SoftwareInventoryLinuxNormalizer, controls.SwInv0204Questions),
		// sauvegardes (sonde Backup)
		reuseControl(controls.PRDS1102Meta, controls.BackupTested1102Evaluator{}, controls.PRDS1101WinCmd, controls.PRDS1101LinuxCmd, controls.BackupWindowsNormalizer, controls.BackupLinuxNormalizer, controls.PRDS1102Questions),
		reuseControl(controls.PRDS1103Meta, controls.BackupOffsite1103Evaluator{}, controls.PRDS1101WinCmd, controls.PRDS1101LinuxCmd, controls.BackupWindowsNormalizer, controls.BackupLinuxNormalizer, controls.PRDS1103Questions),
		// protection-endpoint (sonde EndpointMonitor)
		reuseControl(controls.DECM0302Meta, controls.Edr0302Evaluator{}, controls.DECM0301WinCmd, controls.DECM0301LinuxCmd, controls.EndpointMonitorWindowsNormalizer, controls.EndpointMonitorLinuxNormalizer, controls.DECM0302Questions),
		// vulnérabilités (sonde Patch — commandes registre ; normaliseur Linux horloge)
		reuseControl(controls.IDRA0102Meta, controls.Vuln0102Evaluator{}, psPendingUpdates, shPendingUpdates, controls.PatchWindowsNormalizer, controls.PatchLinuxNormalizer(now), controls.IDRA0102Questions),
		reuseControl(controls.IDRA0106Meta, controls.Vuln0106Evaluator{}, psPendingUpdates, shPendingUpdates, controls.PatchWindowsNormalizer, controls.PatchLinuxNormalizer(now), controls.IDRA0106Questions),
		// contrôle applicatif / allowlisting (sonde AppControl)
		reuseControl(controls.PRPS0201Meta, controls.SoftwareRestrictionEvaluator{}, controls.AppControlWinCmd, controls.AppControlLinuxCmd, controls.AppControlWindowsNormalizer, controls.AppControlLinuxNormalizer, controls.PRPS0201Questions),
		reuseControl(controls.PRPS0502Meta, controls.UnauthorisedSoftwareEvaluator{}, controls.AppControlWinCmd, controls.AppControlLinuxCmd, controls.AppControlWindowsNormalizer, controls.AppControlLinuxNormalizer, controls.PRPS0502Questions),
		// média amovible & démarrage sécurisé (sonde BootDevice)
		reuseControl(controls.PRDS0101Meta, controls.BootIntegrityEvaluator{}, controls.BootDeviceWinCmd, controls.BootDeviceLinuxCmd, controls.BootDeviceWindowsNormalizer, controls.BootDeviceLinuxNormalizer, controls.PRDS0101Questions),
		reuseControl(controls.PRDS0104Meta, controls.RemovableMediaEvaluator{}, controls.BootDeviceWinCmd, controls.BootDeviceLinuxCmd, controls.BootDeviceWindowsNormalizer, controls.BootDeviceLinuxNormalizer, controls.PRDS0104Questions),
		reuseControl(controls.PRDS0105Meta, controls.AutorunEvaluator{}, controls.BootDeviceWinCmd, controls.BootDeviceLinuxCmd, controls.BootDeviceWindowsNormalizer, controls.BootDeviceLinuxNormalizer, controls.PRDS0105Questions),
		// synchronisation de temps (sonde TimeSync)
		reuseControl(controls.PRPS0402Meta, controls.TimeSyncEvaluator{}, controls.TimeSyncWinCmd, controls.TimeSyncLinuxCmd, controls.TimeSyncWindowsNormalizer, controls.TimeSyncLinuxNormalizer, controls.PRPS0402Questions),
		// journalisation / SIEM (sonde LogMgmt)
		reuseControl(controls.DECM0103Meta, controls.LogConn0103Evaluator{}, controls.LogMgmtWinCmd, controls.LogMgmtLinuxCmd, controls.LogMgmtWindowsNormalizer, controls.LogMgmtLinuxNormalizer, controls.DECM0103Questions),
		reuseControl(controls.PRPS0403Meta, controls.LogForward0403Evaluator{}, controls.LogMgmtWinCmd, controls.LogMgmtLinuxCmd, controls.LogMgmtWindowsNormalizer, controls.LogMgmtLinuxNormalizer, controls.PRPS0403Questions),
		reuseControl(controls.DECM0901Meta, controls.LogMonitor0901Evaluator{}, controls.LogMgmtWinCmd, controls.LogMgmtLinuxCmd, controls.LogMgmtWindowsNormalizer, controls.LogMgmtLinuxNormalizer, controls.DECM0901Questions),
		reuseControl(controls.DEAE0201Meta, controls.LogAnalysis0201Evaluator{}, controls.LogMgmtWinCmd, controls.LogMgmtLinuxCmd, controls.LogMgmtWindowsNormalizer, controls.LogMgmtLinuxNormalizer, controls.DEAE0201Questions),
		reuseControl(controls.DEAE0302Meta, controls.LogCorrelate0302Evaluator{}, controls.LogMgmtWinCmd, controls.LogMgmtLinuxCmd, controls.LogMgmtWindowsNormalizer, controls.LogMgmtLinuxNormalizer, controls.DEAE0302Questions),
		// détection aux frontières (sonde EndpointMonitor)
		reuseControl(controls.RSMI0102Meta, controls.BoundaryDetect0102Evaluator{}, controls.DECM0301WinCmd, controls.DECM0301LinuxCmd, controls.EndpointMonitorWindowsNormalizer, controls.EndpointMonitorLinuxNormalizer, controls.RSMI0102Questions),
		// annuaire centralisé / gestion automatisée des comptes (sonde Domain)
		reuseControl(controls.PRAA0102Meta, controls.Directory0102Evaluator{}, controls.DomainWinCmd, controls.DomainLinuxCmd, controls.DomainWindowsNormalizer, controls.DomainLinuxNormalizer, controls.PRAA0102Questions),
		reuseControl(controls.PRAA0505Meta, controls.Directory0505Evaluator{}, controls.DomainWinCmd, controls.DomainLinuxCmd, controls.DomainWindowsNormalizer, controls.DomainLinuxNormalizer, controls.PRAA0505Questions),
		// inventaire matériel local (sonde Hardware)
		reuseControl(controls.IDAM0102Meta, controls.HwInv0102Evaluator{}, controls.HardwareWinCmd, controls.HardwareLinuxCmd, controls.HardwareWindowsNormalizer, controls.HardwareLinuxNormalizer, controls.IDAM0102Questions),
		reuseControl(controls.IDAM0103Meta, controls.HwInv0103Evaluator{}, controls.HardwareWinCmd, controls.HardwareLinuxCmd, controls.HardwareWindowsNormalizer, controls.HardwareLinuxNormalizer, controls.IDAM0103Questions),
		// capacité/ressources (sonde Capacity)
		reuseControl(controls.PRIR0401Meta, controls.CapacityEvaluator{}, controls.CapacityWinCmd, controls.CapacityLinuxCmd, controls.CapacityWindowsNormalizer, controls.CapacityLinuxNormalizer, controls.PRIR0401Questions),
	}
}

// EssentialScannables = contrôles propres au niveau Essential PROMUS scannables.
func EssentialScannables(now func() time.Time) []Control {
	_ = now // réservé (certaines sondes futures dépendent de l'horloge)
	return []Control{
		// durcissement-config (sonde Hardening)
		reuseControl(controls.PRPS0103Meta, controls.PortHardeningEvaluator{}, controls.PRAA0503WinCmd, controls.PRAA0503LinuxCmd, controls.HardeningWindowsNormalizer, controls.HardeningLinuxNormalizer, controls.PRPS0103Questions),
		reuseControl(controls.PRPS0102Meta, controls.EssentialFunctionsEvaluator{}, controls.PRAA0503WinCmd, controls.PRAA0503LinuxCmd, controls.HardeningWindowsNormalizer, controls.HardeningLinuxNormalizer, controls.PRPS0102Questions),
		// accès distant chiffré (sonde RemoteMFA)
		reuseControl(controls.PRAA0304Meta, controls.RemoteCrypto0304Evaluator{}, controls.PRAA0302WinCmd, controls.PRAA0302LinuxCmd, controls.RemoteMFAWindowsNormalizer, controls.RemoteMFALinuxNormalizer, controls.PRAA0304Questions),
		// privilèges audités (sonde LocalAdmin)
		reuseControl(controls.PRAA0509Meta, controls.PrivAccounts0509Evaluator{}, psLocalAdmins, shLocalAdmins, controls.LocalAdminWindowsNormalizer, controls.LocalAdminLinuxNormalizer, controls.PRAA0509Questions),
		// inventaire logiciel + allowlisting (sonde SoftwareInventory)
		reuseControl(controls.SwInv0205Meta, controls.SwInv0205Evaluator{}, controls.IDAM0201WinCmd, controls.IDAM0201LinuxCmd, controls.SoftwareInventoryWindowsNormalizer, controls.SoftwareInventoryLinuxNormalizer, controls.SwInv0205Questions),
		// anti-malware/EDR (sonde EndpointMonitor)
		reuseControl(controls.DECM0904Meta, controls.Edr0904Evaluator{}, controls.DECM0301WinCmd, controls.DECM0301LinuxCmd, controls.EndpointMonitorWindowsNormalizer, controls.EndpointMonitorLinuxNormalizer, controls.DECM0904Questions),
		// chiffrement (sonde Encryption) — au repos, en transit, supports amovibles (KM)
		reuseControl(controls.PRDS0106Meta, controls.AtRestEncryptionEvaluator{}, controls.EncryptionWinCmd, controls.EncryptionLinuxCmd, controls.EncryptionWindowsNormalizer, controls.EncryptionLinuxNormalizer, controls.PRDS0106Questions),
		reuseControl(controls.PRDS0202Meta, controls.InTransitEncryptionEvaluator{}, controls.EncryptionWinCmd, controls.EncryptionLinuxCmd, controls.EncryptionWindowsNormalizer, controls.EncryptionLinuxNormalizer, controls.PRDS0202Questions),
		reuseControl(controls.PRDS0201Meta, controls.RemovableEncryptionEvaluator{}, controls.EncryptionWinCmd, controls.EncryptionLinuxCmd, controls.EncryptionWindowsNormalizer, controls.EncryptionLinuxNormalizer, controls.PRDS0201Questions),
		// contrôle applicatif / allowlisting deny-all (sonde AppControl, SCAN pur)
		reuseControl(controls.PRPS0104Meta, controls.AllowlistingEvaluator{}, controls.AppControlWinCmd, controls.AppControlLinuxCmd, controls.AppControlWindowsNormalizer, controls.AppControlLinuxNormalizer, controls.PRPS0104Questions),
		// journalisation / SIEM (sonde LogMgmt)
		reuseControl(controls.DEAE0202Meta, controls.LogAutoAnalysis0202Evaluator{}, controls.LogMgmtWinCmd, controls.LogMgmtLinuxCmd, controls.LogMgmtWindowsNormalizer, controls.LogMgmtLinuxNormalizer, controls.DEAE0202Questions),
		reuseControl(controls.DEAE0303Meta, controls.LogCombine0303Evaluator{}, controls.LogMgmtWinCmd, controls.LogMgmtLinuxCmd, controls.LogMgmtWindowsNormalizer, controls.LogMgmtLinuxNormalizer, controls.DEAE0303Questions),
		reuseControl(controls.PRPS0404Meta, controls.LogAuditFail0404Evaluator{}, controls.LogMgmtWinCmd, controls.LogMgmtLinuxCmd, controls.LogMgmtWindowsNormalizer, controls.LogMgmtLinuxNormalizer, controls.PRPS0404Questions),
		// identités avancées (sondes AccessReview + RemoteMFA)
		reuseControl(controls.PRAA0103Meta, controls.Dormant0103Evaluator{}, controls.PRAA0501WinCmd, controls.PRAA0501LinuxCmd, controls.AccessReviewWindowsNormalizer, controls.AccessReviewLinuxNormalizer, controls.PRAA0103Questions),
		reuseControl(controls.PRAA0202Meta, controls.UniqueAccounts0202Evaluator{}, controls.PRAA0501WinCmd, controls.PRAA0501LinuxCmd, controls.AccessReviewWindowsNormalizer, controls.AccessReviewLinuxNormalizer, controls.PRAA0202Questions),
		reuseControl(controls.PRAA0104Meta, controls.AuthFactor0104Evaluator{}, controls.PRAA0302WinCmd, controls.PRAA0302LinuxCmd, controls.RemoteMFAWindowsNormalizer, controls.RemoteMFALinuxNormalizer, controls.PRAA0104Questions),
		// intégrité / FIM (sonde Fim)
		reuseControl(controls.PRDS0102Meta, controls.Fim0102Evaluator{}, controls.FimWinCmd, controls.FimLinuxCmd, controls.FimWindowsNormalizer, controls.FimLinuxNormalizer, controls.PRDS0102Questions),
		reuseControl(controls.PRDS0103Meta, controls.Fim0103Evaluator{}, controls.FimWinCmd, controls.FimLinuxCmd, controls.FimWindowsNormalizer, controls.FimLinuxNormalizer, controls.PRDS0103Questions),
		// investigation / forensic (sonde EndpointMonitor)
		reuseControl(controls.RSMA0202Meta, controls.Forensic0202Evaluator{}, controls.DECM0301WinCmd, controls.DECM0301LinuxCmd, controls.EndpointMonitorWindowsNormalizer, controls.EndpointMonitorLinuxNormalizer, controls.RSMA0202Questions),
		// inventaire matériel local — détection matériel/firmware (sonde Hardware)
		reuseControl(controls.IDAM0104Meta, controls.HwDet0104Evaluator{}, controls.HardwareWinCmd, controls.HardwareLinuxCmd, controls.HardwareWindowsNormalizer, controls.HardwareLinuxNormalizer, controls.IDAM0104Questions),
		// plateforme de gestion des vulnérabilités (sonde VulnScanner)
		reuseControl(controls.IDRA0802Meta, controls.VulnPlatform0802Evaluator{}, controls.VulnScannerWinCmd, controls.VulnScannerLinuxCmd, controls.VulnScannerWindowsNormalizer, controls.VulnScannerLinuxNormalizer, controls.IDRA0802Questions),
		reuseControl(controls.IDIM0309Meta, controls.VulnAssessment0309Evaluator{}, controls.VulnScannerWinCmd, controls.VulnScannerLinuxCmd, controls.VulnScannerWindowsNormalizer, controls.VulnScannerLinuxNormalizer, controls.IDIM0309Questions),
	}
}

// Commandes de collecte LECTURE SEULE. Elles interrogent seulement l'état du
// système — aucune ne modifie quoi que ce soit. RemoteSource les exécutera
// telles quelles ; FileSource les journalise. Chaque commande a un FORMAT DE
// SORTIE attendu, décodé par le normaliseur correspondant du contrôle.
const (
	// DE.CM-01.2 — antivirus.
	psDefenderStatus = "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json"
	// (sonde Linux : controls.AntivirusLinuxCmd)

	// DE.CM-01.1 — pare-feu local. MULTI-DISTRO côté Linux (ufw, firewalld,
	// nftables, iptables) : voir controls.FirewallLinuxCmd.
	psFirewallStatus = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json"
	// (sonde Linux : controls.FirewallLinuxCmd)

	// ID.AM-08.2 — correctifs de sécurité. MULTI-DISTRO : auto-détection du
	// gestionnaire (apt/dnf/zypper) ; émet 4 lignes : gestionnaire, nb correctifs
	// sécurité, epoch du dernier log, "yes"/"no" auto-update.
	psPendingUpdates = "$c=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Software'\").Updates.Count; $au=(New-Object -ComObject Microsoft.Update.AutoUpdate).Settings.NotificationLevel; [pscustomobject]@{pending=$c; auto=($au -ge 4)} | ConvertTo-Json"
	shPendingUpdates = "export LC_ALL=C; if command -v apt-get >/dev/null 2>&1; then echo apt; apt-get -s upgrade 2>/dev/null | grep -c '\\-security'; stat -c %Y /var/log/dpkg.log 2>/dev/null; test -f /etc/apt/apt.conf.d/20auto-upgrades && echo yes || echo no; " +
		"elif command -v dnf >/dev/null 2>&1; then echo dnf; dnf -q updateinfo list security 2>/dev/null | grep -c .; stat -c %Y /var/log/dnf.log 2>/dev/null; systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 && echo yes || echo no; " +
		"elif command -v zypper >/dev/null 2>&1; then echo zypper; zypper -q list-patches --category security 2>/dev/null | grep -c '|'; stat -c %Y /var/log/zypp/history 2>/dev/null; echo no; " +
		"elif command -v pacman >/dev/null 2>&1; then echo pacman; { checkupdates 2>/dev/null || true; } | grep -c .; stat -c %Y /var/log/pacman.log 2>/dev/null; echo no; " +
		"elif command -v apk >/dev/null 2>&1; then echo apk; apk version -l '<' 2>/dev/null | grep -c .; echo 0; echo no; fi"

	// PR.PS-04.1 — journalisation. NB : la durée de rétention et le transfert
	// distant sont environnement-dépendants ; ces sondes émettent un format
	// stable mais les valeurs exactes seront affinées par déploiement.
	psLogging = "[pscustomobject]@{enabled=((Get-Service EventLog -ErrorAction SilentlyContinue).Status -eq 'Running'); retention_days=90; forwarding=$false} | ConvertTo-Json"
	shLogging = "export LC_ALL=C; systemctl is-active systemd-journald; echo 90; (grep -rqs '^[^#].*@@\\?[0-9]' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null && echo yes || echo no)"

	// PR.AA-05.4 — comptes administrateurs locaux.
	// Groupe Administrateurs par SID UNIVERSEL (S-1-5-32-544) et compte intégré
	// Administrateur par RID (500) — NEUTRES en langue (les noms « Administrators »/
	// « Administrateurs »/« Administratoren »… sont traduits, le SID/RID non).
	psLocalAdmins = "$m=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue); $a=(Get-LocalUser -ErrorAction SilentlyContinue | Where-Object {$_.SID.Value -like '*-500'}); $b=$false; if($a){$b=$a.Enabled}; [pscustomobject]@{admin_count=$m.Count; builtin_admin_disabled=(-not $b)} | ConvertTo-Json"
	shLocalAdmins = "export LC_ALL=C; getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\\n' | grep -vc '^$'; passwd -S root 2>/dev/null | grep -q ' L ' && echo yes || echo no"
)

// DefaultControls renvoie le registre des contrôles avec l'horloge système.
func DefaultControls() []Control { return ControlsWithClock(time.Now) }

// ControlsWithClock construit le registre en injectant une horloge dans les
// normaliseurs qui en dépendent (calculs d'ancienneté). Il assemble :
//   - les contrôles SCANNABLES (Evaluator + Commands + Normalizers) ;
//   - le contrôle déclaratif GV.PO-01.1 (défini à part) ;
//   - tous les autres contrôles déclaratifs du catalogue (boucle sur données).
func ControlsWithClock(now func() time.Time) []Control {
	ctrls := []Control{
		{
			Meta:      controls.DECM0102Meta,
			Evaluator: controls.AntivirusEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("DE.CM-01.2", "windows", psDefenderStatus),
				"linux":   scan.ReadOnlyCommand("DE.CM-01.2", "linux", controls.AntivirusLinuxCmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.AntivirusWindowsNormalizer,
				"linux":   controls.AntivirusLinuxNormalizer(now),
			},
			Questions: controls.DECM0102Questions,
		},
		{
			Meta:      controls.DECM0101Meta,
			Evaluator: controls.FirewallEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("DE.CM-01.1", "windows", psFirewallStatus),
				"linux":   scan.ReadOnlyCommand("DE.CM-01.1", "linux", controls.FirewallLinuxCmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.FirewallWindowsNormalizer,
				"linux":   controls.FirewallLinuxNormalizer,
			},
			Questions: controls.DECM0101Questions,
		},
		{
			Meta:      controls.IDAM0802Meta,
			Evaluator: controls.PatchEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("ID.AM-08.2", "windows", psPendingUpdates),
				"linux":   scan.ReadOnlyCommand("ID.AM-08.2", "linux", shPendingUpdates),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.PatchWindowsNormalizer,
				"linux":   controls.PatchLinuxNormalizer(now),
			},
			Questions: controls.IDAM0802Questions,
		},
		{
			// PR.PS-04.1 — journalisation : endpoints (windows/linux) ET
			// équipements réseau (routeros/…), même évaluateur, sources fusionnées.
			Meta:      controls.PRPS0401Meta,
			Evaluator: controls.LoggingEvaluator{},
			Commands: mergeCommands(
				map[string]scan.CollectCommand{
					"windows": scan.ReadOnlyCommand("PR.PS-04.1", "windows", psLogging),
					"linux":   scan.ReadOnlyCommand("PR.PS-04.1", "linux", shLogging),
				},
				netCommands("PR.PS-04.1", controls.NetLoggingCommands()),
			),
			Normalizers: mergeNormalizers(
				map[string]assess.NormalizeFunc{
					"windows": controls.LoggingWindowsNormalizer,
					"linux":   controls.LoggingLinuxNormalizer,
				},
				controls.NetLoggingNormalizers(),
			),
			Questions: controls.PRPS0401Questions,
		},
		{
			// PR.AA-05.4 — comptes administrateurs locaux (système, scannable).
			Meta:      controls.PRAA0504Meta,
			Evaluator: controls.LocalAdminEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("PR.AA-05.4", "windows", psLocalAdmins),
				"linux":   scan.ReadOnlyCommand("PR.AA-05.4", "linux", shLocalAdmins),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.LocalAdminWindowsNormalizer,
				"linux":   controls.LocalAdminLinuxNormalizer,
			},
			Questions: controls.PRAA0504Questions,
		},
		{
			// PR.IR-01.1 — pare-feu RÉSEAU, scannable via les adaptateurs
			// constructeur (framework netdevice). Commandes/normaliseurs assemblés
			// par plateforme (routeros, pfsense, fortios…).
			Meta:        controls.PRIR0101Meta,
			Evaluator:   controls.NetFirewallEvaluator{},
			Commands:    netCommands(controls.PRIR0101Meta.ID, controls.NetFirewallCommands()),
			Normalizers: controls.NetFirewallNormalizers(),
			Questions:   controls.PRIR0101Questions,
		},
		{
			// PR.IR-01.2 — segmentation RÉSEAU, scannable via les adaptateurs.
			Meta:        controls.PRIR0102Meta,
			Evaluator:   controls.NetSegmentationEvaluator{},
			Commands:    netCommands(controls.PRIR0102Meta.ID, controls.NetSegmentationCommands()),
			Normalizers: controls.NetSegmentationNormalizers(),
			Questions:   controls.PRIR0102Questions,
		},
		{
			// PR.AA-01.1 — gestion des identités/identifiants (KM) : politique de
			// mot de passe, verrouillage, compte invité. Doc via questionnaire.
			Meta:      controls.PRAA0101Meta,
			Evaluator: controls.IdentityEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("PR.AA-01.1", "windows", controls.PRAA0101WinCmd),
				"linux":   scan.ReadOnlyCommand("PR.AA-01.1", "linux", controls.PRAA0101LinuxCmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.IdentityWindowsNormalizer,
				"linux":   controls.IdentityLinuxNormalizer,
			},
			Questions: controls.PRAA0101Questions,
		},
		{
			// PR.AA-05.3 — moindre privilège / durcissement (KM) : protocoles
			// legacy et surface d'écoute.
			Meta:      controls.PRAA0503Meta,
			Evaluator: controls.HardeningEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("PR.AA-05.3", "windows", controls.PRAA0503WinCmd),
				"linux":   scan.ReadOnlyCommand("PR.AA-05.3", "linux", controls.PRAA0503LinuxCmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.HardeningWindowsNormalizer,
				"linux":   controls.HardeningLinuxNormalizer,
			},
			Questions: controls.PRAA0503Questions,
		},
		{
			// PR.DS-11.1 — sauvegardes des données critiques (KM).
			Meta:      controls.PRDS1101Meta,
			Evaluator: controls.BackupEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("PR.DS-11.1", "windows", controls.PRDS1101WinCmd),
				"linux":   scan.ReadOnlyCommand("PR.DS-11.1", "linux", controls.PRDS1101LinuxCmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.BackupWindowsNormalizer,
				"linux":   controls.BackupLinuxNormalizer,
			},
			Questions: controls.PRDS1101Questions,
		},
		{
			// DE.AE-03.1 — journalisation des outils de protection/détection (KM).
			// Plafond honnête Defined : rétention/revue restent organisationnelles.
			Meta:      controls.DEAE0301Meta,
			Evaluator: controls.DetLoggingEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("DE.AE-03.1", "windows", controls.DEAE0301WinCmd),
				"linux":   scan.ReadOnlyCommand("DE.AE-03.1", "linux", controls.DEAE0301LinuxCmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.DetLoggingWindowsNormalizer,
				"linux":   controls.DetLoggingLinuxNormalizer,
			},
			Questions: controls.DEAE0301Questions,
		},
		{
			// ID.AM-02.1 — inventaire logiciel : le scan énumère, le questionnaire
			// atteste le « documenté/revu/à jour ». Plafond Defined.
			Meta:      controls.IDAM0201Meta,
			Evaluator: controls.SoftwareInventoryEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("ID.AM-02.1", "windows", controls.IDAM0201WinCmd),
				"linux":   scan.ReadOnlyCommand("ID.AM-02.1", "linux", controls.IDAM0201LinuxCmd),
				"m365":    scan.ReadOnlyCommand("ID.AM-02.1", "m365", controls.IDAM0201M365Cmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.SoftwareInventoryWindowsNormalizer,
				"linux":   controls.SoftwareInventoryLinuxNormalizer,
				"m365":    controls.M365InventoryNormalizer,
			},
			Questions: controls.IDAM0201Questions,
		},
		{
			// DE.CM-03-1 — surveillance endpoint/EDR (ID à tiret, fidèle CCB).
			Meta:      controls.DECM0301Meta,
			Evaluator: controls.EndpointMonitorEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("DE.CM-03-1", "windows", controls.DECM0301WinCmd),
				"linux":   scan.ReadOnlyCommand("DE.CM-03-1", "linux", controls.DECM0301LinuxCmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.EndpointMonitorWindowsNormalizer,
				"linux":   controls.EndpointMonitorLinuxNormalizer,
			},
			Questions: controls.DECM0301Questions,
		},
		{
			// PR.AA-05.1 — permissions d'accès définies/revues (KM, preuve
			// PARTIELLE) : comptes dormants. Plafond Defined (revue = organisationnel).
			Meta:      controls.PRAA0501Meta,
			Evaluator: controls.AccessReviewEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("PR.AA-05.1", "windows", controls.PRAA0501WinCmd),
				"linux":   scan.ReadOnlyCommand("PR.AA-05.1", "linux", controls.PRAA0501LinuxCmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.AccessReviewWindowsNormalizer,
				"linux":   controls.AccessReviewLinuxNormalizer,
			},
			Questions: controls.PRAA0501Questions,
		},
		{
			// PR.PS-05.1 — filtres web/e-mail (preuve PARTIELLE : e-mail = serveur).
			Meta:      controls.PRPS0501Meta,
			Evaluator: controls.WebFilterEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("PR.PS-05.1", "windows", controls.PRPS0501WinCmd),
				"linux":   scan.ReadOnlyCommand("PR.PS-05.1", "linux", controls.PRPS0501LinuxCmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.WebFilterWindowsNormalizer,
				"linux":   controls.WebFilterLinuxNormalizer,
			},
			Questions: controls.PRPS0501Questions,
		},
		{
			// PR.AA-03.2 — MFA accès distant (KM). Côté hôte : preuve FAIBLE (RDP/NLA,
			// plafond Defined). Côté M365 (plateforme "m365") : preuve AUTORITAIRE au
			// niveau IdP qui ferme la lacune et dépasse le plafond host-side.
			Meta:      controls.PRAA0302Meta,
			Evaluator: controls.RemoteMFAEvaluator{},
			Commands: map[string]scan.CollectCommand{
				"windows": scan.ReadOnlyCommand("PR.AA-03.2", "windows", controls.PRAA0302WinCmd),
				"linux":   scan.ReadOnlyCommand("PR.AA-03.2", "linux", controls.PRAA0302LinuxCmd),
				"m365":    scan.ReadOnlyCommand("PR.AA-03.2", "m365", controls.PRAA0302M365Cmd),
			},
			Normalizers: map[string]assess.NormalizeFunc{
				"windows": controls.RemoteMFAWindowsNormalizer,
				"linux":   controls.RemoteMFALinuxNormalizer,
				"m365":    controls.M365MFANormalizer,
			},
			Questions: controls.PRAA0302Questions,
		},
		{
			// Contrôle déclaratif défini dans son propre fichier (4 questions).
			Meta:      controls.GVPO0101Meta,
			Questions: controls.GVPO0101Questions,
		},
	}

	// Contrôles déclaratifs du catalogue (Meta + questions Doc/Impl seulement).
	for _, d := range controls.DeclarativeControls {
		ctrls = append(ctrls, Control{Meta: d.Meta, Questions: d.Questions})
	}

	// DÉGRADATION GRACIEUSE : chaque contrôle SCANNABLE reçoit une question
	// d'Implementation « de repli », à remplir UNIQUEMENT si le scan technique n'a
	// pas pu couvrir le contrôle (hôte injoignable, OS non supporté). En
	// fonctionnement normal le scan couvre l'Implementation et cette réponse est
	// ignorée ; elle ne sert que de filet pour ne jamais imposer un 0 injuste.
	for i := range ctrls {
		if len(ctrls[i].Commands) > 0 {
			ctrls[i].Questions = append(ctrls[i].Questions, implFallbackQuestion(ctrls[i].Meta.ID))
		}
	}
	return ctrls
}

// implFallbackQuestion fabrique la question d'attestation d'Implementation de
// repli d'un contrôle scannable (axe Implementation, clé "impl_fallback").
func implFallbackQuestion(id string) survey.Question {
	return survey.Ask(id, survey.Implementation, "impl_fallback",
		"REPLI — à remplir UNIQUEMENT si le scan n'a pas pu couvrir ce contrôle (hôte injoignable / OS non supporté) : dans quelle mesure la mesure est-elle réellement en place ?")
}

// netCommands enveloppe les commandes réseau (par plateforme) en CollectCommand
// read-only pour un contrôle donné. Générique : sert PR.IR-01.1, PR.IR-01.2, etc.
func netCommands(controlID string, scripts map[string]string) map[string]scan.CollectCommand {
	out := make(map[string]scan.CollectCommand)
	for platform, script := range scripts {
		out[platform] = scan.ReadOnlyCommand(controlID, platform, script)
	}
	return out
}

// mergeCommands fusionne deux tables de commandes par plateforme (endpoints +
// équipements réseau). En cas de clé identique, la seconde l'emporte.
func mergeCommands(base, extra map[string]scan.CollectCommand) map[string]scan.CollectCommand {
	for k, v := range extra {
		base[k] = v
	}
	return base
}

// mergeNormalizers fusionne deux tables de normaliseurs par plateforme.
func mergeNormalizers(base, extra map[string]assess.NormalizeFunc) map[string]assess.NormalizeFunc {
	for k, v := range extra {
		base[k] = v
	}
	return base
}

// AllQuestions rassemble les questions de tous les contrôles du registre.
func AllQuestions(ctrls []Control) []survey.Question {
	var qs []survey.Question
	for _, c := range ctrls {
		qs = append(qs, c.Questions...)
	}
	return qs
}
