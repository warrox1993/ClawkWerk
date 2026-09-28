package controls

// WinPre est le préambule commun des sondes PowerShell (LECTURE SEULE).
//
// Validation réelle du 28/09/2026 (Windows 11 Pro 25H2 fr-BE, compte local non
// administrateur membre de « Utilisateurs de gestion à distance » et « Lecteurs
// des journaux d'événements ») : sur une ouverture de session RÉSEAU (WinRM),
// WMI/CIM, Get-Service (énumération), w32tm, Get-BitLockerVolume,
// Confirm-SecureBootUEFI, Get-MpComputerStatus et l'API Windows Update
// répondent « Accès refusé ». Les anciennes sondes masquaient ces refus
// (-ErrorAction SilentlyContinue, 2>$null) et en tiraient des CONCLUSIONS
// fausses : BitLocker actif rapporté « non chiffré », Secure Boot actif rapporté
// « désactivé », disque rapporté « 0 % » (sain), aucune sauvegarde/EDR/SIEM
// « détecté » faute de pouvoir lister les services.
//
// Règle désormais portée par chaque sonde : une source ILLISIBLE n'est jamais
// une réponse. La fonction F classe l'échec :
//   - refus d'accès (HRESULT 0x80070005, WBEM 0x80041003, « refusé »,
//     « non autorisé », « unauthorized », « denied », « verweigert », « geweigerd ») : la sonde
//     écrit « ACCESS DENIED: <ressource> » et sort proprement ; le moteur en fait
//     un trou de collecte « droits insuffisants » (engine.privilegeGap), jamais
//     un constat ;
//   - toute autre erreur : message sur stderr et code de sortie 1, donc
//     « collecte échouée », jamais un constat.
//
// Les sondes privilégient ensuite des sources lisibles SANS droits
// d'administration (registre, journaux d'événements, .NET) et n'utilisent
// WMI/CIM qu'en premier essai.
const WinPre = `$ProgressPreference='SilentlyContinue'; ` +
	`function F($w,$e){if("$($e.Exception.HResult) $($e.Exception.Message) $($e.Exception.InnerException.Message)" -match '2147024891|0x80070005|0x80041003|denied|refus|autoris|unauthori|verweigert|geweigerd'){"ACCESS DENIED: $w";exit 0};[Console]::Error.WriteLine("PROBE ERROR: $w : $($e.Exception.Message)");exit 1}; `

// WinAutoServices renvoie (dans $S) les services dont le NOM correspond à
// l'expression régulière $re et qui démarrent automatiquement (Start 0, 1 ou 2),
// lus dans le registre : l'énumération du gestionnaire de services (Get-Service)
// est refusée à une session réseau non administrateur. Un service installé mais
// en démarrage manuel ou désactivé (ex. wbengine, Sense non intégré, WdNisSvc)
// n'est PAS compté comme un agent déployé.
const WinAutoServices = `try{$K=Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services -EA Stop}catch{F 'registre des services' $_}; ` +
	`$S=@($K|?{$_.PSChildName -match $re}|?{$st=(Get-ItemProperty $_.PSPath -EA SilentlyContinue).Start; $st -ne $null -and $st -le 2}|%{$_.PSChildName}); `
