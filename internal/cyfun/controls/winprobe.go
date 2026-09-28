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
// F ne doit JAMAIS échouer elle-même : un appel de méthode sur une valeur nulle
// y produisait une erreur non bloquante, F rendait la main et la sonde
// poursuivait avec des valeurs par défaut (constaté le 28/09/2026 sur Device
// Guard). Toute l'introspection de l'exception est donc protégée par try/catch,
// et la chaîne de repli est le texte brut de l'erreur.
//
// Les sondes privilégient ensuite des sources lisibles SANS droits
// d'administration (registre, journaux d'événements, .NET) et n'utilisent
// WMI/CIM qu'en premier essai.
const WinPre = `$ProgressPreference='SilentlyContinue'; ` +
	`function F($w,$e){$s="$e"; try{$x=$e.Exception; $s="$($x.GetType().FullName) $($x.HResult) $($x.Message)"; $i=$x.InnerException; if($i){$s+=" $($i.GetType().FullName) $($i.HResult) $($i.Message)"}}catch{}; if($s -match 'UnauthorizedAccess|SecurityException|2147024891|2147217405|0x80070005|0x80041003|denied|not allowed|refus|autoris|unauthori|verweigert|nicht zul|geweigerd|niet toegestaan'){"ACCESS DENIED: $w";exit 0};[Console]::Error.WriteLine("PROBE ERROR: $w : $s");exit 1}; `

// WinAutoServices range dans $S les services dont le NOM correspond à
// l'expression régulière $re, qui démarrent automatiquement (Start 0, 1 ou 2,
// lu dans le registre : l'énumération Get-Service est refusée à une session
// réseau non administrateur) ET qui tournent (Get-Service <nom>, autorisé) ;
// dans $X ceux qui démarrent automatiquement mais sont ARRÊTÉS (agent en panne
// ou arrêté par un attaquant : jamais compté comme actif). Un état illisible
// fait échouer la sonde (fonction F) plutôt que d'être supposé.
const WinAutoServices = `try{$K=Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services -EA Stop}catch{F 'registre des services' $_}; $S=@(); $X=@(); ` +
	`foreach($k in @($K|?{$_.PSChildName -match $re})){$st=(Get-ItemProperty $k.PSPath -EA SilentlyContinue).Start; if($st -ne $null -and $st -le 2){try{$v=Get-Service -Name $k.PSChildName -EA Stop}catch{F "etat du service $($k.PSChildName)" $_}; if("$($v.Status)" -eq 'Running'){$S+=$k.PSChildName}else{$X+=$k.PSChildName}}}; `
