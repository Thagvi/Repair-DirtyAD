<#
.SYNOPSIS
    Audit et remise en etat progressive d'un domaine Active Directory mal gere.

.DESCRIPTION
    Ce script realise un audit detaille d'un domaine Active Directory :
    - Sante AD : DCDIAG, replication, FSMO
    - Export utilisateurs, groupes, ordinateurs, OU, GPO
    - Detection des comptes inactifs
    - Detection des comptes PasswordNeverExpires
    - Detection des comptes sans pre-authentification Kerberos
    - Detection des utilisateurs avec SPN
    - Detection de la delegation non contrainte
    - Audit des groupes privilegies
    - Export et rapport HTML des GPO
    - Creation d'une OU de quarantaine
    - Generation d'un rapport HTML lisible pour documentation

    Par defaut, le script est en mode AUDIT SEUL.
    Aucune action corrective destructive n'est effectuee sans parametre explicite.

.PARAMETER OutputRoot
    Dossier racine de sortie pour les rapports et exports.

.PARAMETER InactiveDays
    Nombre de jours d'inactivite a partir duquel un compte est considere comme inactif.

.PARAMETER CreateQuarantineOU
    Cree l'OU de quarantaine si elle n'existe pas.

.PARAMETER DisableInactiveUsers
    Desactive les utilisateurs inactifs detectes.

.PARAMETER MoveInactiveUsersToQuarantine
    Deplace les utilisateurs inactifs dans l'OU de quarantaine. Necessite CreateQuarantineOU ou une OU deja existante.

.PARAMETER DisableInactiveComputers
    Desactive les ordinateurs inactifs detectes.

.PARAMETER MoveInactiveComputersToQuarantine
    Deplace les ordinateurs inactifs dans l'OU de quarantaine. Necessite CreateQuarantineOU ou une OU deja existante.

.PARAMETER FixNoPreAuth
    Reactive la pre-authentification Kerberos sur les comptes ou elle est desactivee.

.PARAMETER FixPasswordNeverExpires
    Desactive l'option "PasswordNeverExpires" sur les comptes utilisateurs concernes.
    Attention : a utiliser apres verification des comptes de service.

.PARAMETER FixUnconstrainedDelegation
    Desactive la delegation non contrainte sur les utilisateurs et ordinateurs concernes.

.PARAMETER DisableEmptyGPOs
    Desactive les GPO vides detectees.
    Attention : a valider dans un environnement reel avant usage.

.PARAMETER WhatIf
    Simule les actions correctives sans les appliquer.

.EXAMPLE
    .\Repair-DirtyAD.ps1

    Lance uniquement l'audit et genere les rapports.

.EXAMPLE
    .\Repair-DirtyAD.ps1 -CreateQuarantineOU

    Lance l'audit et cree l'OU de quarantaine.

.EXAMPLE
    .\Repair-DirtyAD.ps1 -CreateQuarantineOU -DisableInactiveUsers -MoveInactiveUsersToQuarantine -WhatIf

    Simule la desactivation et le deplacement des utilisateurs inactifs.

.EXAMPLE
    .\Repair-DirtyAD.ps1 -FixNoPreAuth -FixUnconstrainedDelegation -WhatIf

    Simule les corrections de securite les moins risquees.

.NOTES
    Auteur : Thagvi
	Développement réalisé avec assistance et relecture technique
    Usage : Lab / documentation BAIS / reprise AD
    A executer sur un controleur de domaine ou un serveur avec RSAT Active Directory.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$OutputRoot = "E:\Audit_AD",
    [int]$InactiveDays = 90,

    [switch]$CreateQuarantineOU,

    [switch]$DisableInactiveUsers,
    [switch]$MoveInactiveUsersToQuarantine,

    [switch]$DisableInactiveComputers,
    [switch]$MoveInactiveComputersToQuarantine,

    [switch]$FixNoPreAuth,
    [switch]$FixPasswordNeverExpires,
    [switch]$FixUnconstrainedDelegation,

    [switch]$DisableEmptyGPOs
)


# Save requested script dry-run state, then disable global WhatIf for audit/export cmdlets.
# Without this, Export-Csv, New-Item, Backup-GPO, etc. do not create report files when -WhatIf is used.
$ScriptDryRun = $WhatIfPreference
$WhatIfPreference = $false

function Invoke-ScriptShouldProcess {
    param(
        [string]$Target,
        [string]$Action
    )

    if ($ScriptDryRun) {
        Write-Host "WHATIF: Operation '$Action' on target '$Target'."
        return $false
    }

    return $true
}


# ==========================
# Initialisation
# ==========================

$ErrorActionPreference = "Continue"
$ScriptStart = Get-Date
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$RunRoot = Join-Path $OutputRoot "Run_$Timestamp"
$ExportPath = Join-Path $RunRoot "Exports"
$LogPath = Join-Path $RunRoot "Logs"
$GpoBackupPath = Join-Path $RunRoot "GPO_Backup"
$ReportPath = Join-Path $RunRoot "Rapports"
$ActionLog = Join-Path $LogPath "actions_realisees.csv"
$TranscriptPath = Join-Path $LogPath "transcript_$Timestamp.txt"
$TranscriptStarted = $false

New-Item -Path $RunRoot -ItemType Directory -Force | Out-Null
New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
New-Item -Path $GpoBackupPath -ItemType Directory -Force | Out-Null
New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null

try {
    Start-Transcript -Path $TranscriptPath -Force -ErrorAction Stop | Out-Null
    $TranscriptStarted = $true
}
catch {
    $TranscriptStarted = $false
    Write-Host "WARNING: Start-Transcript failed. The script will continue without transcript log."
}

$Actions = New-Object System.Collections.Generic.List[object]
$Findings = New-Object System.Collections.Generic.List[object]

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "============================================================"
    Write-Host $Title
    Write-Host "============================================================"
}

function Add-ActionLog {
    param(
        [string]$Category,
        [string]$ObjectName,
        [string]$ObjectDN,
        [string]$Action,
        [string]$Status,
        [string]$Details
    )

    $Actions.Add([PSCustomObject]@{
        Date       = Get-Date
        Category   = $Category
        ObjectName = $ObjectName
        ObjectDN   = $ObjectDN
        Action     = $Action
        Status     = $Status
        Details    = $Details
    })
}

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Title,
        [string]$Details,
        [int]$Count = 0,
        [string]$ExportFile = ""
    )

    $Findings.Add([PSCustomObject]@{
        Severity   = $Severity
        Category   = $Category
        Title      = $Title
        Count      = $Count
        Details    = $Details
        ExportFile = $ExportFile
    })
}

function Export-Data {
    param(
        [AllowNull()]$Data,
        [Parameter(Mandatory = $true)][string]$Path,
        [string[]]$Headers = @("NoData")
    )

    try {
        $items = @()
        if ($null -ne $Data) {
            $items = @($Data)
        }

        if ($items.Count -eq 0) {
            $headerLine = '"' + ($Headers -join '","') + '"'
            $headerLine | Set-Content -Path $Path -Encoding ASCII
        }
        else {
            $items | Export-Csv -Path $Path -NoTypeInformation -Encoding ASCII
        }
    }
    catch {
        $errPath = $Path + ".error.txt"
        "Export failed: $($_.Exception.Message)" | Out-File -FilePath $errPath -Encoding ASCII
    }

    return $Path
}

function Test-CommandExists {
    param([string]$CommandName)
    return [bool](Get-Command $CommandName -ErrorAction SilentlyContinue)
}

# ==========================
# Prerequis
# ==========================

Write-Section "Verification des prerequis"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Add-ActionLog -Category "Prerequis" -ObjectName "Module ActiveDirectory" -ObjectDN "" -Action "Import-Module" -Status "OK" -Details "Module ActiveDirectory charge."
}
catch {
    Add-ActionLog -Category "Prerequis" -ObjectName "Module ActiveDirectory" -ObjectDN "" -Action "Import-Module" -Status "ERREUR" -Details $_.Exception.Message
    Write-Error "Le module ActiveDirectory est introuvable. Installe RSAT AD ou lance le script sur un DC."
    if ($TranscriptStarted) {
        try { if ($TranscriptStarted) {
    try { Stop-Transcript | Out-Null } catch {}
} } catch {}
    }
    exit 1
}

try {
    Import-Module GroupPolicy -ErrorAction Stop
    $GroupPolicyAvailable = $true
    Add-ActionLog -Category "Prerequis" -ObjectName "Module GroupPolicy" -ObjectDN "" -Action "Import-Module" -Status "OK" -Details "Module GroupPolicy charge."
}
catch {
    $GroupPolicyAvailable = $false
    Add-ActionLog -Category "Prerequis" -ObjectName "Module GroupPolicy" -ObjectDN "" -Action "Import-Module" -Status "AVERTISSEMENT" -Details "Module GroupPolicy indisponible. Les exports GPO seront limites."
}

$Domain = Get-ADDomain
$DomainDN = $Domain.DistinguishedName
$DomainDNS = $Domain.DNSRoot
$QuarantineOUName = "_Quarantaine"
$QuarantineOU = "OU=$QuarantineOUName,$DomainDN"
$InactiveLimit = (Get-Date).AddDays(-$InactiveDays)

Add-ActionLog -Category "Contexte" -ObjectName $DomainDNS -ObjectDN $DomainDN -Action "Lecture contexte domaine" -Status "OK" -Details "Domaine detecte : $DomainDNS"

# ==========================
# Sante AD
# ==========================

Write-Section "Etat de sante Active Directory"

if (Test-CommandExists "dcdiag.exe") {
    cmd /c "dcdiag /v > `"$LogPath\dcdiag_before.txt`" 2>&1"
    Add-ActionLog -Category "Sante AD" -ObjectName "DCDIAG" -ObjectDN "" -Action "dcdiag /v" -Status "OK" -Details "Resultat : $LogPath\dcdiag_before.txt"
}
else {
    Add-ActionLog -Category "Sante AD" -ObjectName "DCDIAG" -ObjectDN "" -Action "dcdiag /v" -Status "NON_EXECUTE" -Details "dcdiag.exe introuvable."
}

if (Test-CommandExists "repadmin.exe") {
    cmd /c "repadmin /replsummary > `"$LogPath\replication_summary_before.txt`" 2>&1"
    cmd /c "repadmin /showrepl > `"$LogPath\showrepl_before.txt`" 2>&1"
    Add-ActionLog -Category "Sante AD" -ObjectName "Replication" -ObjectDN "" -Action "repadmin" -Status "OK" -Details "Resultats dans $LogPath"
}
else {
    Add-ActionLog -Category "Sante AD" -ObjectName "Replication" -ObjectDN "" -Action "repadmin" -Status "NON_EXECUTE" -Details "repadmin.exe introuvable."
}

if (Test-CommandExists "netdom.exe") {
    cmd /c "netdom query fsmo > `"$LogPath\fsmo.txt`" 2>&1"
    Add-ActionLog -Category "Sante AD" -ObjectName "FSMO" -ObjectDN "" -Action "netdom query fsmo" -Status "OK" -Details "Resultat : $LogPath\fsmo.txt"
}

# ==========================
# Creation OU de quarantaine
# ==========================

Write-Section "Preparation de l'OU de quarantaine"

$ExistingQuarantineOU = Get-ADOrganizationalUnit -LDAPFilter "(ou=$QuarantineOUName)" -SearchBase $DomainDN -ErrorAction SilentlyContinue

if ($CreateQuarantineOU) {
    if (-not $ExistingQuarantineOU) {
        if (Invoke-ScriptShouldProcess -Target $QuarantineOU -Action "Creer OU de quarantaine") {
            try {
                New-ADOrganizationalUnit -Name $QuarantineOUName -Path $DomainDN -ProtectedFromAccidentalDeletion $true
                Add-ActionLog -Category "OU" -ObjectName $QuarantineOUName -ObjectDN $QuarantineOU -Action "Creation OU" -Status "OK" -Details "OU de quarantaine creee."
            }
            catch {
                Add-ActionLog -Category "OU" -ObjectName $QuarantineOUName -ObjectDN $QuarantineOU -Action "Creation OU" -Status "ERREUR" -Details $_.Exception.Message
            }
        }
    }
    else {
        Add-ActionLog -Category "OU" -ObjectName $QuarantineOUName -ObjectDN $ExistingQuarantineOU.DistinguishedName -Action "Verification OU" -Status "OK" -Details "OU de quarantaine deja existante."
    }
}
else {
    if ($ExistingQuarantineOU) {
        Add-ActionLog -Category "OU" -ObjectName $QuarantineOUName -ObjectDN $ExistingQuarantineOU.DistinguishedName -Action "Verification OU" -Status "OK" -Details "OU de quarantaine existante detectee."
    }
    else {
        Add-ActionLog -Category "OU" -ObjectName $QuarantineOUName -ObjectDN $QuarantineOU -Action "Verification OU" -Status "INFO" -Details "OU absente. Utiliser -CreateQuarantineOU pour la creer."
    }
}

# ==========================
# Exports complets
# ==========================

Write-Section "Exports complets des objets AD"

$Users = Get-ADUser -Filter * -Properties DisplayName,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,DoesNotRequirePreAuth,ServicePrincipalName,whenCreated,Description,UserAccountControl,TrustedForDelegation,AccountNotDelegated
$UsersExport = $Users | Select-Object Name,SamAccountName,DisplayName,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,DoesNotRequirePreAuth,ServicePrincipalName,TrustedForDelegation,AccountNotDelegated,whenCreated,Description,DistinguishedName
Export-Data -Data $UsersExport -Path "$ExportPath\users_full.csv" | Out-Null

$Groups = Get-ADGroup -Filter * -Properties Description,GroupCategory,GroupScope,whenCreated,ManagedBy
$GroupsExport = $Groups | Select-Object Name,SamAccountName,GroupCategory,GroupScope,whenCreated,ManagedBy,Description,DistinguishedName
Export-Data -Data $GroupsExport -Path "$ExportPath\groups_full.csv" | Out-Null

$Computers = Get-ADComputer -Filter * -Properties Enabled,LastLogonDate,OperatingSystem,whenCreated,TrustedForDelegation,Description
$ComputersExport = $Computers | Select-Object Name,Enabled,OperatingSystem,LastLogonDate,TrustedForDelegation,whenCreated,Description,DistinguishedName
Export-Data -Data $ComputersExport -Path "$ExportPath\computers_full.csv" | Out-Null

$OUs = Get-ADOrganizationalUnit -Filter * -Properties whenCreated,Description,ProtectedFromAccidentalDeletion
$OUsExport = $OUs | Select-Object Name,whenCreated,ProtectedFromAccidentalDeletion,Description,DistinguishedName
Export-Data -Data $OUsExport -Path "$ExportPath\ou_full.csv" | Out-Null

Add-ActionLog -Category "Export" -ObjectName "Objets AD" -ObjectDN $DomainDN -Action "Export complet" -Status "OK" -Details "Exports CSV generes dans $ExportPath"

# ==========================
# Audit utilisateurs
# ==========================

Write-Section "Audit des comptes utilisateurs"

$InactiveUsers = $Users | Where-Object {
    $_.Enabled -eq $true -and
    ($_.LastLogonDate -lt $InactiveLimit -or $_.LastLogonDate -eq $null)
} | Select-Object Name,SamAccountName,Enabled,LastLogonDate,whenCreated,DistinguishedName

Export-Data -Data $InactiveUsers -Path "$ExportPath\users_inactive_${InactiveDays}_days.csv" | Out-Null
Add-Finding -Severity "Moyen" -Category "Utilisateurs" -Title "Utilisateurs inactifs" -Count ($InactiveUsers.Count) -Details "Comptes actifs sans connexion recente ou sans LastLogonDate depuis $InactiveDays jours." -ExportFile "users_inactive_${InactiveDays}_days.csv"

$DisabledUsers = $Users | Where-Object { $_.Enabled -eq $false } | Select-Object Name,SamAccountName,Enabled,LastLogonDate,whenCreated,DistinguishedName
Export-Data -Data $DisabledUsers -Path "$ExportPath\users_disabled.csv" | Out-Null
Add-Finding -Severity "Info" -Category "Utilisateurs" -Title "Utilisateurs desactives" -Count ($DisabledUsers.Count) -Details "Comptes utilisateurs deja desactives." -ExportFile "users_disabled.csv"

$PwdNeverExpiresUsers = $Users | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true } | Select-Object Name,SamAccountName,PasswordNeverExpires,Enabled,DistinguishedName
Export-Data -Data $PwdNeverExpiresUsers -Path "$ExportPath\users_password_never_expires.csv" | Out-Null
Add-Finding -Severity "Moyen" -Category "Utilisateurs" -Title "PasswordNeverExpires active" -Count ($PwdNeverExpiresUsers.Count) -Details "Comptes actifs dont le mot de passe n'expire jamais. A verifier surtout pour les comptes de service." -ExportFile "users_password_never_expires.csv"

$NoPreAuthUsers = $Users | Where-Object { $_.DoesNotRequirePreAuth -eq $true -and $_.Enabled -eq $true } | Select-Object Name,SamAccountName,DoesNotRequirePreAuth,Enabled,DistinguishedName
Export-Data -Data $NoPreAuthUsers -Path "$ExportPath\users_no_kerberos_preauth.csv" | Out-Null
Add-Finding -Severity "Critique" -Category "Kerberos" -Title "Pre-authentification Kerberos desactivee" -Count ($NoPreAuthUsers.Count) -Details "Ces comptes sont vulnerables a l'AS-REP Roasting." -ExportFile "users_no_kerberos_preauth.csv"

$UsersWithSPN = $Users | Where-Object { $_.ServicePrincipalName -and $_.Enabled -eq $true } | Select-Object Name,SamAccountName,Enabled,ServicePrincipalName,DistinguishedName
Export-Data -Data $UsersWithSPN -Path "$ExportPath\users_with_spn.csv" | Out-Null
Add-Finding -Severity "Eleve" -Category "Kerberos" -Title "Utilisateurs avec SPN" -Count ($UsersWithSPN.Count) -Details "Comptes potentiellement kerberoastables. Ne pas supprimer automatiquement : verifier les services associes." -ExportFile "users_with_spn.csv"

# ==========================
# Audit ordinateurs
# ==========================

Write-Section "Audit des comptes ordinateurs"

$InactiveComputers = $Computers | Where-Object {
    $_.Enabled -eq $true -and
    ($_.LastLogonDate -lt $InactiveLimit -or $_.LastLogonDate -eq $null)
} | Select-Object Name,Enabled,OperatingSystem,LastLogonDate,whenCreated,DistinguishedName

Export-Data -Data $InactiveComputers -Path "$ExportPath\computers_inactive_${InactiveDays}_days.csv" | Out-Null
Add-Finding -Severity "Moyen" -Category "Ordinateurs" -Title "Ordinateurs inactifs" -Count ($InactiveComputers.Count) -Details "Comptes ordinateurs actifs sans connexion recente depuis $InactiveDays jours." -ExportFile "computers_inactive_${InactiveDays}_days.csv"

$DisabledComputers = $Computers | Where-Object { $_.Enabled -eq $false } | Select-Object Name,Enabled,OperatingSystem,LastLogonDate,DistinguishedName
Export-Data -Data $DisabledComputers -Path "$ExportPath\computers_disabled.csv" | Out-Null
Add-Finding -Severity "Info" -Category "Ordinateurs" -Title "Ordinateurs desactives" -Count ($DisabledComputers.Count) -Details "Comptes ordinateurs deja desactives." -ExportFile "computers_disabled.csv"

# ==========================
# Audit delegation
# ==========================

Write-Section "Audit des delegations dangereuses"

$UsersUnconstrainedDelegation = $Users | Where-Object { $_.TrustedForDelegation -eq $true } | Select-Object Name,SamAccountName,TrustedForDelegation,DistinguishedName
Export-Data -Data $UsersUnconstrainedDelegation -Path "$ExportPath\users_unconstrained_delegation.csv" | Out-Null

$ComputersUnconstrainedDelegation = $Computers | Where-Object { $_.TrustedForDelegation -eq $true } | Select-Object Name,TrustedForDelegation,OperatingSystem,DistinguishedName
Export-Data -Data $ComputersUnconstrainedDelegation -Path "$ExportPath\computers_unconstrained_delegation.csv" | Out-Null

Add-Finding -Severity "Critique" -Category "Delegation" -Title "Utilisateurs avec delegation non contrainte" -Count ($UsersUnconstrainedDelegation.Count) -Details "Les comptes utilisateurs ne devraient quasiment jamais etre en delegation non contrainte." -ExportFile "users_unconstrained_delegation.csv"
Add-Finding -Severity "Critique" -Category "Delegation" -Title "Ordinateurs avec delegation non contrainte" -Count ($ComputersUnconstrainedDelegation.Count) -Details "La delegation non contrainte est dangereuse et doit etre justifiee ou supprimee." -ExportFile "computers_unconstrained_delegation.csv"

# ==========================
# Audit groupes privilegies
# ==========================

Write-Section "Audit des groupes privilegies"

$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators",
    "Print Operators",
    "DnsAdmins",
    "Group Policy Creator Owners"
)

$PrivilegedResults = foreach ($GroupName in $PrivilegedGroups) {
    try {
        $Members = Get-ADGroupMember $GroupName -Recursive -ErrorAction Stop
        foreach ($Member in $Members) {
            [PSCustomObject]@{
                GroupName      = $GroupName
                MemberName     = $Member.Name
                SamAccountName = $Member.SamAccountName
                ObjectClass    = $Member.ObjectClass
                DistinguishedName = $Member.DistinguishedName
            }
        }
    }
    catch {
        [PSCustomObject]@{
            GroupName      = $GroupName
            MemberName     = "ERREUR OU GROUPE INTROUVABLE"
            SamAccountName = ""
            ObjectClass    = ""
            DistinguishedName = $_.Exception.Message
        }
    }
}

Export-Data -Data $PrivilegedResults -Path "$ExportPath\privileged_groups_members.csv" | Out-Null
Add-Finding -Severity "Critique" -Category "Groupes privilegies" -Title "Membres des groupes a privileges" -Count ($PrivilegedResults.Count) -Details "A controler manuellement. Reduire ces groupes au strict minimum." -ExportFile "privileged_groups_members.csv"

# Groupes vides
$EmptyGroups = foreach ($Group in $Groups) {
    try {
        $Members = Get-ADGroupMember $Group.DistinguishedName -ErrorAction Stop
        if (-not $Members) {
            $Group | Select-Object Name,SamAccountName,GroupCategory,GroupScope,DistinguishedName
        }
    }
    catch {}
}

Export-Data -Data $EmptyGroups -Path "$ExportPath\empty_groups.csv" | Out-Null
Add-Finding -Severity "Faible" -Category "Groupes" -Title "Groupes vides" -Count ($EmptyGroups.Count) -Details "Groupes sans membre. Ne pas supprimer sans verifier les ACL, GPO et applications." -ExportFile "empty_groups.csv"

# ==========================
# Audit GPO
# ==========================

Write-Section "Audit des GPO"

if ($GroupPolicyAvailable) {
    $GPOs = Get-GPO -All
    $GPOsExport = $GPOs | Select-Object DisplayName,Id,Owner,CreationTime,ModificationTime,GpoStatus
    Export-Data -Data $GPOsExport -Path "$ExportPath\gpo_full.csv" | Out-Null

    try {
        Backup-GPO -All -Path $GpoBackupPath | Out-Null
        Add-ActionLog -Category "GPO" -ObjectName "Toutes les GPO" -ObjectDN "" -Action "Backup-GPO" -Status "OK" -Details "Sauvegarde dans $GpoBackupPath"
    }
    catch {
        Add-ActionLog -Category "GPO" -ObjectName "Toutes les GPO" -ObjectDN "" -Action "Backup-GPO" -Status "ERREUR" -Details $_.Exception.Message
    }

    try {
        Get-GPOReport -All -ReportType Html -Path "$ReportPath\GPO_Report.html"
        Add-ActionLog -Category "GPO" -ObjectName "Toutes les GPO" -ObjectDN "" -Action "Get-GPOReport" -Status "OK" -Details "Rapport : $ReportPath\GPO_Report.html"
    }
    catch {
        Add-ActionLog -Category "GPO" -ObjectName "Toutes les GPO" -ObjectDN "" -Action "Get-GPOReport" -Status "ERREUR" -Details $_.Exception.Message
    }

    $EmptyGPOs = foreach ($GPO in $GPOs) {
        $ReportXmlPath = Join-Path $LogPath ("GPO_" + ($GPO.Id.Guid) + ".xml")
        try {
            Get-GPOReport -Guid $GPO.Id -ReportType Xml -Path $ReportXmlPath
            [xml]$Xml = Get-Content $ReportXmlPath

            $ComputerExtensionData = $Xml.GPO.Computer.ExtensionData
            $UserExtensionData = $Xml.GPO.User.ExtensionData

            if (-not $ComputerExtensionData -and -not $UserExtensionData) {
                $GPO | Select-Object DisplayName,Id,Owner,CreationTime,ModificationTime,GpoStatus
            }
        }
        catch {}
    }

    Export-Data -Data $EmptyGPOs -Path "$ExportPath\gpo_empty_or_no_settings.csv" | Out-Null
    Add-Finding -Severity "Faible" -Category "GPO" -Title "GPO sans parametres detectes" -Count ($EmptyGPOs.Count) -Details "GPO potentiellement inutiles. A verifier avant desactivation." -ExportFile "gpo_empty_or_no_settings.csv"
}
else {
    Add-Finding -Severity "Moyen" -Category "GPO" -Title "Audit GPO limite" -Count 0 -Details "Le module GroupPolicy n'est pas disponible." -ExportFile ""
}

# ==========================
# Actions correctives optionnelles
# ==========================

Write-Section "Actions correctives optionnelles"

if ($FixNoPreAuth) {
    foreach ($User in $NoPreAuthUsers) {
        if (Invoke-ScriptShouldProcess -Target $User.SamAccountName -Action "Reactiver pre-authentification Kerberos") {
            try {
                Set-ADAccountControl -Identity $User.DistinguishedName -DoesNotRequirePreAuth $false
                Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "FixNoPreAuth" -Status "OK" -Details "Pre-authentification Kerberos reactivee."
            }
            catch {
                Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "FixNoPreAuth" -Status "ERREUR" -Details $_.Exception.Message
            }
        }
    }
}

if ($FixPasswordNeverExpires) {
    foreach ($User in $PwdNeverExpiresUsers) {
        if (Invoke-ScriptShouldProcess -Target $User.SamAccountName -Action "Desactiver PasswordNeverExpires") {
            try {
                Set-ADUser -Identity $User.DistinguishedName -PasswordNeverExpires $false
                Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "FixPasswordNeverExpires" -Status "OK" -Details "PasswordNeverExpires desactive."
            }
            catch {
                Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "FixPasswordNeverExpires" -Status "ERREUR" -Details $_.Exception.Message
            }
        }
    }
}

if ($FixUnconstrainedDelegation) {
    foreach ($User in $UsersUnconstrainedDelegation) {
        if (Invoke-ScriptShouldProcess -Target $User.SamAccountName -Action "Desactiver delegation non contrainte utilisateur") {
            try {
                Set-ADAccountControl -Identity $User.DistinguishedName -TrustedForDelegation $false
                Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "FixUnconstrainedDelegationUser" -Status "OK" -Details "Delegation non contrainte desactivee."
            }
            catch {
                Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "FixUnconstrainedDelegationUser" -Status "ERREUR" -Details $_.Exception.Message
            }
        }
    }

    foreach ($Computer in $ComputersUnconstrainedDelegation) {
        if (Invoke-ScriptShouldProcess -Target $Computer.Name -Action "Desactiver delegation non contrainte ordinateur") {
            try {
                Set-ADAccountControl -Identity $Computer.DistinguishedName -TrustedForDelegation $false
                Add-ActionLog -Category "Correction" -ObjectName $Computer.Name -ObjectDN $Computer.DistinguishedName -Action "FixUnconstrainedDelegationComputer" -Status "OK" -Details "Delegation non contrainte desactivee."
            }
            catch {
                Add-ActionLog -Category "Correction" -ObjectName $Computer.Name -ObjectDN $Computer.DistinguishedName -Action "FixUnconstrainedDelegationComputer" -Status "ERREUR" -Details $_.Exception.Message
            }
        }
    }
}

# Desactivation et quarantaine utilisateurs inactifs
if ($DisableInactiveUsers -or $MoveInactiveUsersToQuarantine) {
    foreach ($User in $InactiveUsers) {
        if ($DisableInactiveUsers) {
            if (Invoke-ScriptShouldProcess -Target $User.SamAccountName -Action "Desactiver utilisateur inactif") {
                try {
                    Disable-ADAccount -Identity $User.DistinguishedName
                    Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "DisableInactiveUser" -Status "OK" -Details "Utilisateur inactif desactive."
                }
                catch {
                    Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "DisableInactiveUser" -Status "ERREUR" -Details $_.Exception.Message
                }
            }
        }

        if ($MoveInactiveUsersToQuarantine) {
            $OUExists = Get-ADOrganizationalUnit -LDAPFilter "(ou=$QuarantineOUName)" -SearchBase $DomainDN -ErrorAction SilentlyContinue
            if ($OUExists) {
                if (Invoke-ScriptShouldProcess -Target $User.SamAccountName -Action "Deplacer utilisateur en quarantaine") {
                    try {
                        Move-ADObject -Identity $User.DistinguishedName -TargetPath $OUExists.DistinguishedName
                        Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "MoveInactiveUserToQuarantine" -Status "OK" -Details "Utilisateur deplace vers $($OUExists.DistinguishedName)."
                    }
                    catch {
                        Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "MoveInactiveUserToQuarantine" -Status "ERREUR" -Details $_.Exception.Message
                    }
                }
            }
            else {
                Add-ActionLog -Category "Correction" -ObjectName $User.SamAccountName -ObjectDN $User.DistinguishedName -Action "MoveInactiveUserToQuarantine" -Status "NON_EXECUTE" -Details "OU de quarantaine absente. Utiliser -CreateQuarantineOU."
            }
        }
    }
}

# Desactivation et quarantaine ordinateurs inactifs
if ($DisableInactiveComputers -or $MoveInactiveComputersToQuarantine) {
    foreach ($Computer in $InactiveComputers) {
        if ($DisableInactiveComputers) {
            if (Invoke-ScriptShouldProcess -Target $Computer.Name -Action "Desactiver ordinateur inactif") {
                try {
                    Disable-ADAccount -Identity $Computer.DistinguishedName
                    Add-ActionLog -Category "Correction" -ObjectName $Computer.Name -ObjectDN $Computer.DistinguishedName -Action "DisableInactiveComputer" -Status "OK" -Details "Ordinateur inactif desactive."
                }
                catch {
                    Add-ActionLog -Category "Correction" -ObjectName $Computer.Name -ObjectDN $Computer.DistinguishedName -Action "DisableInactiveComputer" -Status "ERREUR" -Details $_.Exception.Message
                }
            }
        }

        if ($MoveInactiveComputersToQuarantine) {
            $OUExists = Get-ADOrganizationalUnit -LDAPFilter "(ou=$QuarantineOUName)" -SearchBase $DomainDN -ErrorAction SilentlyContinue
            if ($OUExists) {
                if (Invoke-ScriptShouldProcess -Target $Computer.Name -Action "Deplacer ordinateur en quarantaine") {
                    try {
                        Move-ADObject -Identity $Computer.DistinguishedName -TargetPath $OUExists.DistinguishedName
                        Add-ActionLog -Category "Correction" -ObjectName $Computer.Name -ObjectDN $Computer.DistinguishedName -Action "MoveInactiveComputerToQuarantine" -Status "OK" -Details "Ordinateur deplace vers $($OUExists.DistinguishedName)."
                    }
                    catch {
                        Add-ActionLog -Category "Correction" -ObjectName $Computer.Name -ObjectDN $Computer.DistinguishedName -Action "MoveInactiveComputerToQuarantine" -Status "ERREUR" -Details $_.Exception.Message
                    }
                }
            }
            else {
                Add-ActionLog -Category "Correction" -ObjectName $Computer.Name -ObjectDN $Computer.DistinguishedName -Action "MoveInactiveComputerToQuarantine" -Status "NON_EXECUTE" -Details "OU de quarantaine absente. Utiliser -CreateQuarantineOU."
            }
        }
    }
}

if ($DisableEmptyGPOs -and $GroupPolicyAvailable) {
    foreach ($GPO in $EmptyGPOs) {
        if (Invoke-ScriptShouldProcess -Target $GPO.DisplayName -Action "Desactiver GPO vide") {
            try {
                Set-GPO -Guid $GPO.Id -GpoStatus AllSettingsDisabled
                Add-ActionLog -Category "Correction" -ObjectName $GPO.DisplayName -ObjectDN $GPO.Id -Action "DisableEmptyGPO" -Status "OK" -Details "GPO desactivee."
            }
            catch {
                Add-ActionLog -Category "Correction" -ObjectName $GPO.DisplayName -ObjectDN $GPO.Id -Action "DisableEmptyGPO" -Status "ERREUR" -Details $_.Exception.Message
            }
        }
    }
}

# ==========================
# Sante AD apres corrections
# ==========================

Write-Section "Controle apres actions"

if (Test-CommandExists "repadmin.exe") {
    cmd /c "repadmin /replsummary > `"$LogPath\replication_summary_after.txt`" 2>&1"
    cmd /c "repadmin /showrepl > `"$LogPath\showrepl_after.txt`" 2>&1"
}

if (Test-CommandExists "dcdiag.exe") {
    cmd /c "dcdiag /v > `"$LogPath\dcdiag_after.txt`" 2>&1"
}

# ==========================
# Generation rapports
# ==========================

Write-Section "Generation des rapports de documentation"

$Actions | Export-Csv -Path $ActionLog -NoTypeInformation -Encoding UTF8
$Findings | Export-Csv -Path "$ReportPath\synthese_constats.csv" -NoTypeInformation -Encoding UTF8

$CriticalCount = ($Findings | Where-Object { $_.Severity -eq "Critique" } | Measure-Object).Count
$HighCount = ($Findings | Where-Object { $_.Severity -eq "Eleve" } | Measure-Object).Count
$MediumCount = ($Findings | Where-Object { $_.Severity -eq "Moyen" } | Measure-Object).Count
$LowCount = ($Findings | Where-Object { $_.Severity -eq "Faible" } | Measure-Object).Count
$InfoCount = ($Findings | Where-Object { $_.Severity -eq "Info" } | Measure-Object).Count

$FindingsRows = foreach ($Finding in $Findings) {
    "<tr><td>$($Finding.Severity)</td><td>$($Finding.Category)</td><td>$($Finding.Title)</td><td>$($Finding.Count)</td><td>$($Finding.Details)</td><td>$($Finding.ExportFile)</td></tr>"
}

$ActionsRows = foreach ($Action in $Actions) {
    "<tr><td>$($Action.Date)</td><td>$($Action.Category)</td><td>$($Action.ObjectName)</td><td>$($Action.Action)</td><td>$($Action.Status)</td><td>$($Action.Details)</td></tr>"
}

$Html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport d'audit et de remise en etat Active Directory</title>
<style>
body {
    font-family: Arial, sans-serif;
    margin: 30px;
    color: #222;
}
h1, h2, h3 {
    color: #1f4e79;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 25px;
}
th {
    background-color: #1f4e79;
    color: white;
    padding: 8px;
    text-align: left;
}
td {
    border: 1px solid #ddd;
    padding: 8px;
    vertical-align: top;
}
tr:nth-child(even) {
    background-color: #f5f5f5;
}
.summary {
    display: flex;
    gap: 15px;
    margin-bottom: 25px;
}
.box {
    border: 1px solid #ddd;
    padding: 15px;
    min-width: 120px;
    background: #fafafa;
}
.critique { color: #b00020; font-weight: bold; }
.eleve { color: #c45100; font-weight: bold; }
.moyen { color: #9a6700; font-weight: bold; }
.info { color: #555; }
code {
    background: #eee;
    padding: 2px 4px;
}
</style>
</head>
<body>

<h1>Rapport d'audit et de remise en etat Active Directory</h1>

<h2>1. Contexte</h2>
<p><strong>Domaine :</strong> $DomainDNS</p>
<p><strong>DN du domaine :</strong> $DomainDN</p>
<p><strong>Date de debut :</strong> $ScriptStart</p>
<p><strong>Date de fin :</strong> $(Get-Date)</p>
<p><strong>Dossier de sortie :</strong> $RunRoot</p>
<p><strong>Mode d'execution :</strong> Audit avec corrections optionnelles selon les parametres passes au script.</p>

<h2>2. Synthese des constats</h2>

<div class="summary">
    <div class="box"><span class="critique">Critique</span><br>$CriticalCount</div>
    <div class="box"><span class="eleve">Eleve</span><br>$HighCount</div>
    <div class="box"><span class="moyen">Moyen</span><br>$MediumCount</div>
    <div class="box">Faible<br>$LowCount</div>
    <div class="box">Info<br>$InfoCount</div>
</div>

<table>
<tr>
<th>Severite</th>
<th>Categorie</th>
<th>Constat</th>
<th>Nombre</th>
<th>Details</th>
<th>Export associe</th>
</tr>
$($FindingsRows -join "`n")
</table>

<h2>3. Actions realisees</h2>
<p>Le tableau ci-dessous liste les actions reellement executees ou simulees par PowerShell selon le mode utilise.</p>

<table>
<tr>
<th>Date</th>
<th>Categorie</th>
<th>Objet</th>
<th>Action</th>
<th>Statut</th>
<th>Details</th>
</tr>
$($ActionsRows -join "`n")
</table>

<h2>4. Fichiers generes</h2>
<ul>
<li><code>Exports\users_full.csv</code> : export complet des utilisateurs</li>
<li><code>Exports\groups_full.csv</code> : export complet des groupes</li>
<li><code>Exports\computers_full.csv</code> : export complet des ordinateurs</li>
<li><code>Exports\ou_full.csv</code> : export complet des OU</li>
<li><code>Exports\privileged_groups_members.csv</code> : membres des groupes privilegies</li>
<li><code>Exports\users_no_kerberos_preauth.csv</code> : comptes vulnerables a l'AS-REP Roasting</li>
<li><code>Exports\users_with_spn.csv</code> : comptes utilisateurs avec SPN</li>
<li><code>Exports\users_password_never_expires.csv</code> : comptes dont le mot de passe n'expire jamais</li>
<li><code>Exports\computers_unconstrained_delegation.csv</code> : ordinateurs avec delegation non contrainte</li>
<li><code>Rapports\GPO_Report.html</code> : rapport detaille des GPO, si le module GroupPolicy est disponible</li>
<li><code>Logs\dcdiag_before.txt</code> et <code>Logs\dcdiag_after.txt</code> : etat de sante AD</li>
<li><code>Logs\replication_summary_before.txt</code> et <code>Logs\replication_summary_after.txt</code> : etat de replication</li>
</ul>

<h2>5. Recommandations de correction</h2>
<ol>
<li>Traiter en priorite les groupes privilegies : Domain Admins, Enterprise Admins, Schema Admins, DnsAdmins, Backup Operators.</li>
<li>Reactiver la pre-authentification Kerberos sur les comptes concernes.</li>
<li>Supprimer la delegation non contrainte lorsqu'elle n'est pas strictement justifiee.</li>
<li>Identifier les comptes de service avec SPN et imposer des mots de passe longs ou migrer vers des gMSA.</li>
<li>Desactiver les utilisateurs et ordinateurs inactifs avant toute suppression definitive.</li>
<li>Mettre les objets douteux en quarantaine avant suppression.</li>
<li>Revoir les GPO une par une avant desactivation ou suppression.</li>
<li>Relancer un audit apres correction afin de comparer les resultats.</li>
</ol>

<h2>6. Note methodologique</h2>
<p>
La demarche appliquee evite les suppressions massives immediates. Dans un contexte de reprise d'un domaine Active Directory mal maintenu,
il est preferable d'exporter les objets, de desactiver les comptes douteux, de les deplacer en quarantaine, puis d'observer les impacts
avant une suppression definitive.
</p>

</body>
</html>
"@

$HtmlPath = Join-Path $ReportPath "Rapport_Audit_AD.html"
$Html | Out-File -FilePath $HtmlPath -Encoding UTF8

$Markdown = @"
# Rapport d'audit et de remise en etat Active Directory

## Contexte

- Domaine : $DomainDNS
- DN du domaine : $DomainDN
- Date de debut : $ScriptStart
- Date de fin : $(Get-Date)
- Dossier de sortie : $RunRoot

## Synthese

| Severite | Categorie | Constat | Nombre | Export |
|---|---|---|---:|---|
$(($Findings | ForEach-Object { "| $($_.Severity) | $($_.Category) | $($_.Title) | $($_.Count) | $($_.ExportFile) |" }) -join "`n")

## Actions realisees

| Date | Categorie | Objet | Action | Statut | Details |
|---|---|---|---|---|---|
$(($Actions | ForEach-Object { "| $($_.Date) | $($_.Category) | $($_.ObjectName) | $($_.Action) | $($_.Status) | $($_.Details) |" }) -join "`n")

## Recommandations

1. Traiter les groupes privilegies.
2. Corriger les comptes sans pre-authentification Kerberos.
3. Supprimer la delegation non contrainte non justifiee.
4. Identifier les comptes de service avec SPN.
5. Desactiver puis mettre en quarantaine les comptes inactifs.
6. Revoir les GPO avant suppression.
7. Relancer l'audit apres correction.

"@

$MarkdownPath = Join-Path $ReportPath "Rapport_Audit_AD.md"
$Markdown | Out-File -FilePath $MarkdownPath -Encoding UTF8

Add-ActionLog -Category "Rapport" -ObjectName "Rapport HTML" -ObjectDN $HtmlPath -Action "Generation rapport" -Status "OK" -Details "Rapport genere."
$Actions | Export-Csv -Path $ActionLog -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Audit termine."
Write-Host "Dossier de sortie : $RunRoot"
Write-Host "Rapport HTML : $HtmlPath"
Write-Host "Rapport Markdown : $MarkdownPath"
Write-Host "Journal des actions : $ActionLog"

if ($TranscriptStarted) {
    try { Stop-Transcript | Out-Null } catch {}
}
