# ─────────────────────────────────────────────────────────────
# AuditAuth.ps1
# Sign-in as a user (default) or as an app registration (service principal).
#
# App registration sign-in never writes the app's details to disk:
#   - The Az context autosave is turned off for the process before signing in, so nothing is
#     written to ~/.Azure (no context, no token cache, no secret).
#   - The secret is kept as a SecureString in memory only. It is never a plain-text parameter,
#     never written to run.json, the generated tool scripts or the logs.
#   - External tools get the client ID, certificate thumbprint or secret through environment
#     variables that exist only while that tool runs (this process and its child). The child
#     removes them as soon as it has read them, and this process removes them afterwards.
#   - Microsoft Graph (Maester) uses -ContextScope Process, so its token cache stays in memory.
#   - When the audit ends, the app's Az session is removed from the process.
# ─────────────────────────────────────────────────────────────

$script:AuditAuth = @{
    Mode                  = "User"     # User | ServicePrincipal
    TenantId              = ""
    ClientId              = ""
    CertificateThumbprint = ""
    Secret                = $null      # SecureString, memory only
}

# Names of the environment variables used to hand the app over to a tool process
$script:AuditAuthEnvNames = @("SIMPLEAZUREAUDIT_SP_TENANT", "SIMPLEAZUREAUDIT_SP_CLIENTID", "SIMPLEAZUREAUDIT_SP_THUMBPRINT", "SIMPLEAZUREAUDIT_SP_SECRET")

function Test-AuditServicePrincipal { return ($script:AuditAuth.Mode -eq "ServicePrincipal") }

function Initialize-AuditAuth {
    <#
      Validates the sign-in parameters. With -ClientId the audit signs in as the app registration:
      with -CertificateThumbprint when given (recommended), otherwise with a client secret
      (-ClientSecret as a SecureString, or prompted for without echo).
    #>
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint,
        [securestring]$ClientSecret,
        [switch]$UseDeviceAuthentication
    )
    if (-not $ClientId) {
        if ($CertificateThumbprint -or $ClientSecret) { throw "-CertificateThumbprint and -ClientSecret require -ClientId (the app registration's application ID)." }
        return
    }
    if (-not $TenantId) { throw "-ClientId requires -TenantID." }
    if ($UseDeviceAuthentication) { throw "-UseDeviceAuthentication is for user sign-in and cannot be used with -ClientId." }
    $guid = [guid]::Empty
    if (-not [guid]::TryParse($ClientId, [ref]$guid)) { throw "-ClientId must be the application (client) ID, a GUID." }
    if ($CertificateThumbprint -and $ClientSecret) { throw "Use either -CertificateThumbprint or -ClientSecret, not both." }

    $script:AuditAuth.Mode     = "ServicePrincipal"
    $script:AuditAuth.TenantId = $TenantId
    $script:AuditAuth.ClientId = $ClientId

    if ($CertificateThumbprint) {
        $thumb = ($CertificateThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
        $cert = @("Cert:\CurrentUser\My\$thumb", "Cert:\LocalMachine\My\$thumb") | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $cert) { throw "Certificate $thumb was not found in Cert:\CurrentUser\My or Cert:\LocalMachine\My." }
        if (-not (Get-Item $cert).HasPrivateKey) { throw "Certificate $thumb has no private key on this machine." }
        $script:AuditAuth.CertificateThumbprint = $thumb
    }
    else {
        if (-not $ClientSecret) {
            $ClientSecret = Read-Host "Client secret for app $ClientId (input is hidden)" -AsSecureString
        }
        if (-not $ClientSecret -or $ClientSecret.Length -eq 0) { throw "No client secret was given." }
        $script:AuditAuth.Secret = $ClientSecret
    }
}

function Connect-AuditAzure {
    # Signs this process in to Azure: as the app registration, or as a user (reusing a context when possible).
    param(
        [string]$TenantId,
        [switch]$UseDeviceAuthentication
    )
    if (Test-AuditServicePrincipal) {
        $a = $script:AuditAuth
        # Process scope only: nothing about this sign-in is written to the user's Az profile on disk.
        # Contexts already loaded from disk are dropped from memory (not from disk), so every Az call
        # in this run uses the app.
        Disable-AzContextAutosave -Scope Process -ErrorAction Stop | Out-Null
        Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
        $p = @{ ServicePrincipal = $true; Tenant = $a.TenantId; ErrorAction = "Stop"; WarningAction = "SilentlyContinue" }
        if ($a.CertificateThumbprint) {
            $p.ApplicationId = $a.ClientId
            $p.CertificateThumbprint = $a.CertificateThumbprint
            $method = "certificate"
        }
        else {
            $p.Credential = [pscredential]::new($a.ClientId, $a.Secret)
            $method = "client secret"
        }
        Write-Host "`nSigning in to Azure as an app registration ($method, this session only)..." -ForegroundColor Yellow
        try { Connect-AzAccount @p | Out-Null }
        catch { throw "App registration sign-in failed: $($_.Exception.Message)" }
        finally { $p = $null }
        return
    }

    # A context left in the session by an app registration (or a managed identity) is not reused:
    # user mode must run as a user.
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    $reuse = $ctx -and $ctx.Account -and "$($ctx.Account.Type)" -eq "User" -and (-not $TenantId -or $ctx.Tenant.Id -eq $TenantId)
    if ($reuse) {
        Write-Host "`nUsing the existing Azure sign-in: $($ctx.Account.Id) (tenant $($ctx.Tenant.Id))" -ForegroundColor Yellow
        return
    }

    Write-Host "`nSigning in to Azure..." -ForegroundColor Yellow
    $p = @{ ErrorAction = "Stop"; WarningAction = "SilentlyContinue" }
    if ($TenantId) { $p.TenantId = $TenantId }
    if ($UseDeviceAuthentication) {
        $p.UseDeviceAuthentication = $true
    }
    else {
        Write-Host "  If no sign-in window appears (it can open behind other windows, or not at all in an elevated or VS Code terminal), stop with Ctrl+C and run again with -UseDeviceAuthentication." -ForegroundColor DarkGray
    }
    try { Connect-AzAccount @p | Out-Null }
    catch {
        $hint = if ($UseDeviceAuthentication) { "" } else { " Try again with -UseDeviceAuthentication, or turn off the Windows sign-in broker with: Update-AzConfig -EnableLoginByWam `$false" }
        throw "Azure sign-in failed: $($_.Exception.Message)$hint"
    }
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx -or -not $ctx.Account) { throw "Azure sign-in did not complete (no account is signed in)." }
}

function Disconnect-AuditAzure {
    # Removes the app's session from this process and forgets the secret. Nothing to do for user sign-in.
    if (-not (Test-AuditServicePrincipal)) { return }
    try { Disconnect-AzAccount -ApplicationId $script:AuditAuth.ClientId -TenantId $script:AuditAuth.TenantId -ErrorAction SilentlyContinue | Out-Null } catch { }
    try { Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null } catch { }
    if ($script:AuditAuth.Secret) { $script:AuditAuth.Secret.Dispose() }
    $script:AuditAuth.Secret = $null
    Clear-AuditAuthEnvironment
}

function Get-AuditAccountLabel {
    # What run.json records about the signed-in identity. The app's ID is not recorded.
    if (Test-AuditServicePrincipal) { return "App registration" }
    return "$((Get-AzContext -ErrorAction SilentlyContinue).Account.Id)"
}

function Set-AuditAuthEnvironment {
    # Puts the app's sign-in details in this process's environment, for one tool process to read.
    if (-not (Test-AuditServicePrincipal)) { return }
    $a = $script:AuditAuth
    $env:SIMPLEAZUREAUDIT_SP_TENANT     = $a.TenantId
    $env:SIMPLEAZUREAUDIT_SP_CLIENTID   = $a.ClientId
    $env:SIMPLEAZUREAUDIT_SP_THUMBPRINT = $a.CertificateThumbprint
    $env:SIMPLEAZUREAUDIT_SP_SECRET     = $(if ($a.Secret) { [System.Net.NetworkCredential]::new("", $a.Secret).Password } else { "" })
}

function Clear-AuditAuthEnvironment {
    foreach ($n in $script:AuditAuthEnvNames) { Remove-Item "Env:\$n" -ErrorAction SilentlyContinue }
}

function Get-AuditChildAzSignIn {
    <#
      PowerShell text for a tool's child script. With an app registration it signs the child in to
      Azure for that process only (autosave off), reading the details from the environment and
      removing them right away. With a user sign-in it is empty: the child uses the saved Az context.
      The text holds no IDs or secrets, so the generated script in logs\ does not either.
    #>
    if (-not (Test-AuditServicePrincipal)) { return "" }
    return @'
$__sp = @{ Tenant = $env:SIMPLEAZUREAUDIT_SP_TENANT; Id = $env:SIMPLEAZUREAUDIT_SP_CLIENTID; Thumb = $env:SIMPLEAZUREAUDIT_SP_THUMBPRINT; Secret = $env:SIMPLEAZUREAUDIT_SP_SECRET }
Remove-Item Env:\SIMPLEAZUREAUDIT_SP_TENANT, Env:\SIMPLEAZUREAUDIT_SP_CLIENTID, Env:\SIMPLEAZUREAUDIT_SP_THUMBPRINT, Env:\SIMPLEAZUREAUDIT_SP_SECRET -ErrorAction SilentlyContinue
if (-not $__sp.Id) { throw 'The app registration details were not handed over to this tool.' }
Import-Module Az.Accounts -ErrorAction Stop
Disable-AzContextAutosave -Scope Process | Out-Null
Clear-AzContext -Scope Process -Force -ErrorAction SilentlyContinue | Out-Null
try {
    if ($__sp.Thumb) {
        Connect-AzAccount -ServicePrincipal -ApplicationId $__sp.Id -CertificateThumbprint $__sp.Thumb -Tenant $__sp.Tenant -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    } else {
        $__cred = [pscredential]::new($__sp.Id, (ConvertTo-SecureString -String $__sp.Secret -AsPlainText -Force))
        Connect-AzAccount -ServicePrincipal -Credential $__cred -Tenant $__sp.Tenant -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    }
}
finally { $__sp = $null; $__cred = $null }
Write-Host 'Signed in to Azure as the app registration (this process only, nothing saved).'
'@
}
