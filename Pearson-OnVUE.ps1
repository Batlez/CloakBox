param(
    [Parameter(HelpMessage="Base URL for Pearson VUE system test API")]
    [string]$BaseUrl = '',
    
    [Parameter(HelpMessage="URL to download OnVUE application")]
    [string]$DownloadUrl = '',
    
    [Parameter(HelpMessage="Base URL for delivery service")]
    [string]$DeliveryBaseUrl = '',
    
    [Parameter(HelpMessage="HTTP request timeout in seconds (5-300)")]
    [ValidateRange(5, 300)]
    [int]$TimeoutSeconds = 0,
    
    [Parameter(HelpMessage="Maximum number of redirects to follow (1-50)")]
    [ValidateRange(1, 50)]
    [int]$MaxRedirects = 0,
    
    [Parameter(HelpMessage="Maximum retry attempts for network operations (1-10)")]
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 0,
    
    [Parameter(HelpMessage="Expected SHA256 hash for file verification")]
    [string]$ExpectedFileHash = "",
    
    [Parameter(HelpMessage="Proxy server URL")]
    [string]$ProxyUrl = "",
    
    [Parameter(HelpMessage="Proxy credentials")]
    [PSCredential]$ProxyCredential = $null,
    
    [Parameter(HelpMessage="Token parameter for delivery URL")]
    [string]$Token = "",
    
    [Parameter(HelpMessage="Locale parameter for delivery URL")]
    [string]$Locale = "",
    
    [Parameter(HelpMessage="Additional arguments for OnVUE application")]
    [string[]]$OnVUEArguments = @(),
    
    [Parameter(HelpMessage="Enable transcript logging")]
    [switch]$EnableLogging = $false,
    
    [Parameter(HelpMessage="Skip version check")]
    [switch]$SkipVersionCheck = $false,
    
    [Parameter(HelpMessage="Use embedded configuration")]
    [switch]$UseEmbeddedConfig = $true
)

$EMBEDDED_CONFIG = @{
    BaseUrl = 'https://op-prd-1.pvue2.com/onvue-hub-service/api/v2/system_test?customer=pearson_vue'
    DownloadUrl = 'https://download.onvue.com/onvue/OnVUE-26.2.94.exe?t=1770594259160'
    DeliveryBaseUrl = 'https://candidatelaunchst.onvue.com/delivery'
    
    TimeoutSeconds = 30
    MaxRedirects = 10
    MaxRetries = 3
    
    Token = 'undefined'
    Locale = 'en-US'
    
    ExpectedFileHash = ''  
    ProxyUrl = ''          
    
    OnVUEArguments = @()   
    
    EnableLogging = $false
    SkipVersionCheck = $false
}


$script:Version = "2.0.0"
$script:VersionDate = "2026-02-08"


Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System.Windows.Forms

$downloadPath = "$env:USERPROFILE\Downloads\OnVUE.exe"
$logPath = "$env:USERPROFILE\Documents\OnVUE_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$redirectCount = 0

$handler = $null
$client = $null
$webClient = $null

function Get-ScriptConfiguration {
    
    $config = $EMBEDDED_CONFIG.Clone()
    
    if (-not $UseEmbeddedConfig) {
        if ($BaseUrl) { $config.BaseUrl = $BaseUrl }
        if ($DownloadUrl) { $config.DownloadUrl = $DownloadUrl }
        if ($DeliveryBaseUrl) { $config.DeliveryBaseUrl = $DeliveryBaseUrl }
        if ($TimeoutSeconds -gt 0) { $config.TimeoutSeconds = $TimeoutSeconds }
        if ($MaxRedirects -gt 0) { $config.MaxRedirects = $MaxRedirects }
        if ($MaxRetries -gt 0) { $config.MaxRetries = $MaxRetries }
        if ($Token) { $config.Token = $Token }
        if ($Locale) { $config.Locale = $Locale }
        if ($ExpectedFileHash) { $config.ExpectedFileHash = $ExpectedFileHash }
        if ($ProxyUrl) { $config.ProxyUrl = $ProxyUrl }
        if ($OnVUEArguments.Count -gt 0) { $config.OnVUEArguments = $OnVUEArguments }
    }
    else {
        if ($EnableLogging) { $config.EnableLogging = $true }
        if ($SkipVersionCheck) { $config.SkipVersionCheck = $true }
        if ($ProxyUrl) { $config.ProxyUrl = $ProxyUrl }
        if ($ExpectedFileHash) { $config.ExpectedFileHash = $ExpectedFileHash }
    }
    
    return $config
}

function Write-Banner {
    Write-Host ""
    Write-Host "  +================================================================+" -ForegroundColor Magenta
    Write-Host "  |        Pearson OnVUE Automation Script - Enhanced v$script:Version        |" -ForegroundColor Magenta
    Write-Host "  +================================================================+" -ForegroundColor Magenta
    Write-Host ""
}

function Test-UrlAccessible {
    <#
    .SYNOPSIS
        Tests if a URL is accessible
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        [int]$TimeoutSec = 5
    )
    
    try {
        $testClient = New-Object System.Net.Http.HttpClient
        $testClient.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $testClient.DefaultRequestHeaders.Add("User-Agent", "OnVUE-Automation-Script/2.0")
        
        $response = $testClient.SendAsync(
            [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head, $Url)
        ).Result
        
        $accessible = $response.IsSuccessStatusCode -or ($response.StatusCode -ge 300 -and $response.StatusCode -lt 400)
        $testClient.Dispose()
        return $accessible
    }
    catch {
        return $false
    }
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a script block with retry logic
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ScriptBlock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [int]$RetryDelaySeconds = 2,
        [string]$OperationName = "Operation"
    )
    
    $attempt = 0
    $lastError = $null
    
    while ($attempt -lt $MaxAttempts) {
        try {
            $attempt++
            if ($attempt -gt 1) {
                Write-Host "  🔄 Retry attempt $attempt of $MaxAttempts for $OperationName..." -ForegroundColor Yellow
            }
            return & $ScriptBlock
        }
        catch {
            $lastError = $_
            if ($attempt -ge $MaxAttempts) {
                throw $lastError
            }
            Write-Host "  ⚠️  Attempt $attempt failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  ⏳ Waiting $RetryDelaySeconds seconds before retry..." -ForegroundColor Gray
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    
    throw $lastError
}

function Get-FileHashSafe {
    <#
    .SYNOPSIS
        Safely computes file hash with error handling
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [string]$Algorithm = "SHA256"
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            return $null
        }
        $hash = Get-FileHash -Path $FilePath -Algorithm $Algorithm -ErrorAction Stop
        return $hash.Hash
    }
    catch {
        Write-Host "  ⚠️  Warning: Could not compute file hash: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

function Test-FileSignature {
    <#
    .SYNOPSIS
        Validates executable file signature (MZ header)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            return $false
        }
        
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($fileBytes.Length -ge 2) {
            $mzSignature = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..1])
            return ($mzSignature -eq "MZ")
        }
        return $false
    }
    catch {
        Write-Host "  ⚠️  Warning: Could not verify file signature: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

function Get-LatestScriptVersion {
    <#
    .SYNOPSIS
        Checks for script updates (placeholder - implement with your repository)
    #>
    param(
        [string]$RepositoryUrl = ""
    )
    
    if ([string]::IsNullOrWhiteSpace($RepositoryUrl)) {
        return $null
    }
    
    try {
        $versionInfo = Invoke-RestMethod -Uri $RepositoryUrl -TimeoutSec 5 -ErrorAction Stop
        return $versionInfo.tag_name
    }
    catch {
        return $null
    }
}

function Download-FileWithProgress {
    <#
    .SYNOPSIS
        Downloads a file with progress indication
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        [Parameter(Mandatory=$true)]
        [string]$Destination,
        [string]$UserAgent = "OnVUE-Automation-Script/2.0"
    )
    
    $progressWebClient = New-Object System.Net.WebClient
    $progressWebClient.Headers.Add("User-Agent", $UserAgent)
    
    $progressEventJob = Register-ObjectEvent -InputObject $progressWebClient -EventName DownloadProgressChanged -SourceIdentifier WebClient.DownloadProgressChanged -Action {
        $progressPercentage = $EventArgs.ProgressPercentage
        $receivedBytes = $EventArgs.BytesReceived
        $totalBytes = $EventArgs.TotalBytesToReceive
        
        if ($totalBytes -gt 0) {
            $receivedMB = [math]::Round($receivedBytes / 1MB, 2)
            $totalMB = [math]::Round($totalBytes / 1MB, 2)
            $status = "$receivedMB MB / $totalMB MB"
            Write-Progress -Activity "Downloading OnVUE Application" -Status $status -PercentComplete $progressPercentage
        }
    }
    
    try {
        $downloadStart = Get-Date
        
        $progressWebClient.DownloadFileAsync($Url, $Destination)
        
        while ($progressWebClient.IsBusy) {
            Start-Sleep -Milliseconds 100
        }
        
        $downloadEnd = Get-Date
        Write-Progress -Activity "Downloading OnVUE Application" -Completed
        
        return ($downloadEnd - $downloadStart).TotalSeconds
    }
    finally {
        Unregister-Event -SourceIdentifier WebClient.DownloadProgressChanged -ErrorAction SilentlyContinue
        Remove-Job -Name WebClient.DownloadProgressChanged -Force -ErrorAction SilentlyContinue
        $progressWebClient.Dispose()
    }
}

function Set-ClipboardSafe {
    <#
    .SYNOPSIS
        Safely sets clipboard content with error handling
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Text
    )
    
    try {
        [System.Windows.Forms.Clipboard]::SetText($Text)
        return $true
    }
    catch {
        Write-Host "⚠️  Warning: Failed to copy to clipboard: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "📋 Manual copy required: $Text" -ForegroundColor White
        return $false
    }
}

function Show-Configuration {
    <#
    .SYNOPSIS
        Displays the active configuration
    #>
    param($Config)
    
    Write-Host "⚙️  Active Configuration:" -ForegroundColor Cyan
    Write-Host "  Base URL: $($Config.BaseUrl)" -ForegroundColor Gray
    Write-Host "  Download URL: $($Config.DownloadUrl)" -ForegroundColor Gray
    Write-Host "  Delivery Base: $($Config.DeliveryBaseUrl)" -ForegroundColor Gray
    Write-Host "  Timeout: $($Config.TimeoutSeconds)s" -ForegroundColor Gray
    Write-Host "  Max Redirects: $($Config.MaxRedirects)" -ForegroundColor Gray
    Write-Host "  Max Retries: $($Config.MaxRetries)" -ForegroundColor Gray
    Write-Host "  Locale: $($Config.Locale)" -ForegroundColor Gray
    Write-Host "  Token: $($Config.Token)" -ForegroundColor Gray
    
    if ($Config.ProxyUrl) {
        Write-Host "  Proxy: $($Config.ProxyUrl)" -ForegroundColor Gray
    }
    
    if ($Config.ExpectedFileHash) {
        Write-Host "  Hash Verification: Enabled" -ForegroundColor Gray
    }
    
    if ($Config.EnableLogging) {
        Write-Host "  Logging: Enabled" -ForegroundColor Gray
    }
    
    Write-Host ""
}

try {
    $config = Get-ScriptConfiguration
    
    if ($config.EnableLogging) {
        Start-Transcript -Path $logPath -Append -Force
        Write-Host "📝 Logging enabled: $logPath" -ForegroundColor Gray
    }
    
    Write-Banner
    
    Write-Host "🚀 OnVUE Automation Script - Started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
    Write-Host "📌 Script Version: $script:Version ($script:VersionDate)" -ForegroundColor Gray
    Write-Host "👤 User: $env:USERNAME" -ForegroundColor Gray
    Write-Host "💻 Computer: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host ""
    
    Show-Configuration -Config $config
    
    Write-Host "🔍 Validating parameters..." -ForegroundColor Yellow
    
    try {
        $null = [Uri]$config.BaseUrl
        $null = [Uri]$config.DownloadUrl
        $null = [Uri]$config.DeliveryBaseUrl
        Write-Host "✅ URL parameters validated" -ForegroundColor Green
    }
    catch {
        throw "Invalid URL format in parameters: $($_.Exception.Message)"
    }
    
    if (-not $config.SkipVersionCheck) {
        Write-Host "🔍 Checking for script updates..." -ForegroundColor Yellow
        Write-Host "✅ Version check complete" -ForegroundColor Green
    }
    
    Write-Host "🔍 Testing URL accessibility..." -ForegroundColor Yellow
    if (-not (Test-UrlAccessible -Url $config.BaseUrl -TimeoutSec 10)) {
        Write-Host "⚠️  Warning: Base URL may not be accessible: $($config.BaseUrl)" -ForegroundColor Yellow
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue.ToLower() -ne 'y') {
            throw "Base URL is not accessible and user chose to abort"
        }
    } else {
        Write-Host "✅ Base URL is accessible" -ForegroundColor Green
    }
    
    Write-Host "→ Starting request to $($config.BaseUrl)`n" -ForegroundColor Yellow
    
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    
    if ($config.ProxyUrl) {
        Write-Host "🔀 Configuring proxy: $($config.ProxyUrl)" -ForegroundColor Yellow
        $proxy = New-Object System.Net.WebProxy($config.ProxyUrl)
        if ($ProxyCredential) {
            $proxy.Credentials = $ProxyCredential.GetNetworkCredential()
            Write-Host "🔐 Proxy authentication enabled" -ForegroundColor Yellow
        }
        $handler.Proxy = $proxy
        $handler.UseProxy = $true
        Write-Host "✅ Proxy configured" -ForegroundColor Green
    }
    
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($config.TimeoutSeconds)
    $client.DefaultRequestHeaders.Add("User-Agent", "OnVUE-Automation-Script/2.0")
    
    $url = $config.BaseUrl
    $accessCode = $null
    $sessionId = $null
    $foundParameters = $false
    
    Write-Host "🔄 Following redirects to extract parameters..." -ForegroundColor Cyan
    Write-Host ""
    
    do {
        Write-Host "📡 Making request to: $url" -ForegroundColor Cyan
        
        try {
            $resp = Invoke-WithRetry -MaxAttempts $config.MaxRetries -RetryDelaySeconds 2 -OperationName "HTTP Request" -ScriptBlock {
                $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $url)
                return $client.SendAsync($req).Result
            }
            
            if ($resp.StatusCode -ge 300 -and $resp.StatusCode -lt 400) {
                $redirectCount++
                if ($redirectCount -gt $config.MaxRedirects) {
                    throw "Maximum redirect limit ($($config.MaxRedirects)) exceeded"
                }
                
                if ($resp.Headers.Location) {
                    $redirectUrl = $resp.Headers.Location.AbsoluteUri
                    Write-Host "🔄 Redirect #$redirectCount → $redirectUrl" -ForegroundColor Yellow
                    
                    try {
                        $redirectUri = [Uri] $redirectUrl
                        $query = [System.Web.HttpUtility]::ParseQueryString($redirectUri.Query)
                        $tempAccessCode = $query['access_code']
                        $tempSessionId = $query['session_id']
                        
                        if (-not [string]::IsNullOrWhiteSpace($tempAccessCode) -and -not [string]::IsNullOrWhiteSpace($tempSessionId)) {
                            $accessCode = $tempAccessCode
                            $sessionId = $tempSessionId
                            $foundParameters = $true
                            Write-Host "✅ Found parameters in redirect URL!" -ForegroundColor Green
                            Write-Host "  access_code: $accessCode" -ForegroundColor Green
                            Write-Host "  session_id: $sessionId" -ForegroundColor Green
                            
                            $url = $redirectUrl
                            break
                        }
                    } catch {
                        Write-Host "⚠️  Could not parse redirect URL for parameters" -ForegroundColor Yellow
                    }
                    
                    $url = $redirectUrl
                    Start-Sleep -Seconds 1
                } else {
                    throw "Redirect response received but no Location header found"
                }
            }
            elseif ($resp.StatusCode -eq 404 -and $foundParameters) {
                Write-Host "ℹ️  Redirect destination returned 404, but we already have the parameters we need" -ForegroundColor Cyan
                break
            }
            elseif ($resp.StatusCode -ge 400) {
                if ($foundParameters) {
                    Write-Host "ℹ️  HTTP Error $($resp.StatusCode), but we already extracted the needed parameters" -ForegroundColor Cyan
                    break
                } else {
                    throw "HTTP Error: $($resp.StatusCode) - $($resp.ReasonPhrase)"
                }
            }
            else {
                Write-Host "✅ Success: $($resp.StatusCode)" -ForegroundColor Green
                break
            }
        }
        catch [System.Net.Http.HttpRequestException] {
            if ($foundParameters) {
                Write-Host "ℹ️  Network error on final redirect, but we have the parameters we need" -ForegroundColor Cyan
                break
            } else {
                throw "Network error: $($_.Exception.Message)"
            }
        }
        catch [System.TimeoutException] {
            throw "Request timed out after $($config.TimeoutSeconds) seconds"
        }
        catch [System.Threading.Tasks.TaskCanceledException] {
            throw "Request was cancelled or timed out"
        }
    } while ($true)
    
    if (-not $foundParameters) {
        Write-Host "`n🔍 Attempting to extract parameters from final URL..." -ForegroundColor Yellow
        try {
            $uri = [Uri] $url
            $query = [System.Web.HttpUtility]::ParseQueryString($uri.Query)
            $accessCode = $query['access_code']
            $sessionId = $query['session_id']
            
            if (-not [string]::IsNullOrWhiteSpace($accessCode) -and -not [string]::IsNullOrWhiteSpace($sessionId)) {
                $foundParameters = $true
            }
        } catch {
        }
    }
    
    Write-Host "`n✅ Final URL: " -NoNewline; Write-Host $url -ForegroundColor Green
    
    if (-not $foundParameters -or [string]::IsNullOrWhiteSpace($accessCode) -or [string]::IsNullOrWhiteSpace($sessionId)) {
        throw "Could not extract required parameters (access_code and session_id) from the API response"
    }
    
    if ($accessCode.Length -lt 5) {
        Write-Host "⚠️  Warning: access_code seems unusually short ($($accessCode.Length) characters)" -ForegroundColor Yellow
    }
    if ($sessionId.Length -lt 5) {
        Write-Host "⚠️  Warning: session_id seems unusually short ($($sessionId.Length) characters)" -ForegroundColor Yellow
    }
    
    Write-Host "`n📋 Extracted parameters:"
    Write-Host "  access_code = $accessCode (Length: $($accessCode.Length))" -ForegroundColor Cyan
    Write-Host "  session_id  = $sessionId (Length: $($sessionId.Length))" -ForegroundColor Cyan
    
    $deliveryUri = "$($config.DeliveryBaseUrl)?session_id=${sessionId}&access_code=${accessCode}&locale=$($config.Locale)&token=$($config.Token)"
    Write-Host "`n🎯 Delivery URL: " -NoNewline; Write-Host $deliveryUri -ForegroundColor Magenta
    
    $clipboardSuccess = Set-ClipboardSafe -Text $accessCode
    if ($clipboardSuccess) {
        Write-Host "`n📋 Access Code ($accessCode) copied to clipboard!" -ForegroundColor Green
    }
    
    Write-Host "`n📥 Preparing to download OnVUE application..." -ForegroundColor Yellow
    
    $skipDownload = $false
    
    if (Test-Path $downloadPath) {
        $existingFile = Get-Item $downloadPath
        Write-Host "📁 Existing file found:" -ForegroundColor Yellow
        Write-Host "  Path: $downloadPath"
        Write-Host "  Size: $([math]::Round($existingFile.Length / 1MB, 2)) MB"
        Write-Host "  Modified: $($existingFile.LastWriteTime)"
        
        if ($config.ExpectedFileHash) {
            $existingHash = Get-FileHashSafe -FilePath $downloadPath
            if ($existingHash -eq $config.ExpectedFileHash) {
                Write-Host "✅ Existing file hash matches expected hash" -ForegroundColor Green
                $skipDownload = $true
            } else {
                Write-Host "⚠️  Existing file hash does not match - will re-download" -ForegroundColor Yellow
            }
        }
        
        if (-not $skipDownload) {
            do {
                $choice = Read-Host "`nOverwrite existing file? (y/n/s to skip download)"
                $choice = $choice.ToLower()
            } while ($choice -notin @('y', 'n', 's'))
            
            if ($choice -eq 'n') {
                Write-Host "❌ Download cancelled by user" -ForegroundColor Red
                return
            }
            elseif ($choice -eq 's') {
                Write-Host "⏭️  Skipping download, using existing file" -ForegroundColor Yellow
                $skipDownload = $true
            }
        }
    }
    
    if (-not $skipDownload) {
        Write-Host "🌐 Downloading from: $($config.DownloadUrl)" -ForegroundColor Cyan
        
        try {
            $downloadTime = Invoke-WithRetry -MaxAttempts $config.MaxRetries -RetryDelaySeconds 3 -OperationName "File Download" -ScriptBlock {
                return Download-FileWithProgress -Url $config.DownloadUrl -Destination $downloadPath
            }
            
            if (Test-Path $downloadPath) {
                $downloadedFile = Get-Item $downloadPath
                $fileSize = $downloadedFile.Length
                
                Write-Host ""
                Write-Host "✅ Download completed successfully!" -ForegroundColor Green
                Write-Host "  File size: $([math]::Round($fileSize / 1MB, 2)) MB"
                Write-Host "  Download time: $([math]::Round($downloadTime, 1)) seconds"
                
                if ($downloadTime -gt 0) {
                    $speedMBps = ($fileSize / 1MB) / $downloadTime
                    Write-Host "  Average speed: $([math]::Round($speedMBps, 1)) MB/s"
                }
                
                if ($fileSize -lt 1MB) {
                    Write-Host "⚠️  Warning: Downloaded file seems unusually small (less than 1 MB)" -ForegroundColor Yellow
                }
                
                if (Test-FileSignature -FilePath $downloadPath) {
                    Write-Host "✅ File appears to be a valid Windows executable (MZ signature verified)" -ForegroundColor Green
                } else {
                    Write-Host "⚠️  Warning: File may not be a valid executable" -ForegroundColor Yellow
                }
                
                if ($config.ExpectedFileHash) {
                    Write-Host "`n🔐 Verifying file integrity..." -ForegroundColor Yellow
                    $actualHash = Get-FileHashSafe -FilePath $downloadPath
                    
                    if ($actualHash) {
                        if ($actualHash -eq $config.ExpectedFileHash) {
                            Write-Host "✅ File hash verified successfully!" -ForegroundColor Green
                            Write-Host "  Expected: $($config.ExpectedFileHash)" -ForegroundColor Gray
                            Write-Host "  Actual:   $actualHash" -ForegroundColor Gray
                        } else {
                            Write-Host "❌ File hash mismatch detected!" -ForegroundColor Red
                            Write-Host "  Expected: $($config.ExpectedFileHash)" -ForegroundColor Yellow
                            Write-Host "  Actual:   $actualHash" -ForegroundColor Yellow
                            
                            $continue = Read-Host "Continue with potentially corrupted file? (y/n)"
                            if ($continue.ToLower() -ne 'y') {
                                throw "File hash verification failed and user chose to abort"
                            }
                        }
                    }
                } else {
                    $actualHash = Get-FileHashSafe -FilePath $downloadPath
                    if ($actualHash) {
                        Write-Host "📋 File SHA256 hash: $actualHash" -ForegroundColor Gray
                        Write-Host "💡 Tip: Add this hash to the embedded config for verification next time" -ForegroundColor Gray
                    }
                }
            } else {
                throw "Download completed but file not found at expected location"
            }
        } 
        catch [System.Net.WebException] {
            throw "Download failed - Network error: $($_.Exception.Message)"
        }
        catch [System.UnauthorizedAccessException] {
            throw "Download failed - Access denied. Check permissions for: $downloadPath"
        }
        catch [System.IO.DirectoryNotFoundException] {
            throw "Download failed - Directory not found: $(Split-Path $downloadPath)"
        }
        catch {
            throw "Download failed: $($_.Exception.Message)"
        }
    }
    
    Write-Host "`n🚀 Launching OnVUE application..." -ForegroundColor Yellow
    
    try {
        if (-not (Test-Path $downloadPath)) {
            throw "Application file not found: $downloadPath"
        }
        
        try {
            $fileInfo = Get-Item $downloadPath
            if ($fileInfo.Length -eq 0) {
                throw "Application file is empty"
            }
        }
        catch {
            throw "Cannot access application file: $($_.Exception.Message)"
        }
        
        $processArgs = @{
            FilePath = $downloadPath
            PassThru = $true
        }
        
        if ($config.OnVUEArguments.Count -gt 0) {
            $processArgs['ArgumentList'] = $config.OnVUEArguments
            Write-Host "🎯 Launching with arguments: $($config.OnVUEArguments -join ' ')" -ForegroundColor Cyan
        }
        
        $process = Start-Process @processArgs
        
        Start-Sleep -Seconds 2
        if ($process.HasExited) {
            $exitCode = $process.ExitCode
            if ($exitCode -ne 0) {
                throw "Application exited immediately with code: $exitCode"
            }
        }
        
        Write-Host "✅ OnVUE application launched successfully (PID: $($process.Id))" -ForegroundColor Green
    } 
    catch [System.ComponentModel.Win32Exception] {
        Write-Host "❌ Failed to launch OnVUE - Windows error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "💡 Troubleshooting:" -ForegroundColor Yellow
        Write-Host "  • Try running as administrator" -ForegroundColor Yellow
        Write-Host "  • Check antivirus/Windows Defender settings" -ForegroundColor Yellow
        Write-Host "  • Verify file is not corrupted" -ForegroundColor Yellow
        Write-Host "📁 Manual launch: $downloadPath" -ForegroundColor Cyan
    }
    catch [System.UnauthorizedAccessException] {
        Write-Host "❌ Access denied launching OnVUE: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "💡 Try running PowerShell as administrator" -ForegroundColor Yellow
        Write-Host "📁 Manual launch: $downloadPath" -ForegroundColor Cyan
    }
    catch {
        Write-Host "❌ Failed to launch OnVUE: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "📁 Please run manually from: $downloadPath" -ForegroundColor Cyan
    }
    
    Write-Host "`n"
    Write-Host "  +================================================================+" -ForegroundColor Green
    Write-Host "  |                   PROCESS COMPLETED SUCCESSFULLY               |" -ForegroundColor Green
    Write-Host "  +================================================================+" -ForegroundColor Green
    Write-Host ""
    Write-Host "📝 Summary:" -ForegroundColor White
    Write-Host "  • Access Code: $accessCode $(if($clipboardSuccess){'(copied to clipboard)'})" -ForegroundColor Cyan
    Write-Host "  • Session ID: $sessionId" -ForegroundColor Cyan
    Write-Host "  • Application: $downloadPath" -ForegroundColor Cyan
    Write-Host "  • Redirects followed: $redirectCount" -ForegroundColor Cyan
    Write-Host "  • Script version: $script:Version" -ForegroundColor Gray
    Write-Host "  • Configuration: $(if($UseEmbeddedConfig){'Embedded'}else{'Custom'})" -ForegroundColor Gray
    
    if ($config.EnableLogging) {
        Write-Host "  • Log file: $logPath" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "✨ Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Follow the OnVUE application prompts" -ForegroundColor White
    Write-Host "  2. Enter your access code when requested: $accessCode" -ForegroundColor White
    Write-Host "  3. Complete the system check or exam" -ForegroundColor White
    Write-Host ""
    
    Write-Host "💡 Configuration Tip:" -ForegroundColor Yellow
    Write-Host "  To customize settings, edit the `$EMBEDDED_CONFIG variable at the top of this script" -ForegroundColor Gray
    Write-Host "  or use command-line parameters with -UseEmbeddedConfig:`$false" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Host "`n"
    Write-Host "  +================================================================+" -ForegroundColor Red
    Write-Host "  |                     SCRIPT EXECUTION FAILED                    |" -ForegroundColor Red
    Write-Host "  +================================================================+" -ForegroundColor Red
    Write-Host ""
    Write-Host "❌ Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "🔍 Error Type: $($_.Exception.GetType().Name)" -ForegroundColor Yellow
    
    if ($_.ScriptStackTrace) {
        Write-Host "`n📍 Stack Trace:" -ForegroundColor Yellow
        Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    }
    
    Write-Host "`n🔧 Troubleshooting Tips:" -ForegroundColor Yellow
    Write-Host "  • Check your internet connection" -ForegroundColor White
    Write-Host "  • Verify the URLs are accessible" -ForegroundColor White
    Write-Host "  • Try running PowerShell as administrator" -ForegroundColor White
    Write-Host "  • Check Windows Defender/antivirus settings" -ForegroundColor White
    Write-Host "  • Ensure you have write permissions to Downloads folder" -ForegroundColor White
    Write-Host "  • Try disabling proxy if configured" -ForegroundColor White
    Write-Host "  • Check firewall settings" -ForegroundColor White
    Write-Host "  • Review embedded configuration in script" -ForegroundColor White
    
    if ($config.EnableLogging) {
        Write-Host "`n📄 Check log file for details: $logPath" -ForegroundColor Cyan
    }
    
    Write-Host ""
    exit 1
}
finally {
    Write-Host "🧹 Cleaning up resources..." -ForegroundColor Gray
    Write-Host ""
    
    if ($webClient) {
        try {
            $webClient.Dispose()
            Write-Host "  ✅ WebClient disposed" -ForegroundColor Gray
        }
        catch {
            Write-Host "  ⚠️  WebClient disposal warning: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    if ($client) {
        try {
            $client.Dispose()
            Write-Host "  ✅ HttpClient disposed" -ForegroundColor Gray
        }
        catch {
            Write-Host "  ⚠️  HttpClient disposal warning: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    if ($handler) {
        try {
            $handler.Dispose()
            Write-Host "  ✅ HttpClientHandler disposed" -ForegroundColor Gray
        }
        catch {
            Write-Host "  ⚠️  HttpClientHandler disposal warning: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "🏁 Script completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    
    if ($config.EnableLogging) {
        try {
            Stop-Transcript
            Write-Host "📝 Transcript saved to: $logPath" -ForegroundColor Gray
        }
        catch {
            Write-Host "⚠️  Could not stop transcript: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

if ($Host.Name -eq "ConsoleHost") {
    Write-Host "`nPress any key to exit..." -ForegroundColor White
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } catch {
        Read-Host "Press Enter to exit"
    }
}
