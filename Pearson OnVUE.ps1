param(
    [string]$BaseUrl = 'https://op-prd-1.pvue2.com/onvue-hub-service/api/v2/system_test?customer=pearson_vue',
    [string]$DownloadUrl = 'https://download.onvue.com/onvue/OnVUE-25.10.96.exe?t=1751172065147&IE=.exe',
    [string]$DeliveryBaseUrl = 'https://candidatelaunchst.onvue.com/delivery',
    [int]$TimeoutSeconds = 30,
    [int]$MaxRedirects = 10
)

Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System.Windows.Forms # For clipboard functionality

$downloadPath = "$env:USERPROFILE\Downloads\OnVUE.exe"
$redirectCount = 0

$handler = $null
$client = $null
$webClient = $null

try {
    Write-Host "🚀 OnVUE Automation Script - Started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
    Write-Host "User: $env:USERNAME" -ForegroundColor Gray
    Write-Host "→ Starting request to $BaseUrl`n" -ForegroundColor Yellow

    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $client.DefaultRequestHeaders.Add("User-Agent", "OnVUE-Automation-Script/1.0")

    $url = $BaseUrl
    $accessCode = $null
    $sessionId = $null
    $foundParameters = $false

    do {
        Write-Host "📡 Making request to: $url" -ForegroundColor Cyan
        
        try {
            $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $url)
            $resp = $client.SendAsync($req).Result

            if ($resp.StatusCode -ge 300 -and $resp.StatusCode -lt 400) {
                $redirectCount++
                if ($redirectCount -gt $MaxRedirects) {
                    throw "Maximum redirect limit ($MaxRedirects) exceeded"
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
            throw "Request timed out after $TimeoutSeconds seconds"
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
        Write-Host "⚠️  Warning: access_code seems unusually short" -ForegroundColor Yellow
    }
    if ($sessionId.Length -lt 5) {
        Write-Host "⚠️  Warning: session_id seems unusually short" -ForegroundColor Yellow
    }

    Write-Host "`n📋 Extracted parameters:"
    Write-Host "  access_code = $accessCode (Length: $($accessCode.Length))"
    Write-Host "  session_id  = $sessionId (Length: $($sessionId.Length))"

    $deliveryUri = "${DeliveryBaseUrl}?session_id=${sessionId}&access_code=${accessCode}&locale=en-US&token=undefined"
    Write-Host "`n🎯 Delivery URL: " -NoNewline; Write-Host $deliveryUri -ForegroundColor Magenta

    try {
        [System.Windows.Forms.Clipboard]::SetText($accessCode)
        Write-Host "`n📋 Access Code ($accessCode) copied to clipboard!" -ForegroundColor Green
    }
    catch {
        Write-Host "`n⚠️  Warning: Failed to copy to clipboard: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Manual copy required: $accessCode" -ForegroundColor White
    }

    Write-Host "`n📥 Preparing to download OnVUE application..." -ForegroundColor Yellow
    
    $skipDownload = $false
    if (Test-Path $downloadPath) {
        $existingFile = Get-Item $downloadPath
        Write-Host "📁 Existing file found:" -ForegroundColor Yellow
        Write-Host "  Path: $downloadPath"
        Write-Host "  Size: $([math]::Round($existingFile.Length / 1MB, 2)) MB"
        Write-Host "  Modified: $($existingFile.LastWriteTime)"
        
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

    if (-not $skipDownload) {
        try {
            Write-Host "🌐 Downloading from: $DownloadUrl" -ForegroundColor Cyan
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add("User-Agent", "OnVUE-Automation-Script/1.0")
            
            $downloadStart = Get-Date
            $webClient.DownloadFile($DownloadUrl, $downloadPath)
            $downloadEnd = Get-Date
            $downloadTime = ($downloadEnd - $downloadStart).TotalSeconds

            if (Test-Path $downloadPath) {
                $downloadedFile = Get-Item $downloadPath
                $fileSize = $downloadedFile.Length
                Write-Host "✅ Download completed successfully!" -ForegroundColor Green
                Write-Host "  File size: $([math]::Round($fileSize / 1MB, 2)) MB"
                Write-Host "  Download time: $([math]::Round($downloadTime, 1)) seconds"
                if ($downloadTime -gt 0) {
                    Write-Host "  Average speed: $([math]::Round(($fileSize / 1MB) / $downloadTime, 1)) MB/s"
                }
                
                if ($fileSize -lt 1MB) {
                    Write-Host "⚠️  Warning: Downloaded file seems unusually small" -ForegroundColor Yellow
                }
                
                try {
                    $fileBytes = [System.IO.File]::ReadAllBytes($downloadPath)
                    if ($fileBytes.Length -ge 2) {
                        $mzSignature = [System.Text.Encoding]::ASCII.GetString($fileBytes[0..1])
                        if ($mzSignature -eq "MZ") {
                            Write-Host "✅ File appears to be a valid executable" -ForegroundColor Green
                        } else {
                            Write-Host "⚠️  Warning: File may not be a valid executable" -ForegroundColor Yellow
                        }
                    }
                }
                catch {
                    Write-Host "⚠️  Warning: Could not verify file signature" -ForegroundColor Yellow
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

        $process = Start-Process -FilePath $downloadPath -PassThru
        
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
        Write-Host "💡 Try running as administrator or check antivirus settings" -ForegroundColor Yellow
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

    Write-Host "`n🎉 Process completed successfully!" -ForegroundColor Magenta
    Write-Host "📝 Summary:" -ForegroundColor White
    Write-Host "  • Access Code: $accessCode (copied to clipboard)"
    Write-Host "  • Session ID: $sessionId"
    Write-Host "  • Application: $downloadPath"
    Write-Host "  • Redirects followed: $redirectCount"
    Write-Host "`n✨ Follow the OnVUE application prompts and use your access code when requested." -ForegroundColor Cyan

}
catch {
    Write-Host "`n❌ Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "🔍 Error details: $($_.Exception.GetType().Name)" -ForegroundColor Yellow
    
    Write-Host "`n🔧 Troubleshooting tips:" -ForegroundColor Yellow
    Write-Host "  • Check your internet connection"
    Write-Host "  • Verify the URLs are accessible"
    Write-Host "  • Try running PowerShell as administrator"
    Write-Host "  • Check Windows Defender/antivirus settings"
    Write-Host "  • Ensure you have write permissions to Downloads folder"
    
    exit 1
}
finally {
    Write-Host "`n🧹 Cleaning up resources..." -ForegroundColor Gray
    
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
    
    Write-Host "🏁 Script completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
}

if ($Host.Name -eq "ConsoleHost") {
    Write-Host "`nPress any key to exit..." -ForegroundColor White
    try {
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    } catch {
        Read-Host "Press Enter to exit"
    }
}