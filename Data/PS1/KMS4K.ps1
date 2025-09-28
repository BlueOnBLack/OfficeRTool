# Path to your DLL
$dllPath = $null
try {
  $dllPath = Join-Path $env:OfficeRToolpath "DATA\CORE\LibTSforge.dll"
}
catch {
  Write-Host "[ERROR] VARIABLE not found: OfficeRToolpath"
  return
}

# Function to check if a file exists
function Test-FileExists ($filePath) {
    return Test-Path -Path $filePath -PathType Leaf
}

# Function to load the DLL with better error checking
function Load-TSForgeDLL ($dllPath) {
    if (-not (Test-FileExists $dllPath)) {
        Write-Host "[ERROR] DLL not found at path: '$dllPath'"
        return $false
    }
    try {
        [Reflection.Assembly]::LoadFrom($dllPath) | Out-Null
        Write-Host "DLL loaded successfully." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "[ERROR] Error loading the DLL: $($_.Exception.Message)"
        return $false
    }
}

# Function to WMI information for specific product ID
function Get-WmiInfo {
    param (
    [Parameter(Mandatory=$true)]
    [string]$tsactid)

    try {
        $query = "SELECT ID,Name,Description,LicenseStatus FROM SoftwareLicensingProduct WHERE ID='$tsactid'"
        $record = Get-WmiObject -Query $query -ErrorAction Stop
        if ($record) {
            return $record
        } else {
            Write-Verbose "No SoftwareLicensingProduct found with ID '$tsactid'."
            return $null
        }
    } catch {
        Write-Error "Error retrieving WMI information: $($_.Exception.Message)"
        return $null
    }
}

Write-Host
if (-not @(Load-TSForgeDLL -dllPath $dllPath)) {
  return
}


$tsactid = $env:ID_
$errcode = 0 # Initialize error code
$ver = [LibTSforge.Utils]::DetectVersion()
$prod = [LibTSforge.Utils]::DetectCurrentKey()

try {
    $info = Get-WmiInfo -tsactid $tsactid
    $prodName = $info.Name
    $prodDes = $info.Description

    if ($prodName) {
        $nameParts = $prodName -split ',', 2
        $prodName = if ($nameParts.Count -gt 1) { ($nameParts[1].Trim() -split '[ ,]')[0] } else { $null }
    }
    #[LibTSforge.Modifiers.GenPKeyInstall]::InstallGenPKey($ver, $prod, $tsactid)
    [LibTSforge.Activators.KMS4k]::Activate($ver, $prod, $tsactid)
    $info = Get-WmiInfo -tsactid $tsactid
    if ($info.LicenseStatus -eq 1) {
        if ($prodDes -match 'KMS' -and $prodDes -notmatch 'CLIENT') {
            [LibTSforge.Modifiers.KMSHostCharge]::Charge($ver, $tsactid, $prod)
            Write-Host "[$prodName] CSVLK is permanently activated with KMS4k." -ForegroundColor White -BackgroundColor DarkGreen
            Write-Host "[$prodName] CSVLK is charged with 25 clients for 30 days." -ForegroundColor White -BackgroundColor DarkGreen
        }
        else {
            Write-Host "[$prodName] is permanently activated with KMS4k." -ForegroundColor White -BackgroundColor DarkGreen
        }
    }
    else {
        Write-Host "[$prodName] activation has failed." -ForegroundColor White -BackgroundColor DarkRed
        $errcode = 3
    }	
}
catch {
    $errcode = 3
    #Write-Error "$($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
    Write-Host "[$prodName] activation has failed." -ForegroundColor White -BackgroundColor DarkRed
}
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4ap/XNOC0N3TzW6AH/ldl0le
# xtygggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
# AQsFADAgMR4wHAYDVQQDDBVhZG1pbkBvZmZpY2VydG9vbC5vcmcwHhcNMjQwMTA2
# MTYxMjI3WhcNMzAwMTA2MTYyMjI3WjAgMR4wHAYDVQQDDBVhZG1pbkBvZmZpY2Vy
# dG9vbC5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLZq+Rmrz4
# wwNvgAZVzvbOmj1RlUll7htG/vIJurDabWNvIbYBxycLrzEAJKeuuO8TTtodlhCF
# kvCtzO2gU47wKwqoIK9p5orB9f0xasuxtu7EeIRvXZLpBjKQ20Fnzed6peoPupEb
# 5+2FIjAbM3ErtSbmC7XDhSLhAheV8+Urio/vv7zhiI0JYsfKtcZnbFBG8h5WOoYS
# k7vEF6nW4OleuM6oGuprq7OWDYGLa9sarX8mjNu0CPDgvxoE6vAiOY6lXgT9GoSn
# EOgpn8OOhpBp9ERPzP6Qq6qetl/+wYGkYbQGz7v6fPDQ4ATnGFIfc9G+qICE8iZs
# TV+bgDYjyMUJAgMBAAGjaDBmMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggr
# BgEFBQcDAzAgBgNVHREEGTAXghVhZG1pbkBvZmZpY2VydG9vbC5vcmcwHQYDVR0O
# BBYEFDIRoZpOPb0eh3mSqlUpHSSgioiqMA0GCSqGSIb3DQEBCwUAA4IBAQCe7S09
# 5VqCa9rw0s6FdNqvHOftRgRf1or04i7ZuV3jffN/rValXj8O7GtTRQ9ZFhGInjZ/
# 5UVyLPnhVqVwWzNpqFgTL5/Y0joFQ99GQfv1f5UUt6U4jNjjSTZNdVa3C9iwV4IQ
# jaRhGEQqsvqsOadezbX9jlIpXBKxmua70/cUj8Ub0UBT+jrt3ztqsX/Ei/wrorbh
# 8qS1rgYmi493hgQgKxSG/7tZ5PvbljEO5KPEMagKF6u4XX1B7Mz0DQAJcFUnTsNy
# D/Tj8nc03aYnF8NRkUyRYPhbIgpiY9e7/ivBY+4gF20ONc1Cy8+zqgSn17mF1QTD
# TOzL7jtV+7ROPKxOMYIB1TCCAdECAQEwNDAgMR4wHAYDVQQDDBVhZG1pbkBvZmZp
# Y2VydG9vbC5vcmcCEEnuPQcqcCyoTh5MzHkSiwcwCQYFKw4DAhoFAKB4MBgGCisG
# AQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGWs
# VuvFdPw77oONm87fY7/azcOmMA0GCSqGSIb3DQEBAQUABIIBALbn7FZoxH0wEKbq
# Zu08Zhua2XOxQSbQMQRktbh0c421CPmMuOA4jYqimHJ++kNDaS9Uu0HO/gV56LHa
# +5Uz66nDet5dSWJ+S+C6/kSNklfCkY//Y9UBWoYJT3Vx6f4kk5EFjhvMy7GLtSCh
# Ep/R0LOqIm3bkdzYlQeg+HMFMAnKgKE0uVcU0vUJp6FBWM+1wZgl1ozEbQGYHrO8
# IRf6NTjqkxP93ii2UDWkookLLdsGOeyImpjfAWIly/Pmxhro7RkVtzL/5x3gU2P3
# 8HMPJnHikJByikmAk1OE6XQe3Zr0xyg7+yBgMtg0o8jg+5f8VdrEPnN1ZYWRqH6E
# md4nibQ=
# SIG # End signature block
