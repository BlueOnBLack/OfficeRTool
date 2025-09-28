# Clean screen, start fresh
cls

# Get the current username
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Check if the current username ends with "\Administrator"
if ($currentUser -match '\\Administrator$') {
    Write-Host "The current user is the Administrator. Proceeding with the script."
    # Proceed with the rest of the script
} else {

    # Write 10 lines of gibberish
    1..99 | ForEach-Object {
        $gibberish = -join ((65..90) + (97..122) | Get-Random -Count 10 | % {[char]$_})
        Write-Host $gibberish
    }

    # Wait for 3 seconds
    Start-Sleep -Seconds 3

    # Restart the computer
    Restart-Computer -Force
}

# Get the folder where the script is located
$scriptFolder = $PSScriptRoot

# Get the parent folder path (where the required files are located)
$parentFolder = Split-Path -Path $scriptFolder -Parent

# Define allowed filenames (case-insensitive)
$allowedFiles = @(
    "readme.pdf",
    "Debug Mode.cmd",
    "OfficeRTool.cmd"
)

# --- Validate that all necessary files exist in the parent folder ---
$missingFiles = $allowedFiles | Where-Object { -not (Test-Path (Join-Path $parentFolder $_)) }

if ($missingFiles.Count -gt 0) {
    Write-Warning "The following necessary files are missing in the parent folder: $($missingFiles -join ', ')"
    return
}

# --- Get parent folder path ---
$parentFolder = Split-Path -Path $scriptFolder -Parent

# --- Delete all other files ---
Get-ChildItem -Path $parentFolder -File | ForEach-Object {
    if ($allowedFiles -notcontains $_.Name) {
        Write-Host "Deleting: $($_.Name)"
        Remove-Item -Path $_.FullName -Force
    }
}

# --- Generate checksums ---
$checksumLines = @()
$officeHash = $null

foreach ($name in $allowedFiles) {
    $filePath = Join-Path $parentFolder $name
    if (Test-Path $filePath) {
        $md5 = Get-FileHash -Path $filePath -Algorithm MD5
        $line = "{0} *{1}" -f $md5.Hash.ToLower(), $name
        $checksumLines += $line

        # Save OfficeRTool.cmd hash
        if ($name -ieq "OfficeRTool.cmd") {
            $officeHash = $md5.Hash.ToLower()
        }
    } else {
        Write-Warning "File not found: $name"
    }
}

# Write checksums to file
$outputFile = Join-Path $parentFolder "checksums.md5"
$checksumLines | Set-Content -Path $outputFile -Encoding UTF8
Write-Host "Checksums saved to: $outputFile"

# --- Update defaults.ini with ASCII-to-Hex version of MD5 ---
if ($officeHash) {
    # Convert string to ASCII byte array, then to lowercase hex string
    $hexSignature = -join ([System.Text.Encoding]::ASCII.GetBytes($officeHash) | ForEach-Object { $_.ToString("x2") })

    $iniPath = Join-Path $scriptFolder "defaults.ini"

    if (Test-Path $iniPath) {
        $content = Get-Content $iniPath
        $updated = $false

        # Replace line starting with SIGNATURE=
        $content = $content | ForEach-Object {
            if ($_ -match "^SIGNATURE=") {
                $updated = $true
                "SIGNATURE=$hexSignature"
            } else {
                $_
            }
        }

        if ($updated) {
            $content | Set-Content -Path $iniPath -Encoding UTF8
            Write-Host "Updated SIGNATURE in defaults.ini"
        } else {
            Write-Warning "SIGNATURE line not found in defaults.ini"
        }
    } else {
        Write-Warning "defaults.ini not found in script folder"
    }
} else {
    Write-Warning "OfficeRTool.cmd hash not available"
}

# Get the script's folder (current location of the script file)
$scriptFolder = Split-Path -Path $MyInvocation.MyCommand.Path -Parent

# Set current directory as the script folder (for clarity)
$currentDirectory = $scriptFolder

# Get the parent folder (one level up from the script folder)
$parentFolder = Split-Path -Path $currentDirectory -Parent

# Get the Desktop path for the current user
$desktopPath = [System.Environment]::GetFolderPath('Desktop')

$files       = Get-ChildItem -Recurse -Path $parentFolder
$Pattern     = "^(.)(ps1|vbs|exe|dll)$"
$case        = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
$certificate = "C:\windows\code_signing.crt"
$Thumbprint  = (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)

if (-not $Thumbprint) {
  New-SelfSignedCertificate -DnsName admin@officertool.org -Type CodeSigning -CertStoreLocation cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(6)
  Export-Certificate -Cert (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0] -FilePath $certificate
  certutil -addstore -f "root" $certificate
  certutil -addstore -f "TrustedPublisher" $certificate

  $Thumbprint = (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)
  if (-not $Thumbprint) {
      throw "ERROR :: Failed to create Fake Certificate"
      return
  }
}

$files|?{[REGEX]::IsMatch($_.Extension,$Pattern,$case)}|%{Set-AuthenticodeSignature $_.FullName -Certificate $Thumbprint[0] -Force -ErrorAction SilentlyContinue -Verbose }

# --- Remove old OfficeRTool files from Desktop ---
$oldDesktopFiles = Get-ChildItem -Path $desktopPath -Filter "OfficeRTool.*" | Where-Object { $_.Extension -match "^\.(rar|7z)$" }

$oldDesktopFiles | ForEach-Object {
    Write-Host "Removing old file: $($_.Name) from Desktop"
    Remove-Item -Path $_.FullName -Force
}

# Run Compress.cmd with * and parentFolder as arguments
Set-Location $parentFolder
Start-Process -FilePath cmd -ArgumentList "/c Compress * ""$parentFolder""" -WindowStyle Hidden -Wait

# Define destination path (where to copy the files)
$destinationPath = "D:\Software\MS Tools Pack\Office"

# Get only .rar and .7z files on the Desktop
$filesToCopy = Get-ChildItem -Path $desktopPath -Filter "OfficeRTool.*" | Where-Object { $_.Extension -match "^\.(rar|7z)$" }

# Copy the selected files from Desktop to the destination folder
$filesToCopy | ForEach-Object {
    Write-Host
    Write-Host "Copying file: $($_.Name) from Desktop to $destinationPath"
    Copy-Item -Path $_.FullName -Destination $destinationPath -Force
}

# --- Set Location to Parent Folder ---
Set-Location $parentFolder

# --- Extract CurrentVersion from OfficeRTool.cmd ---
$officeRToolCmdPath = Join-Path $parentFolder "OfficeRTool.cmd"

$CurrentVersion = $null

# Check if OfficeRTool.cmd exists
if (Test-Path $officeRToolCmdPath) {
    Write-Host
    Write-Host "OfficeRTool.cmd found in $parentFolder"
    
    # Read the entire file as a single string, then split by newline
    $content = Get-Content $officeRToolCmdPath -Raw
    $lines = $content -split "`n"

    # Search for the line that sets the Currentversion variable
    $versionLine = $lines | Where-Object { $_ -match 'set\s+"?Currentversion\s*=\s*[\d\.]+' }

    # Extract just the version number from that line
    if ($versionLine -match 'Currentversion\s*=\s*([\d\.]+)') {
        $CurrentVersion = $Matches[1]
        Write-Host "CurrentVersion extracted: $CurrentVersion"
    } else {
        Write-Warning "CurrentVersion pattern not matched correctly in OfficeRTool.cmd"
    }
} else {
    Write-Warning "OfficeRTool.cmd not found in parent folder"
}

# --- Create the RAR file on the Desktop ---
if ($CurrentVersion) {
    # Get the Desktop path for the current user
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')

    # Define the output RAR file name
    $rarFileName = "OfficeRTool-v$CurrentVersion.rar"
    $rarFilePath = Join-Path $desktopPath $rarFileName
    
    # Check if the RAR file already exists and remove it
    if (Test-Path $rarFilePath) {
        Write-Host "Removing existing RAR file: $rarFilePath"
        Remove-Item $rarFilePath -Force
        Start-Sleep 1
    }

    # Ensure the folder exists before proceeding
    if (-not (Test-Path $parentFolder)) {
        Write-Warning "The folder $parentFolder does not exist, aborting RAR creation."
    } else {
        # Path to the WinRAR executable
        $rarExePath = Join-Path $env:ProgramFiles "WinRAR\rar.exe"

        # Set the password as the current year
        $currentYear = (Get-Date).Year
        $password = $currentYear.ToString()  # Current year as the password

        # Define the arguments for creating the RAR file
        $arguments = "a -s -r -ep1 -MT12 -m5 -ma5 -md256m -hp$password `"$rarFilePath`" *"

        # Start the process to create the RAR file
        Set-Location $parentFolder
        Start-Process -FilePath $rarExePath -ArgumentList $arguments -WindowStyle Hidden -Wait

        Write-Host "Created RAR file: $rarFilePath"
    }
} else {
    Write-Warning "No version found, aborting RAR creation"
}



# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUKQr55stasES7hsWaMgz4lrlg
# 0digggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFF6l
# 9txvJ5LsAKjYHCJum2d60COyMA0GCSqGSIb3DQEBAQUABIIBAMPUrCc+E1AUuJ7l
# a5fkLf+Vf3bItLTg5hOMbiw2rcfN9IzvBkseamVHdb53uxYvLTPj2+qoq+jobkYE
# 5s1k3OKrvUIIF0D+Hgip5SDOd296EYxavmP0njAvZGO5lRI/cFuMNlbXagsoeM7h
# OhqX4kfIuAv2e1qbu6DKWC6AvwBcAUmPyZO1I9TGsfd7+TeXCJasWe5etYneBpDV
# AeBjCgpmtZKLUm17P+iS9jNtTgpnSRE/Mhk+Zz/Ot8vckphOnBR7f5Mmg18i7hAP
# T8xOdL5NEqjelHuDidykwd18GXjxPNTnZ5tULO1KaP0RHEEiuU76FXl8wHY8bK/w
# fkDv8oA=
# SIG # End signature block
