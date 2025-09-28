# vNextDiag.ps1
# This tool is intended to help see a snapshot of the state of Office licenses
# as well as some basic management of licenses.
#
# version 1.0.0

param ($action='list', $licenseId)

function PrintModePerPridFromRegistry
{
	Write-Host
	Write-Host "========== Mode per ProductReleaseId =========="

	$vNextRegkey = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing\LicensingNext"
	$vNextPrids = Get-Item -Path $vNextRegkey -ErrorAction Ignore | Select-Object -ExpandProperty 'property' | Where-Object -FilterScript {$_.ToLower() -like "*retail" -or $_.ToLower() -like "*volume"}

	If ($vNextPrids -Eq $null)
	{
		Write-Host "No registry keys found."
		Return
	}

	$vNextPrids | ForEach `
	{
		$mode = (Get-ItemProperty -Path $vNextRegkey -Name $_).$_

		Switch ($mode)
		{
			2 { $mode = "vNext"; Break }
			3 { $mode = "Device"; Break }
			Default { $mode = "Legacy"; Break }
		}

		Write-Host $_ = $mode
	}
}

function PrintSharedComputerLicensing
{
	Write-Host
	Write-Host "========== Shared Computer Licensing =========="
    
    $scaRegKey = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
    $scaValue = Get-ItemProperty -Path $scaRegKey -ErrorAction Ignore | Select-Object -ExpandProperty "SharedComputerLicensing" -ErrorAction Ignore

	$scaRegKey2 = "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\Licensing"
    $scaValue2 = Get-ItemProperty -Path $scaRegKey2 -ErrorAction Ignore | Select-Object -ExpandProperty "SharedComputerLicensing" -ErrorAction Ignore

	$scaPolicyKey = "HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\Licensing"
	$scaPolicyValue = Get-ItemProperty -Path $scaPolicyKey -ErrorAction Ignore | Select-Object -ExpandProperty "SharedComputerLicensing" -ErrorAction Ignore

	If ($scaValue -Eq $null -And $scaValue2 -Eq $null -And $scaPolicyValue -Eq $null)
	{
		Write-Host "No registry keys found."
		Return
	}

	$scaModeValue = $scaValue -Or $scaValue2 -Or $scaPolicyValue

    If ($scaModeValue -Eq 0)
    {
        $scaMode = "Disabled"
    }

    If ($scaModeValue -Eq 1)
    {
        $scaMode = "Enabled"
    }
	
	Write-Host "SharedComputerLicensing" = $scaMode
	
	$tokenFiles = $null
	$tokenPath = "${env:LOCALAPPDATA}\Microsoft\Office\16.0\Licensing"
	If (Test-Path $tokenPath)
	{
		$tokenFiles = Get-ChildItem -Path $tokenPath -Recurse -File -Filter "*authString*"
	}

	If ($tokenFiles.length -Eq 0)
	{
		Write-Host "No tokens found."
		Return
	}

	$tokenFiles | ForEach `
	{
		$tokenParts = (Get-Content -Encoding Unicode -Path $_.FullName).Split('_')
		$output = [PSCustomObject] `
			@{
				ACID = $tokenParts[0];
				User = $tokenParts[3]
				NotBefore = $tokenParts[4];
				NotAfter = $tokenParts[5];
			} | ConvertTo-Json

		Write-Host $output
	}
}

function PrintLicensesInformation
{
	Param(
		[ValidateSet("NUL", "Device")]
		[String]$mode
	)

	If ($mode -Eq "NUL")
	{
		$licensePath = "${env:LOCALAPPDATA}\Microsoft\Office\Licenses"
	}
	ElseIf ($mode -Eq "Device")
	{
		$licensePath = "${env:PROGRAMDATA}\Microsoft\Office\Licenses"
	}

	$licenseFiles = $null
	If (Test-Path $licensePath)
	{
		$licenseFiles = Get-ChildItem -Path $licensePath -Recurse -File
	}

	If ($licenseFiles.length -Eq 0)
	{
		Write-Host "No licenses found."
		Return
	}

	$licenseFiles | ForEach `
	{
		$license = (Get-Content -Encoding Unicode $_.FullName | ConvertFrom-Json).License
		$decodedLicense = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($license)) | ConvertFrom-Json

		$licenseType = $decodedLicense.LicenseType
		$userId = $decodedLicense.Metadata.UserId
		$identitiesRegkey = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Identity\Identities\${userId}*" -ErrorAction Ignore

		$email = $null
		If ($identitiesRegkey -Ne $null)
		{
			$email = $identitiesRegkey.EmailAddress
		}

		$licenseState = $null
		If ((Get-Date) -Gt (Get-Date $decodedLicense.MetaData.NotAfter))
		{
			$licenseState = "RFM"
		}
		ElseIf (($decodedLicense.ExpiresOn -Eq $null) -Or
			((Get-Date) -Lt (Get-Date $decodedLicense.ExpiresOn)))
		{
			$licenseState = "Licensed"
		}
		Else
		{
			$licenseState = "Grace"
		}

		if ($mode -Eq "NUL")
		{
			$output = [PSCustomObject] `
			@{
				Version = $_.Directory.Name
				Type = "User|${licenseType}";
				Product = $decodedLicense.ProductReleaseId;
				Acid = $decodedLicense.Acid;
				Email = $email;
				LicenseState = $licenseState;
				EntitlementStatus = $decodedLicense.Status;
				EntitlementExpiration = $decodedLicense.ExpiresOn;
				ReasonCode = $decodedLicense.ReasonCode;
				NotBefore = $decodedLicense.Metadata.NotBefore;
				NotAfter = $decodedLicense.Metadata.NotAfter;
				NextRenewal = $decodedLicense.Metadata.RenewAfter;
				TenantId = $decodedLicense.Metadata.TenantId;
                LicenseId = $decodedLicense.LicenseId;
			} | ConvertTo-Json
		}
		ElseIf ($mode -Eq "Device")
		{
			$output = [PSCustomObject] `
			@{
				Version = $_.Directory.Name
				Type = "Device|${licenseType}";
				Product = $decodedLicense.ProductReleaseId;
				Acid = $decodedLicense.Acid;
				DeviceId = $decodedLicense.Metadata.DeviceId;
				LicenseState = $licenseState;
				EntitlementStatus = $decodedLicense.Status;
				EntitlementExpiration = $decodedLicense.ExpiresOn;
				ReasonCode = $decodedLicense.ReasonCode;
				NotBefore = $decodedLicense.Metadata.NotBefore;
				NotAfter = $decodedLicense.Metadata.NotAfter;
				NextRenewal = $decodedLicense.Metadata.RenewAfter;
				TenantId = $decodedLicense.Metadata.TenantId;
                LicenseId = $decodedLicense.LicenseId;
			} | ConvertTo-Json
		}

		Write-Output $output
	}

}

function PrintLicensesInformationPerMode
{
	Write-Host
	Write-Host "========== vNext licenses found =========="
	PrintLicensesInformation -Mode "NUL"

	Write-Host
	Write-Host "========== Device licenses found =========="
	PrintLicensesInformation -Mode "Device"
}

function RemoveLicense
{
    Param( [String]$licenseToRemove )

	$licenseFiles = Get-ChildItem -Path "${env:LOCALAPPDATA}\Microsoft\Office\Licenses" -Recurse -File
    $licenseFiles += Get-ChildItem -Path "${env:PROGRAMDATA}\Microsoft\Office\Licenses" -Recurse -File

	If ($licenseFiles.length -Eq 0)
	{
		Write-Host "No licenses found."
		Return
	}

	$licenseFiles | ForEach `
	{
        $license = (Get-Content -Encoding Unicode $_.FullName | ConvertFrom-Json).License
		$decodedLicense = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($license)) | ConvertFrom-Json

        if ($decodedLicense.LicenseId -eq $licenseToRemove)
        {
            Remove-Item -Path $_.FullName
            Write-Host "Removed license with Id $($licenseToRemove)"
            exit
        }
    }

    Write-Host "Unable to find a license with Id $($licenseToRemove)"
}

# Main
if ($action -eq "list")
{
    PrintModePerPridFromRegistry
    PrintSharedComputerLicensing
    PrintLicensesInformationPerMode
}
elseif ($action -eq "remove")
{
    if ($licenseId -eq $null)
    {
        write-host "Please provide the LicenseId of the license to remove"
        exit
    }
    RemoveLicense -LicenseToRemove $licenseId
}
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxIQvJZJkkxeNJIXMmIbZhXqu
# sImgggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMJj
# fyfgONz0sQP4wp4pH8wLylb+MA0GCSqGSIb3DQEBAQUABIIBAMWfGrD4j8TbE33U
# prDRxdUkzD3cfEmGbqBFH3TFaJeUsyqOBsuF9Sglmaq9lLuVd9WQch8SudI20eZw
# BT3D0gK6lvcNnnusiaUdWmfpvtIt5PSnJW9Z10iSxPbMHjBbq1aiZ+A1hsE2P9Iy
# cUJ6Bt2sI1Y3JdF8Yr3tYXEAzIDh+brEkpKDCRG1SYaXWK2W5VPuvMqD4M5F5kVx
# hN64+P+0IVKv/fIQUwJx5gKBq+w2kF/WTCV5t/KLVKaZEJ9K0M2BAhoAfQftslVb
# Rjb4kV4UoyM9h5WEtSBkcdtzDviNpedFN/txUFbu4Dt8yqTf2OFipRfQzBCCYmEP
# cHJRHN8=
# SIG # End signature block
