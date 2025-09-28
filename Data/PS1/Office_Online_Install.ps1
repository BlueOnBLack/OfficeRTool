
<#
version      : 3.0
Release Date : 09-02-2024
Made By      : Dark Dinosaur, MDL
#>
Function Get-Channels {
  $oProd = @{}
  $oProd.Add("BetaChannel","5440fd1f-7ecb-4221-8110-145efaa6372f")
  $oProd.Add("Current","492350f6-3a01-4f97-b9c0-c7c6ddf67d60")
  $oProd.Add("CurrentPreview","64256afe-f5d9-4f86-8936-8840a6a4f5be")
  $oProd.Add("DogfoodCC","f3260cf1-a92c-4c75-b02e-d64c0a86a968")
  $oProd.Add("DogfoodDCEXT","c4a7726f-06ea-48e2-a13a-9d78849eb706")
  $oProd.Add("DogfoodDevMain","ea4a4090-de26-49d7-93c1-91bff9e53fc3")
  $oProd.Add("DogfoodFRDC","834504cc-dc55-4c6d-9e71-e024d0253f6d")
  $oProd.Add("InsidersLTSC","2e148de9-61c8-4051-b103-4af54baffbb4")
  $oProd.Add("InsidersLTSC2021","12f4f6ad-fdea-4d2a-a90f-17496cc19a48")
  $oProd.Add("InsidersLTSC2024","20481F5C-C268-4624-936C-52EB39DDBD97")
  $oProd.Add("InsidersMEC","0002c1ba-b76b-4af9-b1ee-ae2ad587371f")   
  $oProd.Add("MicrosoftCC","5462eee5-1e97-495b-9370-853cd873bb07")
  $oProd.Add("MicrosoftDC","f4f024c8-d611-4748-a7e0-02b6e754c0fe")
  $oProd.Add("MicrosoftDevMain","b61285dd-d9f7-41f2-9757-8f61cba4e9c8")
  $oProd.Add("MicrosoftFRDC","9a3b7ff2-58ed-40fd-add5-1e5158059d1c")
  $oProd.Add("MicrosoftLTSC","1d2d2ea6-1680-4c56-ac58-a441c8c24ff9")
  $oProd.Add("MicrosoftLTSC2021","86752282-5841-4120-ac80-db03ae6b5fdb")
  $oProd.Add("MicrosoftLTSC2024","C02D8FE6-5242-4DA8-972F-82EE55E00671")
  $oProd.Add("MonthlyEnterprise","55336b82-a18d-4dd6-b5f6-9e5095c314a6")
  $oProd.Add("PerpetualVL2019","f2e724c1-748f-4b47-8fb8-8e0d210e9208")
  $oProd.Add("PerpetualVL2021","5030841d-c919-4594-8d2d-84ae4f96e58e")
  $oProd.Add("PerpetualVL2024","7983BAC0-E531-40CF-BE00-FD24FE66619C")
  $oProd.Add("SemiAnnual","7ffbc6bf-bc32-4f92-8982-f9dd17fd3114")
  $oProd.Add("SemiAnnualPreview","b8f9b850-328d-4355-9145-c59439a0c4cf")
  return $oProd
}
Function Office_Online_Install (
  [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
  [String] $Channel,

  [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
  [String] $oVer,

  [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
  [String] $oApps,

  [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
  [String] $mLang,

  [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
  [String] $aLang,

  [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
  [String] $Exclude
  )
{
  $IsX32=$Null
  $IsX64=$Null
  $file = $Null

  $IgnoreCase = [Text.RegularExpressions.RegexOptions]::IgnoreCase
  
  $oProductsId = Get-Channels
  if ($Channel -and ($oProductsId[$Channel] -eq $null)) {
    throw "ERROR: BAD CHANNEL"
  }

  # find FFNRoot value
  $FFNRoot = $oProductsId[$Channel]
  $sUrl="http://officecdn.microsoft.com/pr/$FFNRoot"

  ri @(Join-Path $env:TEMP VersionDescriptor.xml) -Force -ea 0
  Switch ([intptr]::Size) {
    4 { 
        $IsX32 = $true
        $IsX64 = $Null
      }
    8 {
        $IsX32 = $Null
        $IsX64 = $true
      }
  }


  $type = "CDN"
  $bUrl = $sUrl
  $sCulture = $aLang.TrimStart('_')
  $misc = "flt.useoutlookshareaddon=unknown flt.useofficehelperaddon=unknown"

  $sAppList = ''
  $oApps.TrimStart(',').Split(',') | % {$sAppList += "$($_).16_$($sCulture)_x-none|"}
  $sAppList = $sAppList.TrimEnd('|')
  
  gwmi Win32_Service | ? Name -Match "WSearch|ClickToRunSvc" | % {
    $_.StopService() | Out-Null }
  
  Get-Service -Name @("WSearch", "ClickToRunSvc") | 
    Stop-Service -Force -PassThru | Out-Null

  if ($IsX32) {
	$vSys = "x86"
    MD "$ENV:ProgramFiles(x86)\Common Files\Microsoft Shared\ClickToRun" -ea 0 | Out-Null
    $file = "$ENV:TEMP\i320.cab"
    ri $file -Force -ea 0
    iwr -Uri "$sUrl/Office/Data/$oVer/i320.cab" -OutFile $file -ea 0
    if (-not(Test-Path($file))){throw "ERROR: FAIL DOWNLOAD CAB FILE"}
    Expand $file -f:* "$ENV:ProgramFiles(x86)\Common Files\Microsoft Shared\ClickToRun" *>$Null
    Push-Location "$ENV:ProgramFiles(x86)\Common Files\Microsoft Shared\ClickToRun\"
  }

  if ($IsX64) {
	$vSys = "x64"
    MD "$ENV:ProgramFiles\Common Files\Microsoft Shared\ClickToRun" -ea 0 | Out-Null
    $file = "$ENV:TEMP\i640.cab"
    ri $file -Force -ea 0
    iwr -Uri "$sUrl/Office/Data/$oVer/i640.cab" -OutFile $file -ea 0
    if (-not(Test-Path($file))){throw "ERROR: FAIL DOWNLOAD CAB FILE"}
    Expand $file -f:* "$ENV:ProgramFiles\Common Files\Microsoft Shared\ClickToRun" *>$Null
    Push-Location "$ENV:ProgramFiles\Common Files\Microsoft Shared\ClickToRun\"
  }
  
  echo 'Please hold until the setup is finished'
  echo ''
  
  start OfficeClickToRun.exe -args "platform=$vSys culture=$mLang productstoadd=$sAppList $($Exclude) cdnbaseurl.16=$sUrl baseurl.16=$bUrl version.16=$oVer mediatype.16=$type sourcetype.16=$type updatesenabled.16=True acceptalleulas.16=True displaylevel=True bitnessmigration=False deliverymechanism=$FFNRoot $misc" -Wait
}

if ($args[5]) {
  Office_Online_Install $args[0] $args[1] $args[2] $args[3] $args[4] $args[5]
  return
}

Office_Online_Install $args[0] $args[1] $args[2] $args[3] $args[4]
return


# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUl/j6GvzevgEiBVkj+2Wi2K28
# 852gggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOq/
# djRQFZJUHduSslHh0zXUYX7sMA0GCSqGSIb3DQEBAQUABIIBAC9ZseIXP+UzgbpV
# NFLHxu0TTFp7dFODe8bIff/Y5gzaLQs0Qd9ehL2fbWpJdVwaFmbWQBjTjEpxa0TG
# g/FiE5O1s3WvK2i42ULwZ5vldt2v57skvH0Ay6bgYicSLTOemU4lqZS5SY48PKQR
# jlq0Fktg+/zQ9c43GBssNxi88qLiZie9eoKDVFeoY+omIqy+zAq/WoNLqNTqne7j
# uGpWeYrUFgVlOEFTnMo6ixSmh1KpQdOQ8rh/x/lKl4ZBNU3aluhywVf9b3aqvuZN
# CIWpRu1wUQUGE1gDiRHXwXds+rHlbcCJx//fV2GZJuecHymoGGzP7fnxyr4UXX1w
# t9LwLM4=
# SIG # End signature block
