
<#
version      : 3.0
Release Date : 09-02-2024
Made By      : Dark Dinosaur, MDL
#>

Function Office_Offline_Install (
  [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
  [String] $FFNRoot,

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
  $type = "LOCAL"
  $vSys = $ENV:instarch1
  $bUrl = """$(Get-Location)"""
  $sUrl="http://officecdn.microsoft.com/pr/$FFNRoot"
  $sCulture = $aLang.TrimStart('_')
  $misc = "flt.useoutlookshareaddon=unknown flt.useofficehelperaddon=unknown"

  $sAppList = ''
  $oApps.TrimStart(',').Split(',') | % {$sAppList += "$($_).16_$($sCulture)_x-none|"}
  $sAppList = $sAppList.TrimEnd('|')
  
  if ([REGEX]::IsMatch((Get-Location),"^[A-Z]:\\$", [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
    $bUrl = $bUrl.Substring(0,3) + '"' }
  
  echo ''
  echo 'Please hold until the setup is finished'
  echo ''
  
  Push-Location "$ENV:CommonProgramFiles\Microsoft Shared\ClickToRun"
  start OfficeClickToRun.exe -args "platform=$vSys culture=$mLang productstoadd=$sAppList $($Exclude) cdnbaseurl.16=$sUrl baseurl.16=$bUrl version.16=$oVer mediatype.16=$type sourcetype.16=$type updatesenabled.16=True acceptalleulas.16=True displaylevel=True bitnessmigration=False deliverymechanism=$FFNRoot $misc" -Wait
}

if ($args[5]) {
  Office_Offline_Install $args[0] $args[1] $args[2] $args[3] $args[4] $args[5]
  return
}

Office_Offline_Install $args[0] $args[1] $args[2] $args[3] $args[4]
return


# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUh/DW/DkBrpT2RUz/JNo0q4uN
# DkOgggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKoT
# 5B/b2ISgIZHB1aI63O4WINQNMA0GCSqGSIb3DQEBAQUABIIBAJjgD26Mz04hkhPl
# yqMTiG2icwEVUmce6iR2xaD+6fgdLFSK3iQn7amqsISNFOeIOjO7KrT3yMcV45gw
# Ufoma5+8CCQO/YTmO3qEx1uItdTEn12wxh2hSIu/NxCl4k+b/0+vyhw1nyMMIRh3
# ZbsCX0docnxr7iAgtQW1FjwwU2Ow54MjwODd414HGjFKAg9LMk5ZhUgzokDBkJfy
# b+fhR0IPztEtFsIbV4wdSdnUljPI0TN/dvZyiyXBuHRPvOLPbBxBWaBFCalhaByk
# Rvm2op0b4zAU/zeSxYjV74M8iI1Nve8h0ZloA/oC8vtG1T0iXLejvLIcKf3HgeQ8
# t/pTrbc=
# SIG # End signature block
