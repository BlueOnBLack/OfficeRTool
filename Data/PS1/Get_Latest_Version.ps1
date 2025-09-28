Function Convert-To-System {
   param (
     [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
     [string] $NAME
   )
  
  switch ($NAME){
   "ARM"      {return "ARM"}
   "CHPE"     {return "CHPE"}
   "Win7"     {return "7.0"}
   "Win8"     {return "8.0"}
   "Win8.0"   {return "8.0"}
   "Win8.1"   {return "8.1"}
   "Default"  {return "10.0"}
   "RDX Test" {return "RDX"}
  }
  return "Null"
}

Function Convert-To-Channel {
   param (
     [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Mandatory)]
     [string] $FFN
   )
  
  switch ($FFN){
   "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" {return "Current"}
   "64256afe-f5d9-4f86-8936-8840a6a4f5be" {return "CurrentPreview"}
   "5440fd1f-7ecb-4221-8110-145efaa6372f" {return "BetaChannel"}
   "55336b82-a18d-4dd6-b5f6-9e5095c314a6" {return "MonthlyEnterprise"}
   "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" {return "SemiAnnual"}
   "b8f9b850-328d-4355-9145-c59439a0c4cf" {return "SemiAnnualPreview"}
   "f2e724c1-748f-4b47-8fb8-8e0d210e9208" {return "PerpetualVL2019"}
   "5030841d-c919-4594-8d2d-84ae4f96e58e" {return "PerpetualVL2021"}
   "7983BAC0-E531-40CF-BE00-FD24FE66619C" {return "PerpetualVL2024"}
   "ea4a4090-de26-49d7-93c1-91bff9e53fc3" {return "DogfoodDevMain"}
   "f3260cf1-a92c-4c75-b02e-d64c0a86a968" {return "DogfoodCC"}
   "c4a7726f-06ea-48e2-a13a-9d78849eb706" {return "DogfoodDCEXT"}
   "834504cc-dc55-4c6d-9e71-e024d0253f6d" {return "DogfoodFRDC"}
   "5462eee5-1e97-495b-9370-853cd873bb07" {return "MicrosoftCC"}
   "f4f024c8-d611-4748-a7e0-02b6e754c0fe" {return "MicrosoftDC"}
   "b61285dd-d9f7-41f2-9757-8f61cba4e9c8" {return "MicrosoftDevMain"}
   "9a3b7ff2-58ed-40fd-add5-1e5158059d1c" {return "MicrosoftFRDC"}
   "1d2d2ea6-1680-4c56-ac58-a441c8c24ff9" {return "MicrosoftLTSC"}
   "86752282-5841-4120-ac80-db03ae6b5fdb" {return "MicrosoftLTSC2021"}
   "C02D8FE6-5242-4DA8-972F-82EE55E00671" {return "MicrosoftLTSC2024"}
   "2e148de9-61c8-4051-b103-4af54baffbb4" {return "InsidersLTSC"}
   "12f4f6ad-fdea-4d2a-a90f-17496cc19a48" {return "InsidersLTSC2021"}
   "20481F5C-C268-4624-936C-52EB39DDBD97" {return "InsidersLTSC2024"}
   "0002c1ba-b76b-4af9-b1ee-ae2ad587371f" {return "InsidersMEC"}
  }
  return "Null"
}

Function Get-Office-Apps {
   param (
     [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
     [string] $FFN
   )
  
  $ProgressPreference = 'SilentlyContinue'
  $URI = 'https://clients.config.office.net/releases/v1.0/OfficeReleases'
  $URI = 'https://mrodevicemgr.officeapps.live.com/mrodevicemgrsvc/api/v2/C2RReleaseData'
  $REQ = IWR $URI -ea 0

  if (-not $REQ) {
    return $null
  }

  $Json = $REQ.Content | ConvertFrom-Json
  return $Json|Sort-Object -Property @{Expression = "FFN"; Descending = $true},@{Expression = "Name"; Descending = $true},@{Expression = "AvailableBuild"; Descending = $true}|select @{Name='Channel'; Expr={$_.FFN|Convert-To-Channel}},FFN,@{Name='Build'; Expr={$_.AvailableBuild}},@{Name='System'; Expr={$_.Name|Convert-To-System}}
}

# ISE - PS
# .\Test.ps1 'Current' '10.0'

# Terminal & Console
# powershell -nop -f ".\XXX.ps1" "Current" "10.0"

if ($args[1]) {
  $channel = $args[0]
  $System  = $args[1]
  $oApp = Get-Office-Apps|?{(($_.Channel -eq $channel) -or ($_.FFN -eq $channel)) -and ($_.System -eq $System)}
  return $oApp.Build
}

# ISE - PS
# .\Test.ps1 'Current'

# Terminal & Console
# powershell -nop -f ".\XXX.ps1" "Current"

if ($args[0]) {
  $channel = $args[0]
  $oApps = Get-Office-Apps|?{($_.Channel -eq $channel) -or ($_.FFN -eq $channel)}
  foreach ($oApp in $oApps) {
    "$($oApp.Build),$($oApp.System)"
  }
  return
}

if (!$args) {
  $oApps = Get-Office-Apps
  foreach ($oApp in $oApps) {
    "$($oApp.Channel),$($oApp.FFN),$($oApp.Build),$($oApp.System)"
  }
  return
}
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTf8fPhkrqdvts10NZUgIx8Vm
# WrCgggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEev
# Wud2HXJ2pBp2z2mSfcInS73IMA0GCSqGSIb3DQEBAQUABIIBAH0wPmvVRQz8nD8w
# +LRE86piD/+NS0FnJ542j7ULZH328XH6Ij+r1o3xl1H+Q3Nz3WBba2Cl3mMSQyfX
# LHKX71516vddKJi/77bc0a6wGZPwHlgyd+Vwj0MK8HtQRfwdgPwlQl0QRlv2+OP5
# qJMsP3poT07aUccnDQduVgrggHypd5Lbf2GWPzzrJ3KfUIavFlwdx99FZvdywmEF
# Si0XFKtUDiS5wNAa/bGNd11WlzP2HFWWedgN4RKcwLaT6DMLs+rk1pMvrMNwiYEh
# /8hDjwVCV8OCTgkgmlyLpNQfONp+L/uMzeP0LbLS5ds7k6ZcZRMc44XkoX9dLZR2
# z1Of2Ac=
# SIG # End signature block
