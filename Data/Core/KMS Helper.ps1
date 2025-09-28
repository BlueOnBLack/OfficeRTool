# powershell catch exception codes for wmi query
# https://stackoverflow.com/questions/29923588/powershell-catch-exception-codes-for-wmi-query

# gwim ... gcim ... maybe i change it later ...
# gwmi is much better, GetPropertyValue, method invoke .. etc

if ($Args[0] -eq '/QUERY_BASIC') {
 $class = $Args[2];
 $value = @($Args[1]).Replace(' ','')
 $wmi_Object = gwmi -Query "select $($value) from $($class)" -ea 0
 if (-not $wmi_Object) {
   return "Error:WMI_SEARCH_FAILURE" 
 }
 foreach ($item in $wmi_Object) {
  $line = '';
  $value.Split(",")|%{$line += ",$($item.GetPropertyValue("$_"))"}
  Write-Host $line
 }
 return
}

if ($Args[0] -eq '/QUERY_ADVENCED') {
 $class  = $Args[2];
 $filter = $Args[3];
 $value  = @($Args[1]).Replace(' ','')
 $wmi_Object = gwmi -Query "select $($value) from $($class) where ($($filter))" -ea 0
 if (-not $wmi_Object) { 
   return "Error:WMI_SEARCH_FAILURE" 
 }
 foreach ($item in $wmi_Object) {
  $line = '';
  $value.Split(",")|%{$line += ",$($item.GetPropertyValue("$_"))"}
  Write-Host $line
 }
 return
}

if ($Args[0] -eq '/ACTIVATE') {
 $CLASS = $Args[1]
 $ID    = $Args[2]
 $ErrorActionPreference = "Stop"
  try {
   (gwmi $class | ? ID -EQ $ID).Activate()
   return "Error:0"
 }
 catch {
  # return wmi last error, in hex format
  $HResult = ‘{0:x}’ -f  @($_.Exception.InnerException).HResult
  return "Error:$($HResult)"
 }
}

if ($Args[0] -eq '/UninstallProductKey') {
 $CLASS  = $Args[1]
 $FILTER = $Args[2]

 try {
   (gwmi $CLASS -f $FILTER).UninstallProductKey()
   #(gwmi -Query "select * from $($CLASS) where ($($FILTER))").UninstallProductKey()
   return "Error:0"
  }
 catch {
   # return wmi last error, in hex format
   $HResult = ‘{0:x}’ -f  @($_.Exception.InnerException).HResult
   return "Error:$($HResult)"
 }
}

if ($Args[0] -eq '/InstallProductKey') {
 $KEY  = $Args[1]
 $ErrorActionPreference = "Stop"

 try {
  (gwmi SoftwareLicensingService).InstallProductKey($KEY)
  return "Error:0"
 }
 catch {
  # return wmi last error, in hex format
  $HResult = ‘{0:x}’ -f  @($_.Exception.InnerException).HResult
  return "Error:$($HResult)"
 }
}

if ($Args[0] -eq '/InstallLicense') {
 $LicenseFile      = $Args[1]
 $ErrorActionPreference = "Stop"
 
 if([IO.File]::Exists($LicenseFile)-ne $true) {
	return "Error:FILE_NOT_FOUND" }

 try {
  (gwmi SoftwareLicensingService).InstallLicense(
    @([IO.File]::ReadAllText($LicenseFile)))
  return "Error:0"
 }
 catch {
  # return wmi last error, in hex format
  $HResult = ‘{0:x}’ -f  @($_.Exception.InnerException).HResult
  return "Error:$($HResult)"
 }
}

 if ($Args[0] -eq '/rilc') {

  # Private Sub ReinstallLicenses()
  #   strOemFolder = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\system32\oem"
  #   strSppTokensFolder = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\system32\spp\tokens"
  #   Set folder = fso.GetFolder(strSppTokensFolder)
  #   For Each subFolder in folder.SubFolders
  #       InstallLicenseFiles subFolder, fso
  #   Next
  #   If (fso.FolderExists(strOemFolder)) Then
  #       InstallLicenseFiles strOemFolder, fso
  #   End If
  # End Sub

  $LicensingService = gwmi SoftwareLicensingService -ea 1
  if (-not $LicensingService) {
	  return }
  
  $pathList = (
    (Join-Path $ENV:SystemRoot "system32\oem"),
    (Join-Path $ENV:SystemRoot "system32\spp\tokens"))

  foreach ($loc in $pathList) {
    if (Test-Path $loc) {
      dir $loc *.xrm-ms -Recurse -force -Name | % {
        $LicenseFile = Join-Path $loc $_
        "Install License: $($LicenseFile)"
        $LicensingService.InstallLicense(
          [IO.FILE]::ReadAllText($LicenseFile)) | Out-Null }}}
}

if ($Args[0] -eq '/ato') {

  #objProduct.Activate()
  #objService.RefreshLicenseStatus()
  #objProduct.refresh_

  $LicensingService = gwmi SoftwareLicensingService -ea 1
  $LicensingProduct = gwmi SoftwareLicensingProduct -F "(ApplicationId='55c92734-d682-4d71-983e-d6ec3f16059f' and PartialProductKey is not null)" -ea 1
  if (-not $LicensingProduct) {
    return }
  if (-not $LicensingService) {
    return }
  $LicensingProduct.Activate()
  $LicensingService.RefreshLicenseStatus()
  $LicensingProduct.refresh_
}

return $null


# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYgDhi4BBbFsx/yxy09y1JB2L
# WXegggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOTT
# +pk5Qaji1pggpkF2WP7jJPJLMA0GCSqGSIb3DQEBAQUABIIBAHkIi842CshFGA1B
# 8PE/CjANhbCfkiiBZuZLnWIZ64GLzXeJrOMQy7o6jaQTxwglu8sVHjx564JKlgs+
# 3OLTMcqx00AyXzhikx1DyfyCAqa7lAFgBbZ0y2DpfhylarQFVW8fFZJb8LUaF3JJ
# AJganRcBSNLXeJSWcMM449EQYLeFWpfdOaz1H6IAZHdArlc6YybjBMCSaxGzIn8K
# KDHtYQTT0I+hHlEYPPp/gZwfLtgJP60Y8Lm3lprCfWBUm1ZXAUnB7PK2OWPK7ssU
# zsdWhfB9kofztfizqIjoGwrQsePGMRR7YcPcVN7YtPxIDEJFsBFxAXeoegdvlTsa
# +Kg56dI=
# SIG # End signature block
