function get_latest_version_WC {
	
	$url = '^https?:\/\/(.*).exe"$'
	$sku = 'ms.dlcfamilyid|ms.dlcproductid|ms.dwntype' # 'https?:\/\/(.*).exe'
	$tmp = join-path $env:windir -ChildPath 'temp\officedeploymenttool.raw'
	$lnk = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117'

	if (test-path $tmp) {del $tmp | Out-Null}
	try {
	  (New-Object System.Net.WebClient).DownloadFile($lnk, $tmp)
	}
	catch {
	   return
	}
	if (!(test-path $tmp)) {
		return
	}
	
	foreach ($val in @(Get-Content $tmp)) {
	  if ($val -match $sku){
		sv -Name "sec" -Value $val -Scope global -force
		break;
	  }
	}
	
	if (!($sec)) {
	  return
	}
	
	foreach ($val in $sec.Split('=')) {
	  if ($val -match $url){
		return $val.TrimEnd('"')
	  }
	}
}

function get_latest_version_WR {
	
	$url = '^https?:\/\/(.*).exe$'
	$lnk = 'https://www.microsoft.com/en-us/download/details.aspx?id=49117'
	
	try {
		$ProgressPreference = 'SilentlyContinue'    # Subsequent calls do not display UI.
		$req = iwr -URI $lnk
		$ProgressPreference = 'Continue'            # Subsequent calls do display UI.
	}
	catch {
		$ProgressPreference = 'Continue'            # Subsequent calls do display UI.
		return
	}
	<# $uri = $req.Links | ? data-bi-cn -eq 'click here to download manually' #>
	$uri = $req.Links | ? href -match $url | select-object -first 1
	if ($uri) {
	  return @($uri).Href
	}
}

<# if ($env:terminalFound) {
	get_latest_version_WC;
	return
} #>

<# get_latest_version_WR
return #>

# 
get_latest_version_WR
return
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4J3a5PzARSRdQfnVATCPr4Ay
# Rj+gggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMCK
# INtQLPAz9vverMJ6M28BhQ+WMA0GCSqGSIb3DQEBAQUABIIBAMNNzwhRMPCi4c5Y
# fcjB4QPpDPpTdA3sV6/IJx76wVZ2DAvDaWxc9e1NVlrXWFr4NrKAPuox3PWSmtb3
# kTsHhMIWqhXlUH+d+ISMYoL0j1ToUBOl6nlfNAMdqvJvLB5TVnmkJx8m5sOsa6dM
# tztX9iwu4c15mJfAwtSxN8xK6mduJ25PAJ5jbgoqB558coxnIFR0v5Ypxu1NsNVe
# 304UYRSoS6fBk4CAeBw6/7Ajo/HVenbh0WhYmrQwEeUc27fcubjt60WbEtIwvnYf
# klU7eg2F7rmcDCBWd0chmUXA/Lg77zBGDqKF2EtdMuGQsu7s95Ma5M6IOgPboZTr
# RbN4QAA=
# SIG # End signature block
