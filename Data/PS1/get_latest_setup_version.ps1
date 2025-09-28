function get_latest_version {
	
	$filter = ' \/<>()'
	$uri   = 'https://learn.microsoft.com/en-us/officeupdates/odt-release-history'
	
	<# Origional version, have better one #>
	$regex = '[setup.exe]*[version]*[16].[0-9].[0-9][0-9][0-9][0-9][0-9].[0-9][0-9][0-9][0-9][0-9]'
	
	<# 16.x Prefix #>
	$regex_Lite = '^16\.[0-9]\.[0-9][0-9][0-9][0-9][0-9]\.[0-9][0-9][0-9][0-9][0-9]$'
	<# Start with <p> ~ *** ~ Group A, Setup.exe ~ *** ~ Group B, version ~ *** ~ Group C, 16.x Prefix ~ *** ~ end with </p> #>
	$regex_Full = '^\<p\>(.*)setup\.exe(.*)version(.*)16\.[0-9]\.[0-9][0-9][0-9][0-9][0-9]\.[0-9][0-9][0-9][0-9][0-9](.*)\<\/p\>$'
	
	try {
	  $ProgressPreference = 'SilentlyContinue'    # Subsequent calls do not display UI.	
	  $content = @(iwr -Uri $uri).RawContent 
	  $ProgressPreference = 'Continue'            # Subsequent calls do display UI.
	}
	catch { 
	  $ProgressPreference = 'Continue'            # Subsequent calls do display UI.
	  return
	}

	foreach ($val in @($content.Split("`n"))) {
	  if ($val -match $regex_Full) {
	    sv -Name "info" -Value $val -Scope global -force
		break
	  }
	}

	if ($info) {
	  $version = $info.Split($filter) | where {$_ -match $regex_Lite} | Select-Object -Last 1
	}
	if ($version) {
	  return $version
	}
}

get_latest_version;
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU468P++DCw0FKZabvkJv+od4z
# BoqgggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMF+
# imLi/Yl5bMPr0Ssf/RnBo9w9MA0GCSqGSIb3DQEBAQUABIIBABEOqHyX1NU8+Wxz
# Zv2V5QI5rFw0zrlsH178JmrweXwFHJhO2n+SkknwNt14DXqTc7QbWj511JgLQoDj
# EqfjPWqPV/9fEx3kqihHiPoayaYoujnJWqs2DKxxOaNjPP1z0ahcE+bKdcXVT9wx
# 8/p70ZezVtvFYUCBf19bKlb44xv66tbCBgK3hr8PXTupkHApKTOL6j4LG3v+buld
# G6opwcuo4CQ0lD1+ar1RDK87AW1e3HXRBJCRUE6lTsex80L6CVeiGHQnz4XjRx6O
# TQ83A+SXA4Xdnph7nKT3qSL3YDooiJEE+4bpeFCQNFuE1v12ws8D59UFvTxSEiWd
# cgq4wFI=
# SIG # End signature block
