$arr = @(
  @('MondoRetail','MondoVolume'),
  @('OneNoteRetail','OneNoteVolume'),
  @('ProPlusRetail','ProPlusVolume'),
  @('ProPlus2019Retail','ProPlus2019Volume'),
  @('ProPlus2021Retail','ProPlus2021Volume'),
  @('StandardRetail','StandardVolume'),
  @('Standard2019Retail','Standard2019Volume'),
  @('Standard2021Retail','Standard2021Volume'),
  @('ProjectProRetail','ProjectProVolume'),
  @('ProjectPro2019Retail','ProjectPro2019Volume'),
  @('ProjectPro2021Retail','ProjectPro2021Volume'),
  @('ProjectStdRetail','ProjectStdVolume'),
  @('ProjectStd2019Retail','ProjectStd2019Volume'),
  @('ProjectStd2021Retail','ProjectStd2021Volume'),
  @('VisioProRetail','VisioProVolume'),
  @('VisioPro2019Retail','VisioPro2019Volume'),
  @('VisioPro2021Retail','VisioPro2021Volume'),
  @('VisioStdRetail','VisioStdVolume'),
  @('VisioStd2019Retail','VisioStd2019Volume'),
  @('VisioStd2021Retail','VisioStd2021Volume'),
  @('WordRetail','WordVolume'),
  @('Word2019Retail','Word2019Volume'),
  @('Word2021Retail','Word2021Volume'),
  @('ExcelRetail','ExcelVolume'),
  @('Excel2019Retail','Excel2019Volume'),
  @('Excel2021Retail','Excel2021Volume'),
  @('PowerpointRetail','PowerpointVolume'),
  @('Powerpoint2019Retail','Powerpoint2019Volume'),
  @('Powerpoint2021Retail','Powerpoint2021Volume'),
  @('OutlookRetail','OutlookVolume'),
  @('Outlook2019Retail','Outlook2019Volume'),
  @('Outlook2021Retail','Outlook2021Volume'),
  @('AccessRetail','AccessVolume'),
  @('Access2019Retail','Access2019Volume'),
  @('Access2021Retail','Access2021Volume'),
  @('PublisherRetail','PublisherVolume'),
  @('Publisher2019Retail','Publisher2019Volume'),
  @('Publisher2021Retail','Publisher2021Volume'),
  @('SkypeForBusinessRetail','SkypeForBusinessVolume'),
  @('SkypeForBusiness2019Retail','SkypeForBusiness2019Volume'),
  @('ProPlusSPLA2021Volume','ProPlus2021Volume'),
  @('StandardSPLA2021Volume','Standard2021Volume'),
  @('ProjectProXVolume','ProjectProVolume'),
  @('ProjectStdXVolume','ProjectStdVolume'),
  @('VisioProXVolume','VisioProVolume'),
  @('VisioStdXVolume','VisioStdVolume'),
  @('O365ProPlusVolume','O365ProPlusRetail'),
  @('O365HomePremVolume','O365HomePremRetail'),
  @('O365BusinessVolume','O365BusinessRetail'),
  @('O365AppsBasicVolume','O365AppsBasicRetail')
)

$clr = Join-Path -Path $env:windir -ChildPath 'Temp\ONAME_CHANGE.REG'
if (test-path $clr) {
	$gcr  = Get-Content -Encoding Unicode $clr
	foreach ($itm in $arr) {
		#$gcr = $gcr.Replace($itm[0], $itm[1])
		$gcr = $gcr -replace $itm[0], $itm[1]
	}
	Set-Content -value $gcr -Encoding Unicode $clr
}
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxLGgkjsjlKBHSKk2f9+GISO0
# yPmgggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCxu
# OVNDCxz7JSk2ptHYAHyVDFp3MA0GCSqGSIb3DQEBAQUABIIBAAHUvGWiA1Ml8PTS
# CvYAOHO1wVhJJbAsDZrHhjkMZs0I+o8OZGSS2WWs0ZM9z9cSdE4FrwS20Y06QdUe
# KawRhZXtFA/hV3Ukl8V0wqiy3JChfHC3T4it17CPmgdHMx1hdaF5H2qNzNGHDe9N
# wl6r+5glusk6gHqwixJtLs/Gk3Z3iajWY989mgBk8mUV5ohYgS4uAAX7qQcsMOtq
# jF+4OOHcdCJgBbLzT544JDZbjqu2tCXdefixQd4kQdcsLj2m4luBEMI8SAKrl4t3
# Rqv8vK2NV9/IhT3/L57c5gDres9sUlG9pKI6UjH+tWJSU34DWoheSHbMBKBn3xHw
# 1IBFDhA=
# SIG # End signature block
