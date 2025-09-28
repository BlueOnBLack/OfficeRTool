# Check the internet performance using Powershell?
# https://www.joakimnordin.com/is-it-possible-to-check-the-internet-performance-at-a-clients-network-using-powershell/

if ($Args[0] -match 'Get') {  $Speedtest = cmd /c "$env:speedtest" --format=json --accept-license --accept-gdpr 2>$null | ConvertFrom-Json
  if (-not $Speedtest) {throw 'Fail to get information'}  [PSCustomObject]$SpeedObject = @{  	downloadspeed = [math]::Round($Speedtest.download.bandwidth / 1000000 * 8, 2)  	uploadspeed   = [math]::Round($Speedtest.upload.bandwidth / 1000000 * 8, 2)  	packetloss    = [math]::Round($Speedtest.packetLoss)  	isp           = $Speedtest.isp  	ExternalIP    = $Speedtest.interface.externalIp  	InternalIP    = $Speedtest.interface.internalIp  	UsedServer    = $Speedtest.server.host  	URL           = $Speedtest.result.url  	Jitter        = [math]::Round($Speedtest.ping.jitter)  	Latency       = [math]::Round($Speedtest.ping.latency)  }  return @(    [Math]::Round($SpeedObject.downloadspeed / 10))
}

if ($Args[0] -match 'Set') {
  $gcr  = Get-Content -Encoding Ascii .\Settings.ini -ErrorAction Stop;
  for ($num = 1 ; $num -le $gcr.Length ; $num++) {
    if ($gcr[$num] -match 'Speed_Limit') {
      $gcr[$num]="Speed_Limit=$($env:Speed_Limit)"
      break;
    }}
  Set-Content -value $gcr -Encoding Ascii .\Settings.ini
  return;
}
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5VrPGFeUg9dJVni+rnTlAD3d
# msqgggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIxF
# rhkRdSRCpiSq5ErxR+Vvn6cfMA0GCSqGSIb3DQEBAQUABIIBAJQR4ASwA2IXVG/M
# ikKxsRwgGMYNHoETkgyrLGKSzuHq/cyoyfj6GMwCJiTOIBlTBSw4lLKECQBPjF3y
# j/Nhj3TJI1G+PaJ0o79dlfXFNZzcbCBvfKajEv/95IMl4lA4X2l4sk33254fPnhk
# p56HZabuPgdE0vl1DaFAMPwRe3K/SjHkxsGriSLGhvuRPDr+2Lz97yVTT3YsBt2U
# 6y3dhYu73846oE0NYzIPt2OhbYkuzdHc/XwgwqDgsDn/Xj01Q6biLNk2rXtH1Saw
# 1uW/hjS4oDgv/uCC0ukxdOnPRPQKt3o+lt9yNWORVBPIVapgx7MqsPeZPLrEup7P
# eicSK/g=
# SIG # End signature block
