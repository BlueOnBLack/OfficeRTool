
timeout 2 | Out-Null
if ($env:S_ID) {
  $id = [INT]$env:S_ID
  while (@(gcim win32_process | where {($_.ParentProcessId -eq $id) -and ($_.Name -eq 'OfficeClickToRun.exe')}).Count -eq 0){
	timeout 2 | Out-Null
	if (@(gcim win32_process | where ProcessId -eq $id ).Count -eq 0) { 
	  echo 'error occurred during initialization of installation'
	  echo ''
	  exit
	}
  }
  echo 'Please hold until the setup is finished'
  echo ''
  while (@(gcim win32_process | where {($_.ParentProcessId -eq $id) -and ($_.Name -eq 'OfficeClickToRun.exe')}).Count -GT 0) {
    timeout 2 | out-null
  }
}
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUzjGjZY+r+AlumkwHj/kwXboN
# qD2gggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOLa
# Go0XWCN3rbsjZxBA0SWarsmZMA0GCSqGSIb3DQEBAQUABIIBAMn2PdMEmY3AhuYz
# QD3G5RMqAF8kg7wfqJPtmHjkgkS4WdDv1Oib0JO3+7zaG8rO2+uipB9iZUMAHxlv
# 4BDTtl33swYNqGHOU3a16Amr/9qer6lvYn/BL04k7zf3lUUQZKcwOkFSks9RI/Gf
# 9xBc3NjpmQ5qDt/UIHIqI8tfbGEATE1IVNAeKjWsLHIJxe8HkVCtHd0mePMS0R/Q
# koHH9oTAh5CGPWvq1UWEus6y4yYG7BTcyTSuYi8+cT/gruOoofQykTzVrQxOSuwn
# HXQp5GlFOEe/O7M5qVJLFFA1LmsbeDoCLChBjEVdxBHGAiX5fY1cRxyfQyt7HEia
# mFT3bZg=
# SIG # End signature block
