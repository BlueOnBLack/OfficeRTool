<# disabling the cmd close button by batch command #>
<# https://stackoverflow.com/questions/13763134/disabling-the-cmd-close-button-by-batch-command #>

$code = @'
using System;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace CloseButtonToggle {

 internal static class WinAPI {
   [DllImport("kernel32.dll")]
   internal static extern IntPtr GetConsoleWindow();

   [DllImport("user32.dll")]
   [return: MarshalAs(UnmanagedType.Bool)]
   internal static extern bool DeleteMenu(IntPtr hMenu,
                          uint uPosition, uint uFlags);

   [DllImport("user32.dll")]
   [return: MarshalAs(UnmanagedType.Bool)]
   internal static extern bool DrawMenuBar(IntPtr hWnd);

   [DllImport("user32.dll")]
   internal static extern IntPtr GetSystemMenu(IntPtr hWnd,
              [MarshalAs(UnmanagedType.Bool)]bool bRevert);

   const uint SC_CLOSE     = 0xF060;
   const uint SC_MAXIMIZE  = 0xF030;
   const uint SC_MINIMIZE  = 0xF020;
   const uint SC_SIZE      = 0xF000;
   const uint MF_BYCOMMAND = 0;

   internal static void ChangeCurrentState(IntPtr Console, bool state) {
     IntPtr hMenu = GetSystemMenu(Console, state);
	 DeleteMenu(hMenu, SC_SIZE, MF_BYCOMMAND);
	 DeleteMenu(hMenu, SC_MAXIMIZE, MF_BYCOMMAND);
     DrawMenuBar(Console);
   }
   internal static void ChangeCurrentState(bool state) {
	 IntPtr Console = GetConsoleWindow();
     IntPtr hMenu = GetSystemMenu(Console, state);
	 DeleteMenu(hMenu, SC_SIZE, MF_BYCOMMAND);
	 DeleteMenu(hMenu, SC_MAXIMIZE, MF_BYCOMMAND);
     DrawMenuBar(Console);
   }
 }

 public static class Status {
   public static void Disable(IntPtr Console) {
     WinAPI.ChangeCurrentState(Console, false); //its 'true' if need to enable
   }
   public static void Disable() {
     WinAPI.ChangeCurrentState(false); //its 'true' if need to enable
   }
 }
}
'@

Add-Type $code;
if (!($env:terminalFound)) {
	[CloseButtonToggle.Status]::Disable();
	exit;
}
if ($env:PROC_ID) {
	$ptr = @(Get-Process |where id -eq $env:PROC_ID).MainWindowHandle;
	[CloseButtonToggle.Status]::Disable($ptr);
	exit
}
if ($env:terminalFound) {
	foreach ($ptr in @(Get-Process -Name "windowsterminal" -ErrorAction SilentlyContinue).MainWindowHandle)  {
		[CloseButtonToggle.Status]::Disable($ptr);
	}
	exit
}
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURwjxws6TWIfhmkvJNBW0mrSF
# 2nGgggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOtX
# jXFELtRC0bZQP7hJ0oiX+LLwMA0GCSqGSIb3DQEBAQUABIIBACBDcMdEtGx+5u8H
# pZg2aPOJRBGlEXzYFWdpdzyWpdZaaST+oM43HUDeh5ayXF9fZChrBVHhHelgTPZM
# 9wJsFEHb4zrq9XIkr2Rvd68Gi2Fleqsj/ujGvvQY4i/qgU3fefkqP+YI97ECDI20
# BM65EY570WigG8oawgs3pgEolKL9CuAtnkrKgjaVzmXqBPQKjRaAqnB9OVo3l2yJ
# s6Ck/LMzCXd7Oe5VtCSVMhBIaF1UP4VOG0E2W8dP0M73MD9EEZQeljxvbYF7L2Go
# B/4GdCkkJnSGXWkAtqC6sojeNu5aaqe3+lxKFP8FFq7P3RlGynr0pzPuqd17F8gH
# PgOdRv0=
# SIG # End signature block
