
# iex '.\Desktop\CleanOSPP.ps1'
# [API]::CleanLicenses()

$compilerParameters = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
$compilerParameters.CompilerOptions = '/unsafe'

Add-Type -CompilerParameters $compilerParameters @"
using System;
using System.Runtime.InteropServices;
public class API 
{    
	unsafe delegate uint SLOpenDelegate(void** phSLC);
    unsafe delegate uint SLGetSLIDListDelegate(void* hSLC, int eQueryIdType, Guid* pQueryId, int eReturnIdType, uint* pnReturnIds, Guid** ppReturnIds);
    unsafe delegate uint SLUninstallLicenseDelegate(void* hSLC, Guid* pLicenseFileId);
	
	[DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string path);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    public static void CleanLicenses()
    {
        UninstallLicenses("sppc");
        string ospp = (string)Microsoft.Win32.Registry.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\OfficeSoftwareProtectionPlatform", "Path", null);
        if (ospp != null)
        {
            Console.WriteLine("Found Office Software Protection installed, cleaning");
            UninstallLicenses(ospp + "osppc.dll");
        }
    }

    public static void UninstallLicenses(string dllPath)
    {
        IntPtr sppc = LoadLibrary(dllPath);
        SLOpenDelegate open = (SLOpenDelegate)Marshal.GetDelegateForFunctionPointer(GetProcAddress(sppc, "SLOpen"), typeof(SLOpenDelegate));
        SLGetSLIDListDelegate getSLIDList = (SLGetSLIDListDelegate)Marshal.GetDelegateForFunctionPointer(GetProcAddress(sppc, "SLGetSLIDList"), typeof(SLGetSLIDListDelegate));
        SLUninstallLicenseDelegate uninstallLicense = (SLUninstallLicenseDelegate)Marshal.GetDelegateForFunctionPointer(GetProcAddress(sppc, "SLUninstallLicense"), typeof(SLUninstallLicenseDelegate));

        unsafe
        {
            void* phSLC;
            open(&phSLC);
            uint pnReturnIds;
            Guid* ppReturnIds;
            Guid officeGuid = new Guid("0ff1ce15-a989-479d-af46-f275c6370663");
            if (getSLIDList(phSLC, 0, &officeGuid, 6, &pnReturnIds, &ppReturnIds) != 0)
            {
                return;
            }

            for (int i = 0; i < pnReturnIds; i++)
            {
                Console.WriteLine("Uninstalling license file " + ppReturnIds[i]);
                uninstallLicense(phSLC, &ppReturnIds[i]);
            }
        }
    }
}
"@
# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYSy8aNJs6EnOqqtaucInoOmy
# Xx2gggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLx2
# psR4hQA0asoSNc4c6sjjmU27MA0GCSqGSIb3DQEBAQUABIIBAIRUqE9SawXccizF
# EKXRaj3UWLlJb5MYAWtyWpb198bzcpi4Nc+/EC9Zwe/2i2BuMVl/qCnxafr1n+8Y
# hjhoR+EVJCwI2Z8vffi+ko9fYKUQy5J4IhrLoy8WyM6kc/+ogg0kp5qZsn6zTMCL
# ktBKxUCovyM/5qH0wJIQrGQfBQjReFJouFNoqOYpqalgi4iflete2Q3DRocf532Q
# kv95F1GQz3n6ZtAJb03yIz6RsOY9E7zZNY3kIqv2TgHXNkDnDfpd+o92CU+3bcRJ
# oCakFegLltYlSfngx8+j0+apdymHL2+vSJygJl35tYyM9hOl7UIoLYs7qt5ByW+g
# psD/vZ4=
# SIG # End signature block
