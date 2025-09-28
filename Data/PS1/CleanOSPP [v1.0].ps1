# https://github.com/ave9858
# https://gist.github.com/ave9858/9fff6af726ba3ddc646285d1bbf37e71

function UninstallLicenses($DllPath) {
    $DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False)
    $TypeBuilder = $ModuleBuilder.DefineType('sppc', 'Public, Class')
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $FieldArray = [Reflection.FieldInfo[]] @([Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'))

    $Open = $TypeBuilder.DefineMethod('SLOpen', [Reflection.MethodAttributes] 'Public, Static', [int], @([IntPtr].MakeByRefType()))
    $Open.SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @($DllPath),
                $FieldArray,
                @('SLOpen'))))

    $GetSLIDList = $TypeBuilder.DefineMethod('SLGetSLIDList', [Reflection.MethodAttributes] 'Public, Static', [int], @([IntPtr], [int], [guid].MakeByRefType(), [int], [int].MakeByRefType(), [IntPtr].MakeByRefType()))
    $GetSLIDList.SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @($DllPath),
                $FieldArray,
                @('SLGetSLIDList'))))

    $UninstallLicense = $TypeBuilder.DefineMethod('SLUninstallLicense', [Reflection.MethodAttributes] 'Public, Static', [int], @([IntPtr], [IntPtr]))
    $UninstallLicense.SetCustomAttribute((New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @($DllPath),
                $FieldArray,
                @('SLUninstallLicense'))))

    $SPPC = $TypeBuilder.CreateType()
    $Handle = [IntPtr]::Zero
    $SPPC::SLOpen([ref]$handle) | Out-Null
    $pnReturnIds = 0
    $ppReturnIds = [IntPtr]::Zero

    if (!$SPPC::SLGetSLIDList($handle, 0, [ref][guid]"0ff1ce15-a989-479d-af46-f275c6370663", 6, [ref]$pnReturnIds, [ref]$ppReturnIds)) {
        foreach ($i in 0..($pnReturnIds - 1)) {
            $SPPC::SLUninstallLicense($handle, [System.Int64]$ppReturnIds + [System.Int64]16 * $i) | Out-Null
        }    
    }
}

$OSPP = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform" -ErrorAction SilentlyContinue).Path
if ($OSPP) {
    <# Write-Output "Found Office Software Protection installed, cleaning" #>
    UninstallLicenses($OSPP + "osppc.dll")
}
UninstallLicenses("sppc.dll")

# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQvOcEdN4SQIJKKLp2YlVgcJI
# c1OgggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJV9
# s5Zrih+ikf6LMdnWTVBcxJhSMA0GCSqGSIb3DQEBAQUABIIBAA1wfGl84C8li/v2
# XNDUh6DbKCNf0bqH3X0Uny8aaa8PjwwHiZ2IK6X+FZ6/CMl3eb2ile6AD4Ny6dDD
# F6/VxvfArlpqeNjdPyiywiRiH59y61f+DxsV/DSLIBJirgBK6mdoiSyNbEqzWznJ
# NZE9ztoYXpOMjpgaIt+0/nuX+GfixzUWkdc6tyuKfc6uqt1En4xnyaGRhB1Ckqr7
# EohT/847+UT3A6eue+JG1kTq2LnRQu2ZnmMv9y5xp973s2qzM3yfRm0Vx4I8TEzg
# 7KtJTOZ+MCNIlZvqPOyxwI2CMW7kG7ZZJyokxJTejQB0/OL98Pkmjh/zLxFb6hwp
# BmISkN8=
# SIG # End signature block
