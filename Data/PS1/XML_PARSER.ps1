
$IgnoreCase = 
  [Text.RegularExpressions.RegexOptions]::IgnoreCase

$channel_pattern = 
  "^(Current|CurrentPreview|BetaChannel|MonthlyEnterprise|SemiAnnual|SemiAnnualPreview|PerpetualVL2019|PerpetualVL2021|PerpetualVL2024|DogfoodDevMain)$"
  
$variables =  ''
$variables += "(%)("
$variables += "ALLUSERSPROFILE|APPDATA|CommonProgramFiles|CommonProgramFiles(x86)|CommonProgramW6432|HOMEDRIVE|USERPROFILE|"
$variables += "HOMEPATH|LOCALAPPDATA|TEMP|SystemDrive|SystemRoot|PUBLIC|ProgramData|ProgramFiles|ProgramFiles(x86)|ProgramW6432|UserName"
$variables += ")(%)"

$guid_pattern =  '^'
$guid_pattern += "([0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][-][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z])"
$guid_pattern += "-"
$guid_pattern += "([0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z])"
$guid_pattern += "-"
$guid_pattern += "([0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z])"
$guid_pattern += "-"
$guid_pattern += "([0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z][0-9|a-z])"
$guid_pattern += '$'

$lang_list =  '^('
$lang_list += "af-za|sq-al|am-et|ar-sa|hy-am|as-in|az-latn-az|bn-bd|bn-in|eu-es|be-by|bs-latn-ba|"
$lang_list += "bg-bg|ca-es-valencia|ca-es|zh-cn|zh-tw|hr-hr|cs-cz|da-dk|prs-af|nl-nl|en-GB|en-us|"
$lang_list += "et-ee|fil-ph|fi-fi|fr-CA|fr-fr|gl-es|ka-ge|de-de|el-gr|gu-in|ha-Latn-NG|he-il|hi-in|hu-hu|"
$lang_list += "is-is|ig-NG|id-id|ga-ie|it-it|ja-jp|kn-in|kk-kz|km-kh|sw-ke|rw-RW|kok-in|ko-kr|ky-kg|lv-lv|"
$lang_list += "lt-lt|lb-lu|mk-mk|ms-my|ml-in|mt-mt|mi-nz|mr-in|mn-mn|ne-np|nn-no|nb-no|or-in|ps-AF|fa-ir|"
$lang_list += "pl-pl|pt-br|pt-pt|pa-in|quz-pe|ro-ro|rm-CH|ru-ru|tn-ZA|gd-gb|sr-cyrl-ba|sr-cyrl-rs|sr-latn-rs|"
$lang_list += "nso-ZA|sd-arab-pk|si-lk|sk-sk|sl-si|es-es|es-MX|sv-se|ta-in|tt-ru|te-in|th-th|tr-tr|tk-tm|"
$lang_list += "uk-ua|ur-pk|ug-cn|uz-latn-uz|vi-vn|cy-gb|wo-SN|yo-NG|xh-ZA|zu-ZA"
$lang_list += ")$"

Function SetDummyVar {
  param (
   [parameter(Mandatory=$True)]
   [string]$Name
  )
  sv $Name 1 -Force -Scope Global
}

function ParseXML {
	
  param (
   [parameter(Mandatory=$True)]
   [System.Xml.XmlElement]$XmlElement
  )

  $ret   = $null;
  $var_1 = $null; $var_2 = $null; $var_3 = $null;
  $var_4 = $null; $var_5 = $null; $var_6 = $null; 
  $var_7 = $null; $var_8 = $null;
	  
  $Mondo       = $null;
  $ProPlus     = $null; $ProPlus2019    = $null; $ProPlus2021    = $null; $ProPlus2024    = $null
  $VisioPro    = $null; $VisioPro2019   = $null; $VisioPro2021   = $null; $VisioPro2024    = $null
  $ProjectPro  = $null; $ProjectPro2019 = $null; $ProjectPro2021 = $null; $ProjectPro2024    = $null
  $O365ProPlus = $null; $O365Business   = $null; $O365HomePrem   = $null
  
  $name = $XmlElement.name
  if (!$name) {
    return $false
  }
  
  $action = $XmlElement.action
  if (!$action) {
    return $false
  }
  $match = [Regex]::IsMatch($action, "^([1-3])$")
  if (!$match) {
    return $false
  }
  
  $version = $XmlElement.version
  if (!$version) {
    return $false
  }
  
  $match = $null
  $match = [Regex]::IsMatch($version, "^(16.[0-9].[0-9][0-9][0-9][0-9][0-9].[0-9][0-9][0-9][0-9][0-9]|Auto)$",$IgnoreCase)
  if (!$match) {
    return $false
  }
  
  $channel = $XmlElement.channel
  $guid    = $XmlElement.channel
  $System  = $XmlElement.System
  
  if (($channel -eq $null) -or ($guid -eq $null)) {
    return $false
  }
  
  # mode 2, auto channel
  if (($action -eq 2) -and ($channel -ne 'Auto')) {
    return $false
  }
  if (($action -eq 2) -and ($version -ne 'Auto')) {
    return $false
  }
  
  # mode 1/3 === user selected channel
  if ((($action -eq 1) -or ($action -eq 3)) -and ($channel -eq 'Auto')) {
    return $false
  }
  
  if (($action -eq 1) -and ($System -eq $null)) {
    return $false
  }
  
  if ((($action -eq 2) -or ($action -eq 3)) -and $System) {
    return $false
  }
  
  if ($System) {
	  $is_match = $null
	  $is_match = [REGEX]::IsMatch($System,"^(Auto|x86|AMD64|IA64)$",$IgnoreCase)
	  if (!($is_match)) {
	    return $false
    }
  }
  
  $match_1 = [REGEX]::IsMatch($channel,$channel_pattern,$IgnoreCase)
  $match_2 = [REGEX]::IsMatch($guid,$guid_pattern,$IgnoreCase)
  
  if (($action -eq 3) -and !$match_1 -and !$match_2) {
    return $false
  }
  
  $type = $XmlElement.P_Type
  $Products = $XmlElement.Products
  
  if (($type -eq $null) -and (($action -eq 2) -or ($action -eq 3))) {
    return $false
  }
  
  if (($Products -eq $null) -and (($action -eq 2) -or ($action -eq 3))) {
    return $false
  }
  
  if ($type -and ($action -eq 1)) {
    return $false
  }
  
  if ($Products -and ($action -eq 1)) {
    return $false
  }
  
  if ($type) {
	$match = $null
    $match = [Regex]::IsMatch($type, "^(Full|Single)$",$IgnoreCase)
    if (!$match) {
      return $false
    }
  
    if ($type -eq 'Full') {
	  $oApps =   ''
      $oApps +=  "Mondo,VisioPro,VisioPro2019,VisioPro2021,VisioPro2024"
	  $oApps +=  ",ProjectPro,ProjectPro2019,ProjectPro2021,ProjectPro2024"
	  $oApps +=  ",ProPlus,ProPlus2019,ProPlus2021,ProPlus2024"
	  $oApps +=  ",O365ProPlus,O365Business,O365HomePrem"
      $app_list = '^(' + ($oApps.Split(',') -join '|') + ')$'
    }
  
    if ($type -eq 'Single') {
      $oApps = ''
      $oApps +=  "VisioPro,VisioPro2019,VisioPro2021,VisioPro2024,ProjectPro,ProjectPro2019,ProjectPro2021,ProjectPro2024"
      $oApps += ",Word,Word2019,Word2021,Word2024,Excel,Excel2019,Excel2021,Excel2024,PowerPoint,PowerPoint2019,PowerPoint2021,PowerPoint2024"
      $oApps += ",Access,Access2019,Access2021,Access2024,Outlook,Outlook2019,Outlook2021,Outlook2024,Publisher,Publisher2019,Publisher2021,Publisher2024"
      $oApps += ",OneNote,OneNote2021Retail,OneNote2024Retail,SkypeForBusiness,SkypeForBusiness2019,SkypeForBusiness2021,SkypeForBusiness2024"
      $app_list = '^(' + ($oApps.Split(',') -join '|') + ')$'
    }
  }
  
  if ($Products) {
    $array = New-Object -TypeName 'System.Collections.ArrayList';
    foreach ($Product in @($Products.Split(', :;'))) {
      # start
      if ($array.Contains($Product)) {
        return $false
      }
	  $IsMatch = $null
	  $IsMatch = [Regex]::IsMatch($Product, $app_list,$IgnoreCase)
      if (-not($IsMatch)) {
        return $false
      }

      $array.Add($Product) | Out-Null

      # Powershell : Function to create new-variable not working
      # https://stackoverflow.com/questions/71495976/powershell-function-to-create-new-variable-not-working

      $PSCmdlet.SessionState.PSVariable.Set($Product,1)

      # end
    }
	
    # https://stackoverflow.com/questions/3466452/xor-of-three-values
	# python converts bool to int, so result = bool(a) + bool(b) + bool(c) == 1
	  
	if ($VisioPro -or $VisioPro2019 -or $VisioPro2021 -or $VisioPro2024) {

	  $ret = $null;
	  $var_1 = $null; $var_2 = $null;
	  $var_3 = $null; $var_4 = $null;
	  
	  $var_1 = $VisioPro     -as [Bool]
	  $var_2 = $VisioPro2019 -as [Bool]
	  $var_3 = $VisioPro2021 -as [Bool]
	  $var_4 = $VisioPro2024 -as [Bool]
	  
	  $ret = ($var_1 + $var_2 + $var_3 + $var_4) -eq 1
	  if ($ret -eq $false) { return $false }
	}

	if ($ProjectPro -or $ProjectPro2019 -or $ProjectPro2021 -or $ProjectPro2024) {
	    
	  $ret = $null;
	  $var_1 = $null; $var_2 = $null;
	  $var_3 = $null; $var_4 = $null;

	  $var_1 = $ProjectPro     -as [Bool]
	  $var_2 = $ProjectPro2019 -as [Bool]
	  $var_3 = $ProjectPro2021 -as [Bool]
	  $var_4 = $ProjectPro2024 -as [Bool]
	  
	  $ret = ($var_1 + $var_2 + $var_3 + $var_4) -eq 1
	  if ($ret -eq $false) { return $false }
	}

	if ($Mondo -or $ProPlus -or $ProPlus2019 -or $ProPlus2021 -or $ProPlus2024 -or $O365ProPlus -or $O365Business -or $O365HomePrem) {

	  $ret = $null; $var_7 = $null; $var_8 = $null;
	  $var_1 = $null; $var_2 = $null; $var_3 = $null;
	  $var_4 = $null; $var_5 = $null; $var_6 = $null;

	  $var_1 = $Mondo        -as [Bool]
	  $var_2 = $ProPlus      -as [Bool]
	  $var_3 = $ProPlus2019  -as [Bool]
	  $var_4 = $ProPlus2021  -as [Bool]
	  $var_5 = $ProPlus2024  -as [Bool]
	  $var_6 = $O365ProPlus  -as [Bool]
	  $var_7 = $O365Business -as [Bool]
	  $var_8 = $O365HomePrem -as [Bool]
		
	  $ret = ($var_1 + $var_2 + $var_3 + $var_4 + $var_5 + $var_6 + $var_7 + $var_8) -eq 1
	  if ($ret -eq $false) { return $false }
	}

    $array = $null
  }
  
  $Location = $XmlElement.Location
   if (!$Location) {
    return $false
  }

  [Regex]::Matches($location,$variables,$IgnoreCase) | % {
    $location = [Regex]::Replace($location,$_.Value,[Environment]::GetEnvironmentVariable($_.Value.Split('%')[1])) }
  
  if ((-not(Test-Path $Location)) -and ($Location -ne 'Online')) {
	return $false
  }
  
  if ((($action -eq 1) -or ($action -eq 2)) -and (-not(Test-Path $Location))) {
	return $false
  }
  
  if (($action -eq 2) -and (Test-Path $Location)) {
	$loc_full_name = Join-path -Path $Location -ChildPath ($name+'\Office\Data')
    if (-not(Test-Path $loc_full_name)) {
      return $false
    }
  }
  
  if (($action -eq 3) -and ($Location -ne 'Online')) {
	return $false
  }
  
  $Language = $XmlElement.Language
   if (!$Language) {
    return $false
  }
  
  $ignore = $null
  if (($action -eq 2) -and ($Language -eq 'Auto')) {
    $ignore = $true
  }
  
  $array = New-Object -TypeName 'System.Collections.ArrayList';
  if ($ignore -eq $null) {
    foreach ($val in @($Language.Split(', :;'))) {
      if ($array.Contains($val)) {
        return $false
      }
	  $IsMatch = [Regex]::IsMatch($val,$lang_list,$IgnoreCase)
      if (($IsMatch -eq $null) -or ($IsMatch -eq $false)) {
        return $false
      }
      $array.Add($val)|Out-Null
    }
  }
  $array = $null
  
  $exclude = $XmlElement.Exclude
  $exclude_apps = "^(Word|Excel|PowerPoint|Access|Outlook|Publisher|OneNote|Skype|OneDrive|Bing|Visio|Project)$"
  
  if ($exclude) {
    $array = New-Object -TypeName 'System.Collections.ArrayList';
	foreach ($val in @($exclude.Split(', :;'))) {
	if ($array.Contains($val)) {
	  return $false
	}
	$IsMatch = [Regex]::IsMatch($val, $exclude_apps,$IgnoreCase)
	if (($IsMatch -eq $null) -or ($IsMatch -eq $false)) {
	  return $false
	}
	$array.Add($val)|Out-Null
	}
	$array = $null
  }
  
  $lang_pack = $XmlElement.lang_pack
  if ($lang_pack) {
    $array = New-Object -TypeName 'System.Collections.ArrayList';
	foreach ($val in @($lang_pack.Split(', :;'))) {
	  if ($array.Contains($val)) {
	    return $false
	  }
	  $IsMatch = [Regex]::IsMatch($val,$lang_list,$IgnoreCase)
	  if (($IsMatch -eq $null) -or ($IsMatch -eq $false)) {
	    return $false
	  }
	  $array.Add($val)|Out-Null
	}
	$array = $null
  }
  
  $proof_tool = $XmlElement.proof_tool
  if ($proof_tool) {
    $array = New-Object -TypeName 'System.Collections.ArrayList';
	foreach ($val in @($proof_tool.Split(', :;'))) {
	  if ($array.Contains($val)) {
	    return $false
	  }
	  $IsMatch = [Regex]::IsMatch($val,$lang_list,$IgnoreCase)
	  if (($IsMatch -eq $null) -or ($IsMatch -eq $false)) {
	    return $false
	  }
	  $array.Add($val)|Out-Null
	}
	$array = $null
  }
  
  return $true
}

if ($Args[0] -eq $null) {
    $count = 0
    
	$item = $null
	$xmlAttr = $null
	if (-not($env:Profile)){return}
	$item = Get-ChildItem @(Join-Path 'Profiles' $env:Profile) -ErrorAction SilentlyContinue
	if (!$item) {return}
    [xml]$xmlAttr = Get-Content -Path $item.FullName -ErrorAction SilentlyContinue
	if (!$xmlAttr) {return}
	
    $nodes_List = $xmlAttr.Settings.ChildNodes
    if (!$nodes_List) {return}
    foreach ($node in $xmlAttr.Settings.ChildNodes) {
        
		$count +=1
        $act = $node.action
		
        "ID         = $($count)"
		
        if ($act -eq 1) {
	        "action     = Download Mode"
        }
	
        if ($act -eq 2) {
	        "action     = Local Install Mode"
        }
		
        if ($act -eq 3) {
	        "action     = Online Install Mode"
        }
		
        "Name       = $($node.name)"
        "Location   = $($node.Location)"
        "version    = $($node.version)"
        "channel    = $($node.channel)"
		
        if (($act -eq 2) -or ($act -eq 3)) {
	        "Products   = $($node.Products)"
        }
        if (($act -eq 2) -or ($act -eq 3)) {
	        if ($node.Exclude) {
	        "Exclude    = $($node.Exclude)"
	        }
        }
		
        #if (($act -eq 2) -or ($act -eq 3)) {
        #    "Type       = $($node.P_Type)"
        #}
		
        "Language   = $($node.Language)"
		
        if ($act -eq 1) {
	        "System     = $($node.System)"
        }
		
        if (($act -eq 2) -or ($act -eq 3)) {
	        if ($node.lang_pack) {
	        "Lang. Pack = $($node.lang_pack)"
	        }
	        if ($node.proof_tool) {
	        "Proof Pack = $($node.proof_tool)"
	        }
        }
        write-host
    }
    return
}

if ($Args[0] -and $Args[1]) {
 if ($Args[2] -and ($Args[2] -eq '-Extract')) {
  try {
    $count = 0
	$selected = $Args[0] -as [int]
	$value = $Args[1] -as [string]
	
	$item = $null
	$xmlAttr = $null
	if (-not($env:Profile)){return}
	$item = Get-ChildItem @(Join-Path 'Profiles' $env:Profile) -ErrorAction SilentlyContinue
	if (!$item) {return}
    [xml]$xmlAttr = Get-Content -Path $item.FullName -ErrorAction SilentlyContinue
	if (!$xmlAttr) {return}
	
    $nodes_List = $xmlAttr.Settings.ChildNodes
    if (!$nodes_List) {return}
    foreach ($node in $xmlAttr.Settings.ChildNodes) {
        $count +=1
        if ($count -eq $selected) {
	        switch ($value)
	        {
		        "Name" {return "$($node.name)"}
		        "action" {return "$($node.action)"}
		        "version" {return "$($node.version)"}
		        "channel" {return "$($node.channel)"}
		        "Products" {return "$($node.Products)"}
		        "Type" {return "$($node.P_Type)"}
		        "Location" {
                  $Location = $node.Location
                  [Regex]::Matches($location,$variables,$IgnoreCase) | % {
                    $location = [Regex]::Replace(
					  $location,$_.Value,[Environment]::GetEnvironmentVariable($_.Value.Split('%')[1])) }
                  return $Location
                }
		        "Language" {return "$($node.Language)"}
		        "Exclude" {return "$($node.Exclude)"}
		        "lang_pack" {return "$($node.lang_pack)"}
		        "proof_tool" {return "$($node.proof_tool)"}
		        "System" {return "$($node.System)"}
	        }
        }
    }
  }
  catch {
  }
 }
 
 if ($Args[2] -and ($Args[2] -eq '-Verify')) {
  try {
    $count = 0
	$results = $null
	$selected = $Args[0] -as [int]
	$value = $Args[1] -as [string]

    $item = $null
	$xmlAttr = $null
	if (-not($env:Profile)){return}
	$item = Get-ChildItem @(Join-Path 'Profiles' $env:Profile) -ErrorAction SilentlyContinue
	if (!$item) {return}
    [xml]$xmlAttr = Get-Content -Path $item.FullName -ErrorAction SilentlyContinue
	if (!$xmlAttr) {return}
	
    $nodes_List = $xmlAttr.Settings.ChildNodes
    if (!$nodes_List) {return}
    foreach ($node in $xmlAttr.Settings.ChildNodes) {
      $count +=1
	  if ($count -eq $selected) {
		$results = ParseXML $node
		break
	  }
    }
  }
  catch {
    return $false
  }
  
  if ($results -ne $null) {
	return $results
  }
  return $true
 }
 
}


# SIG # Begin signature block
# MIIFoQYJKoZIhvcNAQcCoIIFkjCCBY4CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUsJgwxhGcsBc1vNhwtHu3r/qo
# gWOgggM2MIIDMjCCAhqgAwIBAgIQSe49BypwLKhOHkzMeRKLBzANBgkqhkiG9w0B
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJA5
# RuzSjKWbUcDK+sDuJ/R3zFDzMA0GCSqGSIb3DQEBAQUABIIBAMZdRWdVuR2QtfYE
# J7HPcYwkkVkXNRjOEmsCMZmN56wzQBVCuasW+4+cLiSVC9edP6Y8gHK5TRyrV1tx
# gQAmlwsme8uOiRFjEZCNS6RX1EYqDRjqJUkiZAiCed+Ee8Akur1DqmXfLFtk7t7F
# 1rHQqr4xYl7ricjLp4HZTM05Y97Q1UeTLy50ARkAEXFB3OcB9u3fNeVAlHgwWiWc
# 6FJYOvF9t4gqYs/MekPBB+Z1Z+hVa1RnO5K0IRK58GyhLZqhn5oKPdsYJu/L/FDw
# mpfeLsQdTUsFMNyWG0NR20YcmUfHWXhqb2pvDAC2GDqGXeHji7OoGUOOoiuTf1u8
# m3i0OaY=
# SIG # End signature block
