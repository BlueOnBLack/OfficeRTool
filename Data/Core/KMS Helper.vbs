if WScript.Arguments.Item(0)="/QUERY_BASIC" Then

	on error resume next
    strQuery = "Select " + WScript.Arguments(1) + " from " + WScript.Arguments(2)
	Set objArray= GetObject("winmgmts:\\.\root\CIMV2").ExecQuery(strQuery,,48)
    For each obj in objArray
		result = ","
		For each Prop in obj.Properties_
			result = result & Prop.Value & ","
        Next
		if NOT result = "," Then
			WScript.Echo result
		end if
    Next
	
ElseIf WScript.Arguments.Item(0)="/QUERY_ADVENCED" Then

	on error resume next
    strQuery = "Select " + WScript.Arguments(1) + " from " + WScript.Arguments(2) + " where " + WScript.Arguments(3)
	Set objArray= GetObject("winmgmts:\\.\root\CIMV2").ExecQuery(strQuery,,48)
    For each obj in objArray
		result = ","
		For each Prop in obj.Properties_
			result = result & Prop.Value & ","
        Next
		if NOT result = "," Then
			WScript.Echo result
		end if
    Next
	
ElseIf WScript.Arguments.Item(0)="/ACTIVATE" Then
	
	' New methood Provided by abbodi1406
	on error resume next
	INSTANCE_ID="winmgmts:\\.\root\CIMV2:" + WScript.Arguments.Item(1) + ".ID='" + WScript.Arguments(2) + "'"
	GetObject(INSTANCE_ID).Activate()
	
	' To Err Is VBScript – Part 1
	' https://docs.microsoft.com/en-us/previous-versions/tn-archive/ee692852(v=technet.10)?redirectedfrom=MSDN
	
	WScript.Echo "Error:" & Hex(Err.Number)
	Err.Clear
	
ElseIf WScript.Arguments.Item(0)="/DATA_FILE" Then
	
	' New methood Provided by abbodi1406
	on error resume next
	INSTANCE_ID="winmgmts:\\.\root\CIMV2:CIM_DataFile" + ".name='" + WScript.Arguments(1) + "'"
	WScript.Echo "," + GetObject(INSTANCE_ID).version

ElseIf WScript.Arguments.Item(0)="/UninstallProductKey" Then

	on error resume next
	strQuery = "Select * from " + WScript.Arguments(1) + " Where " + WScript.Arguments(2)
	Set objArray= GetObject("winmgmts:\\.\root\CIMV2").ExecQuery(strQuery,,48)
	For each obj in objArray
		obj.UninstallProductKey()
	Next
	
ElseIf WScript.Arguments.Item(0)="/QUERY_INVOKE" Then
	
	' this is test methood
	' need to check.
	' how it work
	
	on error resume next
	strQuery = "Select * from " + WScript.Arguments(1) + " Where " + WScript.Arguments(2)
	Set objArray= GetObject("winmgmts:\\.\root\CIMV2").ExecQuery(strQuery,,48)
	For each obj in objArray
		obj.ExecMethod(WScript.Arguments(3))
	Next
	
ElseIf WScript.Arguments.Item(0)="/PLAY" Then

	' VBS Play Sound With no Dialogue
	' https://stackoverflow.com/questions/22367004/vbs-play-sound-with-no-dialogue
	
	Dim oPlayer
	Set oPlayer = CreateObject("WMPlayer.OCX")

	' Play audio
	oPlayer.URL = WScript.Arguments(1)
	oPlayer.controls.play
	oPlayer.settings.volume = 100
    ' oPlayer.settings.setMode "loop", True
	While oPlayer.playState <> 1 ' 1 = Stopped
	  WScript.Sleep 100
	Wend

	' Release the audio file
	oPlayer.close
	
End If
'' SIG '' Begin signature block
'' SIG '' MIIFnwYJKoZIhvcNAQcCoIIFkDCCBYwCAQExCzAJBgUr
'' SIG '' DgMCGgUAMGcGCisGAQQBgjcCAQSgWTBXMDIGCisGAQQB
'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB
'' SIG '' AAIBAAIBAAIBADAhMAkGBSsOAwIaBQAEFGYCq7jmpf5w
'' SIG '' 5yrVlZBLoDeI8TwSoIIDNjCCAzIwggIaoAMCAQICEEnu
'' SIG '' PQcqcCyoTh5MzHkSiwcwDQYJKoZIhvcNAQELBQAwIDEe
'' SIG '' MBwGA1UEAwwVYWRtaW5Ab2ZmaWNlcnRvb2wub3JnMB4X
'' SIG '' DTI0MDEwNjE2MTIyN1oXDTMwMDEwNjE2MjIyN1owIDEe
'' SIG '' MBwGA1UEAwwVYWRtaW5Ab2ZmaWNlcnRvb2wub3JnMIIB
'' SIG '' IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy2av
'' SIG '' kZq8+MMDb4AGVc72zpo9UZVJZe4bRv7yCbqw2m1jbyG2
'' SIG '' AccnC68xACSnrrjvE07aHZYQhZLwrcztoFOO8CsKqCCv
'' SIG '' aeaKwfX9MWrLsbbuxHiEb12S6QYykNtBZ83neqXqD7qR
'' SIG '' G+fthSIwGzNxK7Um5gu1w4Ui4QIXlfPlK4qP77+84YiN
'' SIG '' CWLHyrXGZ2xQRvIeVjqGEpO7xBep1uDpXrjOqBrqa6uz
'' SIG '' lg2Bi2vbGq1/JozbtAjw4L8aBOrwIjmOpV4E/RqEpxDo
'' SIG '' KZ/DjoaQafRET8z+kKuqnrZf/sGBpGG0Bs+7+nzw0OAE
'' SIG '' 5xhSH3PRvqiAhPImbE1fm4A2I8jFCQIDAQABo2gwZjAO
'' SIG '' BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUH
'' SIG '' AwMwIAYDVR0RBBkwF4IVYWRtaW5Ab2ZmaWNlcnRvb2wu
'' SIG '' b3JnMB0GA1UdDgQWBBQyEaGaTj29Hod5kqpVKR0koIqI
'' SIG '' qjANBgkqhkiG9w0BAQsFAAOCAQEAnu0tPeVagmva8NLO
'' SIG '' hXTarxzn7UYEX9aK9OIu2bld433zf61WpV4/DuxrU0UP
'' SIG '' WRYRiJ42f+VFciz54ValcFszaahYEy+f2NI6BUPfRkH7
'' SIG '' 9X+VFLelOIzY40k2TXVWtwvYsFeCEI2kYRhEKrL6rDmn
'' SIG '' Xs21/Y5SKVwSsZrmu9P3FI/FG9FAU/o67d87arF/xIv8
'' SIG '' K6K24fKkta4GJouPd4YEICsUhv+7WeT725YxDuSjxDGo
'' SIG '' CheruF19QezM9A0ACXBVJ07Dcg/04/J3NN2mJxfDUZFM
'' SIG '' kWD4WyIKYmPXu/4rwWPuIBdtDjXNQsvPs6oEp9e5hdUE
'' SIG '' w0zsy+47Vfu0TjysTjGCAdUwggHRAgEBMDQwIDEeMBwG
'' SIG '' A1UEAwwVYWRtaW5Ab2ZmaWNlcnRvb2wub3JnAhBJ7j0H
'' SIG '' KnAsqE4eTMx5EosHMAkGBSsOAwIaBQCgeDAYBgorBgEE
'' SIG '' AYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEM
'' SIG '' BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
'' SIG '' BgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSkoDGJF3Tj
'' SIG '' kSrBUKsKPSQ/9otm0TANBgkqhkiG9w0BAQEFAASCAQBK
'' SIG '' AnfFXYEQ3RA7jk857yGd/oU/d+5jOi+a1EYYlJ6wvMrW
'' SIG '' ZWHLXK42RBaSyg1EYlXsfSGTyqXJ2cx1Y3x7wb6025F0
'' SIG '' NDQfiDVC3bJhUyoZDPVp/SFBPVJ3kUkkBVeH61ll7fmU
'' SIG '' QN1dVWyakgF9lLdDDt3w06K7xZ0g5hgvoGkkAHxKvNhu
'' SIG '' vvHqwUTEF0SWzgGT+vS4UmN3CJ02hNpzSUuzS5GTEyN8
'' SIG '' NDAwLcPkIDPk8mlTr8U3qRI0shApk9Hx/CZk2w0e2K0q
'' SIG '' ZeX2c8EEiMYzH/REwqr1R66z9p6sAHZ2+h/yXQvIlxih
'' SIG '' HG45bdBB8AbIPV2gioOH33Z/uGBuKaD3
'' SIG '' End signature block
