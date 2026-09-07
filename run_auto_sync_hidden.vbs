Set WshShell = CreateObject("WScript.Shell")
' Run auto_sync_github.bat in hidden mode (0 = hide window, False = don't wait for completion)
WshShell.Run Chr(34) & WshShell.CurrentDirectory & "\auto_sync_github.bat" & Chr(34), 0, False
