# corenet Fuser Finder (EDID)

Read-only Windows Forensic Tool zur Erkennung von **EDID-Override / Monitor-Spoofing-Indikatoren**.

- Verdict: `Fuser found` / `No fuser found`
- Hinweis: `Review: suspicious EDID heuristics detected`
- `-Strict`: nur High-Confidence Artefakte zählen als „Found“

## Quick Start

```powershell
iwr "https://raw.githubusercontent.com/ranyY2/corenet_fuser/main/Fuser.ps1" -UseBasicParsing -OutFile .\Fuser.ps1
powershell -ExecutionPolicy Bypass -File .\Fuser.ps1
