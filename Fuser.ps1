param(
  [switch]$Strict,
  [switch]$Json,
  [string]$OutFile = ""
)

# =========================
# CORENET Banner 
# =========================
$ascii=@"
   _____ ____  ____  ______   _   ________  ______
  / ___// __ \/ __ \/ ____/  / | / / ____/ /_  __/
  \__ \/ / / / /_/ / __/    /  |/ / __/     / /   
 ___/ / /_/ / _, _/ /___   / /|  / /___    / /    
/____/\____/_/ |_/_____/  /_/ |_/_____/   /_/     
                 corenet   |  Fuser Finder (EDID)
"@
Write-Host $ascii -ForegroundColor Cyan

# =========================
# Helpers: EDID parsing
# =========================
function Test-EdidBlockChecksum {
  param([byte[]]$b)
  $ok=$true
  for($i=0;$i -lt $b.Length;$i+=128){
    $s=0
    for($j=0;$j -lt [Math]::Min(128,$b.Length-$i);$j++){
      $s += $b[$i+$j]
    }
    if(($s % 256) -ne 0){ $ok=$false }
  }
  return $ok
}

function Get-EdidName {
  param([byte[]]$b)
  $n=$null
  for($o=54;$o -le 108;$o+=18){
    if($b[$o]-eq 0 -and $b[$o+1]-eq 0 -and $b[$o+2]-eq 0 -and $b[$o+3]-eq 0xFC -and $b[$o+4]-eq 0){
      $raw = $b[($o+5)..($o+17)]
      $s = [Text.Encoding]::ASCII.GetString($raw)
      $s = $s.Split("`n")[0].Trim()
      if($s){ $n=$s }
    }
  }
  return $n
}

function Get-EdidMfg {
  param([byte[]]$b)
  $w=[UInt16]([UInt16]$b[8] -shl 8 -bor [UInt16]$b[9])
  $w=$w -band 0x7FFF
  $a=[char](64+($w -shr 10))
  $c=[char](64+(($w -shr 5) -band 31))
  $d=[char](64+($w -band 31))
  return ("$a$c$d")
}

function Get-EdidInfo {
  param([byte[]]$Bytes)

  $len = $Bytes.Length
  $chk = Test-EdidBlockChecksum $Bytes

  $serialBytes = $Bytes[12..15]
  $serialHex = ($serialBytes | ForEach-Object { $_.ToString('X2') }) -join ' '
  $serialNum = [BitConverter]::ToUInt32($Bytes,12)

  $week = $Bytes[16]
  $year = 1990 + $Bytes[17]

  $mfg  = Get-EdidMfg $Bytes
  $prod = [BitConverter]::ToUInt16($Bytes,10)
  $name = Get-EdidName $Bytes

  $allZero = ($serialBytes[0]-eq 0 -and $serialBytes[1]-eq 0 -and $serialBytes[2]-eq 0 -and $serialBytes[3]-eq 0)

  [PSCustomObject]@{
    BytesLen    = $len
    ChecksumOk  = $chk
    SerialHEX   = $serialHex
    SerialNum   = $serialNum
    Year        = $year
    Week        = $week
    Mfg         = $mfg
    ProductCode = $prod
    Model       = $name
    ZeroSerial  = $allZero
  }
}

# =========================
# Indicators
# =========================
function Test-CRU {
  $p=@(
    "$env:USERPROFILE\Downloads\cru.exe",
    "$env:USERPROFILE\Downloads\restart64.exe",
    "$env:ProgramFiles\CRU\cru.exe",
    "$env:ProgramFiles(x86)\CRU\cru.exe",
    "$env:USERPROFILE\Desktop\cru.exe"
  )
  return (@($p|Where-Object{Test-Path $_})).Count -gt 0
}

function Has-OverrideFlags {
  $hit=$false
  Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Video" -ErrorAction SilentlyContinue | ForEach-Object{
    Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object{
      $props = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).PSObject.Properties.Name
      if($props | Where-Object { $_ -like "OverrideEdidFlags*" }){ $hit=$true }
    }
  }
  return $hit
}

function Test-IsLaptop {
  $isLap=$false
  try{
    $enc=Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue
    if($enc){
      $ct=@($enc.ChassisTypes)
      $hot=@(8,9,10,14,30,31)
      if(@($ct|Where-Object{$hot -contains $_}).Count -gt 0){ $isLap=$true }
    }
  }catch{}
  try{
    $cs=Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if($cs -and $cs.PCSystemType -eq 2){ $isLap=$true }
  }catch{}
  try{
    $bat=Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    if($bat){ $isLap=$true }
  }catch{}
  return $isLap
}

# =========================
# Main scan
# =========================
$results=@()
$displayRoot="HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
$monitorKeys=@(Get-ChildItem $displayRoot -ErrorAction SilentlyContinue)

$nowYear=(Get-Date).Year
$cru=Test-CRU
$flags=Has-OverrideFlags
$isLaptop=Test-IsLaptop

foreach($monitorKey in $monitorKeys){
  foreach($instance in Get-ChildItem $monitorKey.PSPath -ErrorAction SilentlyContinue){
    $dp = Join-Path $instance.PSPath "Device Parameters"

    $edid = Get-ItemProperty -Path $dp -Name EDID -ErrorAction SilentlyContinue
    $edidOverride = Get-ItemProperty -Path $dp -Name EDID_OVERRIDE -ErrorAction SilentlyContinue

    if(-not $edid){ continue }

    $info = Get-EdidInfo -Bytes ([byte[]]$edid.EDID)

    $reasons=@()
    $score=0

    # High confidence (forensics-safe)
    if($edidOverride){ $reasons += "EDID_OVERRIDE"; $score += 70 }     # strongest registry artifact [web:76]
    if($flags){        $reasons += "OverrideEdidFlags"; $score += 40 }

    # Medium
    if(-not $info.ChecksumOk){ $reasons += "InvalidChecksum"; $score += 25 }
    if($info.BytesLen -notin 128,256){ $reasons += "WeirdLength:$($info.BytesLen)"; $score += 15 }
    if($info.Year -lt 1990 -or $info.Year -gt ($nowYear+1)){ $reasons += "WeirdYear:$($info.Year)"; $score += 10 }
    if(-not $info.Model){ $reasons += "NoModelName"; $score += 10 }

    # Weak (review-only signals)
    if($info.SerialNum -eq 0 -or $info.ZeroSerial){ $reasons += "EmptyOrZeroSerial"; $score += 10 }
    if($cru){ $reasons += "CRU_Artifacts"; $score += 5 }

    if($score -gt 100){ $score = 100 }

    $results += [PSCustomObject]@{
      MonitorID   = $monitorKey.PSChildName
      InstanceID  = $instance.PSChildName

      Mfg         = $info.Mfg
      Product     = $info.ProductCode
      Model       = $info.Model

      SerialHEX   = $info.SerialHEX
      SerialNum   = $info.SerialNum

      Year        = $info.Year
      Week        = $info.Week

      BytesLen    = $info.BytesLen
      ChecksumOk  = $info.ChecksumOk

      HasOverride = [bool]$edidOverride
      HasFlags    = $flags
      HasCRU      = $cru

      RiskScore   = $score
      Suspicious  = ($score -ge 60)
      Reason      = ($reasons -join ",")
      DeviceParameters = $dp
    }
  }
}

# Duplicate serial (weak->medium signal)
$dupeHex = ($results | Group-Object SerialHEX | Where-Object { $_.Name -and $_.Count -gt 1 } | Select-Object -ExpandProperty Name)
$dupeNum = ($results | Where-Object { $_.SerialNum -ne 0 } | Group-Object SerialNum | Where-Object { $_.Count -gt 1 } | Select-Object -ExpandProperty Name)

if($dupeHex){
  $results | Where-Object { $dupeHex -contains $_.SerialHEX } | ForEach-Object {
    $_.Reason = (($_.Reason, "DuplicateSerial") | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique) -join ","
    $_.RiskScore = [Math]::Min(100, $_.RiskScore + 10)
    if($_.RiskScore -ge 60){ $_.Suspicious = $true }
  }
}
if($dupeNum){
  $results | Where-Object { $dupeNum -contains $_.SerialNum } | ForEach-Object {
    $_.Reason = (($_.Reason, "DuplicateSerial") | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique) -join ","
    $_.RiskScore = [Math]::Min(100, $_.RiskScore + 10)
    if($_.RiskScore -ge 60){ $_.Suspicious = $true }
  }
}

# =========================
# Storm-style verdict (FOUND / NOT FOUND + REVIEW)
# =========================
$high = $results | Where-Object { $_.HasOverride -or $_.HasFlags }
$low  = $results | Where-Object { -not ($_.HasOverride -or $_.HasFlags) -and $_.Suspicious }

if($Strict){
  if(($high | Measure-Object).Count -gt 0){
    Write-Host "Fuser found" -ForegroundColor Red
  } else {
    Write-Host "No fuser found" -ForegroundColor Green
  }
} else {
  if(($high | Measure-Object).Count -gt 0){
    Write-Host "Fuser found" -ForegroundColor Red
  } else {
    Write-Host "No fuser found" -ForegroundColor Green
    if(($low | Measure-Object).Count -gt 0){
      Write-Host "Review: suspicious EDID heuristics detected" -ForegroundColor Yellow
    }
  }
}

Write-Host ("Laptop Detected: " + $isLaptop)

# Output table
$results |
  Sort-Object @{Expression='RiskScore';Descending=$true},@{Expression='MonitorID';Descending=$false} |
  Select-Object MonitorID,InstanceID,Model,Mfg,SerialHEX,HasOverride,HasFlags,HasCRU,RiskScore,Reason |
  Format-Table -AutoSize

# =========================
# JSON export (optional)
# =========================
if($Json){
  if([string]::IsNullOrWhiteSpace($OutFile)){
    $OutFile = Join-Path (Get-Location) "corenet_edid_report.json"
  }

  $results | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $OutFile
  Write-Host ("Saved: " + $OutFile) -ForegroundColor Cyan
}

