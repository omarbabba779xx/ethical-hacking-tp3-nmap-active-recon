param(
  [Parameter(Mandatory)][ValidateSet('kali','meta')][string]$Vm,
  [string]$Type,          # texte a taper (puis Entree)
  [switch]$NoEnter,
  [switch]$CtrlC,
  [int]$Wait = 2,         # secondes avant la capture
  [string]$Shot           # nom de capture (sans extension) dans captures\
)
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$name = @{ kali = 'kali-linux-2026.2-virtualbox-amd64'; meta = 'Metasploitable3-ub1404' }[$Vm]
$dir = Join-Path (Split-Path $PSScriptRoot) 'captures'
New-Item -ItemType Directory -Force $dir | Out-Null
if ($CtrlC) { & $vb controlvm $name keyboardputscancode 1d 2e ae 9d | Out-Null; Start-Sleep 1 }
if ($Type) {
  & $vb controlvm $name keyboardputstring $Type | Out-Null
  if (-not $NoEnter) { & $vb controlvm $name keyboardputscancode 1c 9c | Out-Null }
}
if ($Shot) {
  Start-Sleep $Wait
  $f = Join-Path $dir "$Shot.png"
  & $vb controlvm $name screenshotpng $f | Out-Null
  $f
}
