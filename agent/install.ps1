# Установка агента Packet Tracer MCP на Windows-хост с Packet Tracer 9. Одна команда, от администратора:
#   powershell -ExecutionPolicy Bypass -File agent\install.ps1 -User 'HOST\svc_pt' -AllowFrom 203.0.113.10
# -User      учётка, в сеансе которой работает PT (нужен её автовход, например Sysinternals Autologon);
# -AllowFrom адрес сервера ptgen-MCP: только ему открывается порт агента;
# -HostName  имя или IP, по которому сервер ходит к агенту (пишется в сертификат), по умолчанию имя компьютера.
# Скрипт сам копирует код, ставит зависимости, выпускает TLS-сертификат и токен, заводит задачи и правило брандмауэра.
# Повторный запуск обновляет код, а ключ и токен оставляет прежними (-NewSecrets выпускает новые).
param(
    [Parameter(Mandatory)] [string]$User,
    [Parameter(Mandatory)] [string]$AllowFrom,
    [string]$HostName = $env:COMPUTERNAME,
    [int]$Port = 39410,
    [string]$Root = 'C:\ptmcp',
    [string]$Python = '',
    [string]$PtExe = 'C:\Program Files\Cisco Packet Tracer 9.0.0\bin\PacketTracer.exe',
    [string]$TaskPrefix = 'PT MCP',
    [switch]$NewSecrets
)
$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) { throw 'Запустите от администратора' }
$Src = Split-Path -Parent $PSScriptRoot

# Python 3.10+
if (-not $Python) {
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike '*WindowsApps*' } | Select-Object -First 1
    if ($cmd) { $Python = $cmd.Source } elseif (Get-Command py.exe -ErrorAction SilentlyContinue) { $Python = (& py -3 -c 'import sys;print(sys.executable)') }
}
if (-not $Python -or -not (Test-Path $Python)) { throw 'Не найден Python 3.10+ (поставьте для всех пользователей или укажите -Python)' }
& $Python -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
if ($LASTEXITCODE) { throw "Нужен Python 3.10+: $Python" }
$PyW = Join-Path (Split-Path $Python) 'pythonw.exe'
if (-not (Test-Path $PtExe)) { Write-Warning "Не найден Packet Tracer: $PtExe (укажите -PtExe)" }

# каталоги и права: служебной учётке -- изменение, остальным -- ничего
foreach ($d in 'vendor', 'pylib', 'tls', 'logs', 'work', 'ext') { New-Item -ItemType Directory -Force "$Root\$d" | Out-Null }
icacls $Root /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' "${User}:(OI)(CI)M" | Out-Null

# код и зависимости
Remove-Item "$Root\vendor\packet_tracer_mcp" -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item "$Src\agent\ptagent.py", "$Src\agent\keep-console.ps1" $Root -Force
Copy-Item "$Src\vendor\packet_tracer_mcp" "$Root\vendor\" -Recurse -Force
Copy-Item "$Src\agent\ext\ptmcp.pts" "$Root\ext\ptmcp.pts" -Force
& $Python -m pip install --disable-pip-version-check -q --upgrade --target "$Root\pylib" 'comtypes>=1.4' 'pydantic>=2.11,<3' 'cryptography>=42' 2>&1 | Select-Object -Last 3

# TLS: самоподписанный сертификат на -HostName; сервер закрепляет именно его
if ($NewSecrets -or -not (Test-Path "$Root\tls\agent.key")) {
    & $Python "$Src\agent\gen_cert.py" $HostName "$Root\tls" "$Root\pylib"
    if ($LASTEXITCODE) { throw 'Не удалось выпустить сертификат' }
}

# токен: у агента на диске только sha256; сам токен -- в файл для сервера, доступный только администраторам
if ($NewSecrets -or -not (Test-Path "$Root\agent.json")) {
    $b = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    $token = -join ($b | ForEach-Object { $_.ToString('x2') })
    $sha = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($token)) | ForEach-Object { $_.ToString('x2') })
    @{ token_sha256 = $sha; allow = @($AllowFrom); bind = '0.0.0.0'; port = $Port; work = "$Root\work"; pt_exe = $PtExe; keep_pt = $true } |
        ConvertTo-Json | Set-Content "$Root\agent.json" -Encoding UTF8
    New-Item -ItemType Directory -Force "$Root\server" | Out-Null
    icacls "$Root\server" /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
    Set-Content "$Root\server\ptgen-live.env" -Encoding ASCII -Value @(
        "PTLIVE_AGENT_URL=https://${HostName}:$Port", "PTLIVE_AGENT_TOKEN=$token", 'PTLIVE_AGENT_CA=/etc/ptgen-live/agent.crt')
    Remove-Variable token
}
if (Test-Path "$Root\server") { Copy-Item "$Root\tls\agent.crt" "$Root\server\agent.crt" -Force }
icacls "$Root\tls" /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' "${User}:(OI)(CI)R" | Out-Null

# задачи: агент -- в сеансе учётки при входе; раз в 2 мин SYSTEM возвращает её отключённый сеанс на консоль
$act = New-ScheduledTaskAction -Execute $PyW -Argument "`"$Root\ptagent.py`"" -WorkingDirectory $Root
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "$TaskPrefix agent" -Action $act -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $User) -Settings $set -Force `
    -Principal (New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited) -Description "Агент Packet Tracer MCP ($Root\ptagent.py)" | Out-Null
$sam = $User.Split('\')[-1]
$act2 = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Root\keep-console.ps1`" -User $sam -Log `"$Root\logs\keep-console.log`""
Register-ScheduledTask -TaskName "$TaskPrefix console" -Action $act2 -Force `
    -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2)) `
    -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
    -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew) `
    -Description 'Вернуть отключённый сеанс учётки Packet Tracer на консоль (tscon), чтобы окна PT рисовались' | Out-Null

# порт агента -- только с адреса сервера
Get-NetFirewallRule -DisplayName "$TaskPrefix agent $Port" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "$TaskPrefix agent $Port" -Group $TaskPrefix -Direction Inbound -Protocol TCP -LocalPort $Port -Program $PyW `
    -RemoteAddress $AllowFrom -Action Allow -Profile Any | Out-Null

@"
Готово. Осталось:
1. Войти учёткой $User (или включить её автовход). В Packet Tracer: Extensions -> Scripting -> Add -> $Root\ext\ptmcp.pts, запуск On Startup.
2. На сервер: $Root\server\agent.crt -> /etc/ptgen-live/agent.crt, строки из $Root\server\ptgen-live.env -> /etc/default/ptgen-live.
   После этого удалите $Root\server (там токен).
"@
