# Держать сеанс учётки Packet Tracer на консоли: отключённый RDP-сеанс не рисует окна, и снимки получаются пустыми.
# Запускается задачей «PT MCP console» от SYSTEM раз в 2 минуты (её заводит install.ps1). Чужие сеансы не трогает.
param([Parameter(Mandatory)] [string]$User, [string]$Log = 'C:\ptmcp\logs\keep-console.log')
$lines = (query session 2>$null) | Select-Object -Skip 1
foreach ($l in $lines) {
    $t = $l.Substring(1) -split '\s+' | Where-Object { $_ }
    if ($t -contains $User) {
        $i = [array]::IndexOf($t, $User)
        $id = $t[$i + 1]; $state = $t[$i + 2]
        if ($state -eq 'Disc') {
            tscon $id /dest:console 2>&1 | Out-Null
            Add-Content $Log "$(Get-Date -f s) $User сеанс $id Disc -> console ($LASTEXITCODE)"
        }
    }
}
