# NetScope 告警测试：自动检测网关与测试目标，依次发出四种异常流量
#
# 用法：右键"使用 PowerShell 运行"，或在管理员终端：
#   powershell -ExecutionPolicy Bypass -File scripts\告警测试.ps1
#
# 说明：脚本只向"同网段的空闲地址"发包，不会打网关或公网；
#       运行前请确认 NetScope 已在抓本机网卡，并切到"告警"页。

param([switch]$DryRun)

$ErrorActionPreference = "Stop"

# 仓库根目录（scripts 的上一级）
$repo = Split-Path -Parent $PSScriptRoot
$py = Join-Path $repo ".venv\Scripts\python.exe"
$tool = Join-Path $repo "tools\异常流量生成.py"
$log = Join-Path $repo "告警测试日志.txt"

"==== NetScope 告警测试  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ====" |
    Set-Content -Path $log -Encoding UTF8

function Log([string]$msg) {
    Write-Host $msg
    Add-Content -Path $log -Value $msg -Encoding UTF8
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Log "需要管理员权限（发送原始报文）。请用 scripts\告警测试.bat 启动，它会自动提权。"
    exit 1
}
if (-not (Test-Path $py)) {
    Log "找不到虚拟环境：$py"
    Log "请先在仓库根目录执行 python -m venv .venv 并安装 requirements.txt"
    exit 1
}
if (-not (Test-Path $tool)) { Log "找不到 tools\异常流量生成.py"; exit 1 }

# 自动找默认网关，再在同网段挑一个大概率空闲的地址当靶子
$route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -ne "0.0.0.0" } |
    Sort-Object RouteMetric, ifIndex | Select-Object -First 1
$gateway = if ($route) { $route.NextHop } else { "" }
if (-not $gateway) { Log "没有找到默认网关，请检查网络连接。"; exit 1 }

$target = $gateway -replace "\.\d+$", ".253"
if ($target -eq $gateway) { $target = $gateway -replace "\.\d+$", ".252" }

Log "默认网关    : $gateway"
Log "测试目标    : $target（同网段空闲地址，不打网关）"
Log ""

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " 开始前请确认：" -ForegroundColor Cyan
Write-Host "   1. 已断开 VPN，否则报文走隧道抓不到"
Write-Host "   2. NetScope 已启动、选了 Wi-Fi 网卡、正在抓包"
Write-Host "   3. 右侧统计面板已切到“告警”页"
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Read-Host "条件满足后按回车开始（Ctrl+C 取消）"
Write-Host ""

if ($DryRun) {
    Log "[DryRun] 只演示流程，不发送报文："
    Log "  1) syn 600    -> ${target}:80  => 预期 SYN_FLOOD"
    Log "  2) icmp 300   -> $target      => 预期 ICMP_ECHO_FLOOD"
    Log "  3) orphan 40  -> $target      => 预期 ICMP_ORPHAN_REPLY"
    Log "  4) bigecho 1  -> $target      => 预期 ICMP_BIG_ECHO"
    exit 0
}

function Invoke-Phase([string]$title, [string[]]$toolArgs, [string]$expect) {
    Log "---- $title ----"
    Log "预期告警：$expect"
    & $py $tool @toolArgs 2>&1 | Tee-Object -FilePath $log -Append | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Log "本阶段退出码 $LASTEXITCODE，详情见日志。"
    }
    Log ""
}

Invoke-Phase "阶段 1/4  SYN 泛洪" @("syn", "--target", $target, "--port", "80", "--count", "600") "SYN_FLOOD"
Start-Sleep -Seconds 2

Invoke-Phase "阶段 2/4  ICMP 回声请求泛洪" @("icmp", "--target", $target, "--count", "300") "ICMP_ECHO_FLOOD"
Log "等 10 秒，让 echo request 滑出 5 秒统计窗口，否则孤立应答会被当成正常应答……"
Start-Sleep -Seconds 10

Invoke-Phase "阶段 3/4  无请求应答" @("orphan", "--target", $target, "--count", "40") "ICMP_ORPHAN_REPLY"
Start-Sleep -Seconds 2

Invoke-Phase "阶段 4/4  大包 / 分片回声" @("bigecho", "--target", $target) "ICMP_BIG_ECHO"

Write-Host ""
Log "四个阶段跑完了。去 NetScope 的“告警”页看看，应该正好 4 条："
Log "  SYN_FLOOD / ICMP_ECHO_FLOOD / ICMP_ORPHAN_REPLY / ICMP_BIG_ECHO"
Log "日志：$log"
