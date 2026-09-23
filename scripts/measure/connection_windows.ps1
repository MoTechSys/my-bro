#requires -Version 5.1
<# Read-only Windows WazuhSvc evidence. No service control or enrollment.
   Output is private JSON on stdout, not a signed or durable native store.
   Use a reviewed private NTFS destination; import with an independent expected
   byte hash on Linux. Process birth is NOT service readiness. #>
[CmdletBinding()]
param(
    [switch]$Lab,
    [Parameter(Mandatory=$true)][string]$RunId,
    [Parameter(Mandatory=$true)][string]$CycleId,
    [Parameter(Mandatory=$true)][string]$PlanSha256,
    [Parameter(Mandatory=$true)][string]$ClockRef,
    [Parameter(Mandatory=$true)][string]$ExpectedHost,
    [Parameter(Mandatory=$true)][string]$ImagePath,
    [Parameter(Mandatory=$true)][string]$ImageSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Assert-Value([bool]$Ok) {
    if (-not $Ok) { throw 'WINDOWS_EVIDENCE_REJECTED' }
}
function Assert-Text([string]$Text) {
    Assert-Value ($Text.Length -ge 1 -and $Text.Length -le 1024 -and
        $Text.Trim().Length -gt 0 -and $Text -notmatch '[\x00-\x1f\x7f]')
}
function Utc-Milliseconds {
    return ([DateTimeOffset]::UtcNow).ToUnixTimeMilliseconds()
}
function Utc-Ticks([DateTime]$Date) {
    Assert-Value ($Date.Kind -ne [DateTimeKind]::Unspecified)
    if ($Date.Kind -eq [DateTimeKind]::Local) {
        Assert-Value (-not [TimeZoneInfo]::Local.IsAmbiguousTime($Date) -and
            -not [TimeZoneInfo]::Local.IsInvalidTime($Date))
    }
    return $Date.ToUniversalTime().Ticks.ToString([Globalization.CultureInfo]::InvariantCulture)
}
function Protected-ImageHash {
    # Reject reparse points in every existing component. ACL/native binary
    # provenance still requires operator review; this does not verify loaded pages.
    $Item = Get-Item -LiteralPath $ImagePath -Force
    Assert-Value (-not $Item.PSIsContainer -and $Item.Length -le 33554432)
    $Walk = $Item
    while ($null -ne $Walk) {
        Assert-Value (($Walk.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
        if ($Walk -is [IO.FileInfo]) { $Walk = $Walk.Directory } else { $Walk = $Walk.Parent }
    }
    $Stream = [IO.File]::Open($ImagePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $Hash = [Security.Cryptography.SHA256]::Create()
        try {
            Assert-Value ($Stream.Length -le 33554432)
            return ([BitConverter]::ToString($Hash.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
        } finally { $Hash.Dispose() }
    } finally { $Stream.Dispose() }
}
function Service-Sample {
    $Service = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='WazuhSvc'" -OperationTimeoutSec 1)
    Assert-Value ($Service.Count -eq 1)
    $Service = $Service[0]
    Assert-Value ($Service.Name -ceq 'WazuhSvc' -and $Service.State -ceq 'Running' -and $Service.ProcessId -gt 0)
    $ProcessIdValue = [uint32]$Service.ProcessId
    $Process = @(Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId=" + $ProcessIdValue) -OperationTimeoutSec 1)
    Assert-Value ($Process.Count -eq 1)
    $Process = $Process[0]
    Assert-Value ($Process.ProcessId -eq $ProcessIdValue -and $Process.ExecutablePath -ieq $ImagePath -and
        $Process.CreationDate -is [DateTime])
    $Configured = [string]$Service.PathName
    $Quoted = '"' + $ImagePath + '"'
    Assert-Value (($Configured -ieq $Quoted) -or (($ImagePath -notmatch '\s') -and ($Configured -ieq $ImagePath)))
    $Digest = Protected-ImageHash
    Assert-Value ($Digest -ceq $ImageSha256)
    return [ordered]@{
        service_name = [string]$Service.Name; service_state = [string]$Service.State; process_id = $ProcessIdValue
        process_created_ticks = (Utc-Ticks $Process.CreationDate)
        process_datetime_kind = [string]$Process.CreationDate.Kind
        executable_path = [string]$Process.ExecutablePath
        image_sha256 = $Digest; configured_image_matches = $true
    }
}

function Complete-ServiceEvidence($Result) {
    $Result.tick_frequency = [Diagnostics.Stopwatch]::Frequency
    $Result.start_ms = Utc-Milliseconds
    $Result.start_ticks = [Diagnostics.Stopwatch]::GetTimestamp()
    try {
        $Boot = @(Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 1)
        Assert-Value ($Boot.Count -eq 1)
        $Result.boot_before_ticks = Utc-Ticks $Boot[0].LastBootUpTime
        $Result.boot_before_kind = [string]$Boot[0].LastBootUpTime.Kind
        $Result.samples += Service-Sample
        $Result.samples += Service-Sample
        $Boot = @(Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 1)
        Assert-Value ($Boot.Count -eq 1)
        $Result.boot_after_ticks = Utc-Ticks $Boot[0].LastBootUpTime
        $Result.boot_after_kind = [string]$Boot[0].LastBootUpTime.Kind
        Assert-Value ($Result.boot_before_ticks -ceq $Result.boot_after_ticks -and
            $Result.boot_before_kind -ceq $Result.boot_after_kind -and
            $Result.samples[0].process_id -eq $Result.samples[1].process_id -and
            $Result.samples[0].process_created_ticks -ceq $Result.samples[1].process_created_ticks)
        $Result.status = 'complete'
    } catch { $Result.status = 'failed' }
    finally {
        $Result.end_ticks = [Diagnostics.Stopwatch]::GetTimestamp()
        $Result.end_ms = Utc-Milliseconds
    }
    if (($Result.end_ticks - $Result.start_ticks) -gt (2 * $Result.tick_frequency) -or
        $Result.end_ticks -lt $Result.start_ticks -or $Result.end_ms -lt $Result.start_ms) {
        $Result.status = 'failed'
    }
    return $Result
}

try {
    Assert-Value ($Lab -and [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    foreach ($Value in @($RunId,$CycleId,$ClockRef,$ExpectedHost,$ImagePath)) { Assert-Text $Value }
    Assert-Value ($PlanSha256 -cmatch '^[0-9a-f]{64}$' -and $ImageSha256 -cmatch '^[0-9a-f]{64}$')
    Assert-Value ($ImagePath -cmatch '^[A-Za-z]:\\' -and $ImagePath -notmatch '/' -and
        [IO.Path]::GetFullPath($ImagePath) -ceq $ImagePath -and
        [IO.Path]::GetFileName($ImagePath) -ieq 'wazuh-agent.exe')
    $Drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($ImagePath))
    Assert-Value ($Drive.DriveType -eq [IO.DriveType]::Fixed)
    $HostNameValue = [Net.Dns]::GetHostName()
    Assert-Value ($HostNameValue -ceq $ExpectedHost)
    $ProducerDigest = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $Result = [ordered]@{
        schema_version = 1; producer = 'soc-windows-service-v1'; capture_id = [Guid]::NewGuid().ToString('N')
        producer_sha256 = $ProducerDigest; plan_sha256 = $PlanSha256; run_id = $RunId; cycle_id = $CycleId
        clock_ref = $ClockRef; hostname = $HostNameValue; expected_image_path = $ImagePath
        expected_image_sha256 = $ImageSha256; status = 'failed'; samples = @(); boot_before_ticks = $null
        boot_after_ticks = $null; boot_before_kind = $null; boot_after_kind = $null; start_ms = (Utc-Milliseconds); end_ms = $null
        start_ticks = [Diagnostics.Stopwatch]::GetTimestamp(); end_ticks = $null
        tick_frequency = [Diagnostics.Stopwatch]::Frequency
        acceptance_approved = $false; authenticity_verified = $false; loaded_image_hash_verified = $false
    }
    $Result = Complete-ServiceEvidence $Result
    $Json = ConvertTo-Json -InputObject $Result -Depth 5 -Compress
    Assert-Value ([Text.Encoding]::UTF8.GetByteCount($Json) -le 65536)
    [Console]::Out.WriteLine($Json)
    if ($Result.status -ne 'complete') { exit 2 }
} catch {
    [Console]::Error.WriteLine('WINDOWS_EVIDENCE_REJECTED')
    exit 2
}
