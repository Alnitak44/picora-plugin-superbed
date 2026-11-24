# 打包 Picora 插件 ZIP：ZIP 根目录直接是 plugin.json / uploader.json / readme.md / assets/
param(
    [string]$OutputPath,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'

$source = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
function Read-Json([string]$Path) {
    # 插件文件统一为无 BOM 的 UTF-8，避免 Windows PowerShell 按 ANSI 解码中文
    [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false)) | ConvertFrom-Json
}
$metadata = Read-Json (Join-Path $source 'plugin.json')

if ($metadata.packageVersion -ne 1 -or $metadata.runtime -notin @('http-v1', 'http-v2')) {
    throw '需要 packageVersion: 1 和 runtime: http-v1 / http-v2'
}
if (-not $metadata.version -or $metadata.version -notmatch '^\d+\.\d+\.\d+([-+].*)?$') {
    throw 'plugin.json 的 version 需要符合 SemVer，例如 1.0.0'
}
$entry = $metadata.entry
if (-not $entry -or $entry -match '(^/|\\|:|(^|/)\.\.?(/|$))' -or -not $entry.EndsWith('.json')) {
    throw '程序文件 entry 路径不合法'
}
foreach ($name in @('readme.md', $entry)) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $name) -PathType Leaf)) {
        throw "缺少 $name"
    }
}
$program = Read-Json (Join-Path $source $entry)
$schema = if ($metadata.runtime -eq 'http-v2') { 2 } else { 1 }
if ($program.schemaVersion -ne $schema) { throw 'plugin.json 的 runtime 与入口 JSON 的 schemaVersion 不匹配' }
if (-not (Test-Path -LiteralPath (Join-Path $source 'assets') -PathType Container)) {
    throw '缺少 assets 资源目录；没有资源时也请保留空目录'
}

if (-not $OutputPath) {
    $slug = ($metadata.id -split '\.')[-1]
    $OutputPath = Join-Path $source ("releases/{0}-{1}.picora-plugin.zip" -f $slug, $metadata.version)
}
$output = [IO.Path]::GetFullPath($OutputPath)
if (-not $output.EndsWith('.zip', [StringComparison]::OrdinalIgnoreCase)) {
    throw '输出文件必须以 .zip 结尾'
}
if ((Test-Path -LiteralPath $output) -and -not $Force) {
    throw '输出文件已存在，确认后传入 -Force 覆盖'
}

# 只打包插件包根需要的内容，源码工程里的 tools/、docs/、releases/、.git 不进压缩包
$files = [System.Collections.Generic.List[string]]::new()
foreach ($name in @($entry, 'plugin.json', 'readme.md')) {
    $files.Add($name)
}
if (Test-Path -LiteralPath (Join-Path $source 'LICENSE') -PathType Leaf) { $files.Add('LICENSE') }
Get-ChildItem -LiteralPath (Join-Path $source 'assets') -Recurse -File -Force | ForEach-Object {
    $files.Add(($_.FullName.Substring($source.Length + 1) -replace '\\', '/'))
}
if ($files.Count -gt 128) { throw '插件包最多包含 128 个条目' }

$total = 0L
foreach ($name in $files) {
    $item = Get-Item -LiteralPath (Join-Path $source $name)
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "插件包不允许链接文件: $name" }
    if ($item.Length -gt 2MB) { throw "单个文件超过 2 MB: $name" }
    $total += $item.Length
}
if ($total -gt 20MB) { throw '插件包总资源超过 20 MB' }

$parent = [IO.Path]::GetDirectoryName($output)
[IO.Directory]::CreateDirectory($parent) | Out-Null
if (Test-Path -LiteralPath $output) { Remove-Item -LiteralPath $output -Force }

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stream = [IO.File]::Open($output, [IO.FileMode]::CreateNew)
try {
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        $hasAssetFile = @($files | Where-Object { $_ -like 'assets/*' }).Count -gt 0
        if (-not $hasAssetFile) {
            [void]$archive.CreateEntry('assets/')
        }
        foreach ($name in $files) {
            $item = Get-Item -LiteralPath (Join-Path $source $name)
            [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $archive,
                $item.FullName,
                $name,
                [IO.Compression.CompressionLevel]::Optimal
            )
        }
    } finally {
        $archive.Dispose()
    }
} finally {
    $stream.Dispose()
}

$info = Get-Item -LiteralPath $output
if ($info.Length -gt 10MB) {
    Remove-Item -LiteralPath $output -Force
    throw '压缩包超过 10 MB'
}
$hash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLower()
Write-Output "插件包已生成: $($info.FullName)"
Write-Output "大小: $([Math]::Round($info.Length / 1KB, 1)) KB"
Write-Output "SHA256: $hash"
