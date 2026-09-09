[CmdletBinding()]
param([string] $RepositoryRoot = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$vendor = Join-Path $root 'vendor\dnp1-survival-9a7eaed'
$manifestPath = Join-Path $vendor 'package-provenance.json'
$expectedVersion = '0.5.0-survival.9a7eaed'
$expectedCommit = '9a7eaed337286758ab43bd3706457264c3be7c55'
$expectedTree = 'c0b23f91bfb13158ac9a28ff73fe73a1f44fc95d'
$expectedArchiveSha256 = '3b2bd1b2db7af78341589577b3bb7051da34802289d89ea2dd3f5d143f973099'
$expectedRepositoryUrl = 'https://github.com/XPointLabs/deep-protocol.git'
$expected = [ordered]@{
    'Deep.Protocol' = [ordered]@{
        File = "packages/Deep.Protocol.$expectedVersion.nupkg"
        Bytes = 475982
        Sha256 = '4bb199b287f7cd41332e166c6ffcf915fc6b9372fb8b80408dca5522eaed3bb9'
        Sha512 = 'a7ba6d40dfdce18efbfa2fa35c569af8f966f28066a1dbed6a16990a1bca0487695edbce821b753c787c095c30a5fb53694af879e208f48ca6a41b7fc03d9838'
        AssemblySha256 = '5c7a15b97e48e344f8cc152cea636dbd14296a96a4c2864bb97ba6ee0e279c47'
        Assembly = 'lib/net10.0/Deep.Protocol.dll'
        Dependencies = @('Sodium.Core=[1.4.1]')
    }
    'Deep.Protocol.MembershipRoutes' = [ordered]@{
        File = "packages/Deep.Protocol.MembershipRoutes.$expectedVersion.nupkg"
        Bytes = 184328
        Sha256 = 'cb0407979830992ee338e3b3b09c558e5c4e256f56df2da54df3eb9d98c7b3d2'
        Sha512 = 'c18bbcd969bb16349e6fe5c90bc13e86c7e3eb49df71e8282a0f2a3e8ec396ff35451604b99561c5df661cb9f6046fd9019b9e1d0bcdfd0f650c53cf0b6b6d63'
        AssemblySha256 = 'eee28f236eb748f408412439a591913af83a696b75bb1d205e92b30590a7cec0'
        Assembly = 'lib/net10.0/Deep.Protocol.MembershipRoutes.dll'
        Dependencies = @("Deep.Protocol=[$expectedVersion]")
    }
    'Deep.Protocol.ProfileCarrier' = [ordered]@{
        File = "packages/Deep.Protocol.ProfileCarrier.$expectedVersion.nupkg"
        Bytes = 72607
        Sha256 = '43950e48ac28fd3e4c0064fa12293e3ea8b12ad6bea15e8fa173a17f4480c9e5'
        Sha512 = 'cfd6b8f1ee292be275694952b8ad7859e87befb78224b04a87b694fae346e6998d97f3c699bd4bcfdd855302c77b5e6e7f4820ddf7e5392f9495a94aa0e8faa4'
        AssemblySha256 = '49f333e0c2e0fbb1d7bd407a23cded68eec5daeb106d54df910c6eeb7111824a'
        Assembly = 'lib/net10.0/Deep.Protocol.ProfileCarrier.dll'
        Dependencies = @(
            "Deep.Protocol=[$expectedVersion]",
            'libsodium=[1.0.22]',
            'Sodium.Core=[1.4.1]'
        )
    }
}
$forbidden = @(
    'Deep.Protocol.Abstractions',
    'Deep.Protocol.Native',
    'Deep.Protocol.Protobuf',
    'Google.Protobuf'
)

function Assert-Equal([object] $Expected, [object] $Actual, [string] $Label) {
    if ([string]$Expected -cne [string]$Actual) {
        throw "DNP1 protocol closure: $Label differs."
    }
}

function Assert-ExactProperties([object] $Value, [string[]] $Names, [string] $Label) {
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Names | Sort-Object)
    if ([string]::Join('|', $actual) -cne [string]::Join('|', $wanted)) {
        throw "DNP1 protocol closure: $Label fields differ."
    }
}

function Read-StrictNuspec([string] $Path) {
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        if ($archive.Entries.Count -le 0 -or $archive.Entries.Count -gt 4096) {
            throw 'DNP1 protocol closure: package entry count is outside the supported bounds.'
        }
        $entries = @($archive.Entries | Where-Object {
            $_.FullName.EndsWith('.nuspec', [StringComparison]::OrdinalIgnoreCase)
        })
        if ($entries.Count -ne 1 -or $entries[0].Length -gt 1MB) {
            throw 'DNP1 protocol closure: nuspec is missing, duplicated, or oversized.'
        }
        $reader = [IO.StreamReader]::new(
            $entries[0].Open(), [Text.UTF8Encoding]::new($false, $true))
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $xmlReader = [Xml.XmlReader]::Create([IO.StringReader]::new($text), $settings)
        try {
            $document = [Xml.XmlDocument]::new()
            $document.XmlResolver = $null
            $document.Load($xmlReader)
            return $document
        }
        finally { $xmlReader.Dispose() }
    }
    finally { $archive.Dispose() }
}

function Get-PackageEntrySha256([string] $Path, [string] $EntryName) {
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entries = @($archive.Entries | Where-Object { $_.FullName -ceq $EntryName })
        if ($entries.Count -ne 1) {
            throw 'DNP1 protocol closure: package assembly entry differs.'
        }
        $stream = $entries[0].Open()
        try {
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
            }
            finally { $sha.Dispose() }
        }
        finally { $stream.Dispose() }
    }
    finally { $archive.Dispose() }
}

function Get-FileDigest([string] $Path, [ValidateSet('SHA256', 'SHA512')] [string] $Algorithm) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $hash = if ($Algorithm -ceq 'SHA256') {
            [Security.Cryptography.SHA256]::Create()
        }
        else {
            [Security.Cryptography.SHA512]::Create()
        }
        try {
            return ([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        }
        finally { $hash.Dispose() }
    }
    finally { $stream.Dispose() }
}

if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'DNP1 protocol closure: provenance manifest is missing.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-ExactProperties $manifest @(
    'schema', 'version', 'protocolSourceCommit', 'protocolSourceTree',
    'sourceArchiveSha256', 'buildPathMap', 'normalization', 'reproducibility',
    'networkSourcesAllowedForDeepProtocol', 'packages') 'manifest'
Assert-Equal 'xnode-dnp1-protocol-closure.v2' $manifest.schema 'manifest schema'
Assert-Equal $expectedVersion $manifest.version 'closure version'
Assert-Equal $expectedCommit $manifest.protocolSourceCommit 'protocol source commit'
Assert-Equal $expectedTree $manifest.protocolSourceTree 'protocol source tree'
Assert-Equal $expectedArchiveSha256 $manifest.sourceArchiveSha256 'protocol source archive SHA-256'
Assert-Equal '/_/deep-protocol' $manifest.buildPathMap 'deterministic build path map'
Assert-Equal 'Normalize-NuGetPackage/exact-all-dependencies.v1' $manifest.normalization 'normalization contract'
Assert-Equal 'two-independent-git-archive-builds-byte-identical' $manifest.reproducibility 'reproducibility proof'
if ($manifest.networkSourcesAllowedForDeepProtocol -ne $false) {
    throw 'DNP1 protocol closure: network protocol source must be disabled.'
}
if ($manifest.packages.Count -ne $expected.Count) {
    throw 'DNP1 protocol closure: package count differs.'
}

$packageFiles = @(Get-ChildItem -LiteralPath (Join-Path $vendor 'packages') -File)
if ($packageFiles.Count -ne $expected.Count -or
    @($packageFiles | Where-Object { $_.Extension -cne '.nupkg' }).Count -ne 0) {
    throw 'DNP1 protocol closure: vendor inventory is not exact-three nupkg files.'
}

foreach ($id in $expected.Keys) {
    $contract = $expected[$id]
    $items = @($manifest.packages | Where-Object { $_.id -ceq $id })
    if ($items.Count -ne 1) {
        throw 'DNP1 protocol closure: package identity set differs.'
    }
    $item = $items[0]
    Assert-ExactProperties $item @(
        'id', 'version', 'file', 'bytes', 'sha256', 'sha512',
        'assemblySha256', 'dependencies') "$id manifest entry"
    Assert-Equal $expectedVersion $item.version "$id manifest version"
    Assert-Equal $contract.File $item.file "$id manifest path"
    Assert-Equal $contract.Bytes $item.bytes "$id manifest byte length"
    Assert-Equal $contract.Sha256 $item.sha256 "$id manifest SHA-256"
    Assert-Equal $contract.Sha512 $item.sha512 "$id manifest SHA-512"
    Assert-Equal $contract.AssemblySha256 $item.assemblySha256 "$id assembly SHA-256"
    $manifestDependencies = @($item.dependencies | Sort-Object)
    $expectedDependencies = @($contract.Dependencies | Sort-Object)
    Assert-Equal ([string]::Join('|', $expectedDependencies)) `
        ([string]::Join('|', $manifestDependencies)) "$id manifest dependencies"

    $path = Join-Path $vendor $contract.File
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "DNP1 protocol closure: $id package is missing."
    }
    Assert-Equal $contract.Bytes (Get-Item -LiteralPath $path).Length "$id byte length"
    Assert-Equal $contract.Sha256 `
        (Get-FileDigest $path SHA256) "$id SHA-256"
    Assert-Equal $contract.Sha512 `
        (Get-FileDigest $path SHA512) "$id SHA-512"
    Assert-Equal $contract.AssemblySha256 `
        (Get-PackageEntrySha256 $path $contract.Assembly) "$id assembly SHA-256"

    $nuspec = Read-StrictNuspec $path
    $manager = [Xml.XmlNamespaceManager]::new($nuspec.NameTable)
    $manager.AddNamespace('n', $nuspec.DocumentElement.NamespaceURI)
    $metadata = $nuspec.SelectSingleNode('/n:package/n:metadata', $manager)
    $idNode = $metadata.SelectSingleNode('n:id', $manager)
    $versionNode = $metadata.SelectSingleNode('n:version', $manager)
    $repositoryNode = $metadata.SelectSingleNode('n:repository', $manager)
    if ($null -eq $idNode -or $null -eq $versionNode -or $null -eq $repositoryNode) {
        throw "DNP1 protocol closure: $id identity metadata is incomplete."
    }
    Assert-Equal $id $idNode.InnerText "$id nuspec id"
    Assert-Equal $expectedVersion $versionNode.InnerText "$id nuspec version"
    Assert-Equal $expectedCommit $repositoryNode.GetAttribute('commit') "$id repository commit"
    Assert-Equal $expectedRepositoryUrl $repositoryNode.GetAttribute('url') "$id repository URL"
    $dependencies = @($metadata.SelectNodes('.//n:dependency', $manager) | ForEach-Object {
        $dependencyId = $_.GetAttribute('id')
        $dependencyVersion = $_.GetAttribute('version')
        if ($dependencyVersion -notmatch '^\[[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\]$') {
            throw "DNP1 protocol closure: $id dependency '$dependencyId' is not exact-bracketed."
        }
        "$dependencyId=$dependencyVersion"
    } | Sort-Object)
    Assert-Equal ([string]::Join('|', $expectedDependencies)) `
        ([string]::Join('|', $dependencies)) "$id nuspec dependencies"
}

$projectPath = Join-Path $root 'src\XNode.ProfileGenerator\XNode.ProfileGenerator.csproj'
$propsPath = Join-Path $root 'Directory.Packages.props'
[xml]$props = Get-Content -LiteralPath $propsPath -Raw
$versionProperties = @($props.Project.PropertyGroup.Dnp1ProtocolPackageVersion)
if ($versionProperties.Count -ne 1) {
    throw 'DNP1 protocol closure: central version property differs.'
}
Assert-Equal $expectedVersion ([string]$versionProperties[0]) 'central DNP1 version'
[xml]$project = Get-Content -LiteralPath $projectPath -Raw
$protocolReferences = @($project.Project.ItemGroup.PackageReference | Where-Object {
    ([string]$_.Include).StartsWith('Deep.Protocol', [StringComparison]::Ordinal)
})
$projectPins = @($protocolReferences | ForEach-Object {
    "$([string]$_.Include)=$([string]$_.Version)"
} | Sort-Object)
$centralReference = '[$(Dnp1ProtocolPackageVersion)]'
$expectedPins = @($expected.Keys | ForEach-Object { "$_=$centralReference" } | Sort-Object)
Assert-Equal ([string]::Join('|', $expectedPins)) `
    ([string]::Join('|', $projectPins)) 'ProfileGenerator exact-three references'

foreach ($relative in @(
    'src\XNode.ProfileGenerator\packages.lock.json',
    'tests\XNode.ProfileGenerator.Tests\packages.lock.json'
)) {
    $lock = Get-Content -LiteralPath (Join-Path $root $relative) -Raw | ConvertFrom-Json
    foreach ($target in $lock.dependencies.PSObject.Properties) {
        $names = @($target.Value.PSObject.Properties.Name)
        $protocolNames = @($names | Where-Object {
            $_.StartsWith('Deep.Protocol', [StringComparison]::Ordinal)
        } | Sort-Object)
        if ($target.Name.IndexOf('/', [StringComparison]::Ordinal) -ge 0) {
            Assert-Equal '' ([string]::Join('|', $protocolNames)) `
                "$relative/$($target.Name) RID protocol graph"
            Assert-Equal 'libsodium' ([string]::Join('|', @($names | Sort-Object))) `
                "$relative/$($target.Name) RID runtime graph"
        }
        else {
            Assert-Equal ([string]::Join('|', @($expected.Keys | Sort-Object))) `
                ([string]::Join('|', $protocolNames)) "$relative/$($target.Name) protocol graph"
            foreach ($protocolName in $protocolNames) {
                Assert-Equal $expectedVersion $target.Value.$protocolName.resolved `
                    "$relative/$($target.Name)/$protocolName resolved version"
            }
        }
        foreach ($name in $forbidden) {
            if ($names -contains $name) {
                throw "DNP1 protocol closure: forbidden dependency '$name' remains in $relative."
            }
        }
    }
}

$configPath = Join-Path $root 'eng\dnp1-survival.NuGet.Config'
[xml]$config = Get-Content -LiteralPath $configPath -Raw
$protocolSources = @($config.configuration.packageSources.add | Where-Object {
    $_.key -ne 'nuget.org'
})
if ($protocolSources.Count -ne 1) {
    throw 'DNP1 protocol closure: local NuGet source differs.'
}
$sourceValues = @{}
foreach ($source in $protocolSources) { $sourceValues[[string]$source.key] = [string]$source.value }
Assert-Equal '../vendor/dnp1-survival-9a7eaed/packages' `
    $sourceValues['dnp1-protocol-closure'] 'DNP1 NuGet source'
foreach ($sourceKey in @('dnp1-protocol-closure')) {
    $mapping = @($config.configuration.packageSourceMapping.packageSource | Where-Object {
        $_.key -ceq $sourceKey
    })
    if ($mapping.Count -ne 1) {
        throw 'DNP1 protocol closure: package source mapping differs.'
    }
    $patterns = @($mapping[0].package.pattern | Sort-Object)
    Assert-Equal 'Deep.Protocol|Deep.Protocol.*' ([string]::Join('|', $patterns)) `
        "$sourceKey protocol source patterns"
}
$protocolMappings = @($config.configuration.packageSourceMapping.packageSource | Where-Object {
    $patterns = @($_.package.pattern)
    $patterns -contains 'Deep.Protocol' -or $patterns -contains 'Deep.Protocol.*'
})
if ($protocolMappings.Count -ne 1 -or
    [string]$protocolMappings[0].key -cne 'dnp1-protocol-closure') {
    throw 'DNP1 protocol closure: Deep.Protocol is mapped outside the intended local feed.'
}

$activeFiles = @($projectPath,
    $propsPath,
    (Join-Path $root 'src\XNode.ProfileGenerator\packages.lock.json'),
    (Join-Path $root 'tests\XNode.ProfileGenerator.Tests\packages.lock.json'),
    $configPath)
foreach ($path in $activeFiles) {
    $text = Get-Content -LiteralPath $path -Raw
    foreach ($stale in @(
        'e570512', 'e75bfed', 'Deep.Protocol.Abstractions', 'Deep.Protocol.Protobuf', 'Google.Protobuf')) {
        if ($text.IndexOf($stale, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw "DNP1 protocol closure: stale dependency '$stale' remains in $path."
        }
    }
}

Write-Output 'DNP1 exact-three protocol closure gate PASS'
