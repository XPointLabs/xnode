[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern("^[0-9a-f]{40}$")]
    [string]$ExpectedRepositoryCommit
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression.FileSystem

$relationshipsNamespace =
    "http://schemas.openxmlformats.org/package/2006/relationships"
$contentTypesNamespace =
    "http://schemas.openxmlformats.org/package/2006/content-types"
$coreNamespace =
    "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
$dcNamespace = "http://purl.org/dc/elements/1.1/"
$dctermsNamespace = "http://purl.org/dc/terms/"
$xsiNamespace = "http://www.w3.org/2001/XMLSchema-instance"
$xmlnsNamespace = "http://www.w3.org/2000/xmlns/"
$manifestRelationshipType =
    "http://schemas.microsoft.com/packaging/2010/07/manifest"
$coreRelationshipType =
    "$relationshipsNamespace/metadata/core-properties"

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    return ([BitConverter]::ToString($Bytes) -replace "-", "").ToLowerInvariant()
}

function Get-Bytes {
    param([System.IO.Compression.ZipArchiveEntry]$Entry)
    $stream = $Entry.Open()
    try {
        $memory = [System.IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            return $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-Sha256 {
    param([byte[]]$Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ConvertTo-HexString ($sha256.ComputeHash($Bytes))
    }
    finally {
        $sha256.Dispose()
    }
}

function Read-StrictXml {
    param([byte[]]$Bytes, [string]$Label)
    $text = [Text.Encoding]::UTF8.GetString($Bytes).TrimStart([char]0xfeff)
    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.IgnoreComments = $false
    $settings.IgnoreProcessingInstructions = $false
    $stringReader = [System.IO.StringReader]::new($text)
    try {
        $reader = [System.Xml.XmlReader]::Create($stringReader, $settings)
        try {
            $document = [System.Xml.XmlDocument]::new()
            $document.XmlResolver = $null
            $document.PreserveWhitespace = $true
            $document.Load($reader)
            if ($null -eq $document.DocumentElement) {
                throw "$Label has no document element."
            }
            return $document
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stringReader.Dispose()
    }
}

function Get-QualifiedName {
    param([System.Xml.XmlNode]$Node)
    return "{$($Node.NamespaceURI)}$($Node.LocalName)"
}

function ConvertTo-CanonicalXml {
    param([System.Xml.XmlDocument]$Document)
    $builder = [Text.StringBuilder]::new()

    function Add-Node {
        param(
            [System.Xml.XmlNode]$Node,
            [Text.StringBuilder]$Builder
        )
        if ($Node.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $name = Get-QualifiedName $Node
            [void]$Builder.Append("E").Append($name.Length).Append(":").Append($name)
            $attributes = @($Node.Attributes | Where-Object {
                $_.NamespaceURI -ne $xmlnsNamespace
            } | Sort-Object NamespaceURI, LocalName)
            [void]$Builder.Append("A").Append($attributes.Count).Append(":")
            foreach ($attribute in $attributes) {
                $attributeName = Get-QualifiedName $attribute
                [void]$Builder.Append($attributeName.Length).Append(":").
                    Append($attributeName).Append($attribute.Value.Length).
                    Append(":").Append($attribute.Value)
            }
            foreach ($child in $Node.ChildNodes) {
                Add-Node $child $Builder
            }
            [void]$Builder.Append("Z")
            return
        }

        if ($Node.NodeType -in @(
            [System.Xml.XmlNodeType]::Text,
            [System.Xml.XmlNodeType]::CDATA
        )) {
            if (-not [string]::IsNullOrWhiteSpace($Node.Value)) {
                [void]$Builder.Append("T").Append($Node.Value.Length).
                    Append(":").Append($Node.Value)
            }
            return
        }

        if ($Node.NodeType -eq [System.Xml.XmlNodeType]::Whitespace -or
            $Node.NodeType -eq [System.Xml.XmlNodeType]::SignificantWhitespace) {
            return
        }

        throw "XML comments, processing instructions and other non-semantic nodes are forbidden."
    }

    Add-Node $Document.DocumentElement $builder
    return $builder.ToString()
}

function Assert-Root {
    param(
        [System.Xml.XmlDocument]$Document,
        [string]$Namespace,
        [string]$LocalName,
        [string]$Label
    )
    $root = $Document.DocumentElement
    if ($root.NamespaceURI -ne $Namespace -or
        $root.LocalName -ne $LocalName) {
        throw "$Label root element is invalid."
    }
    $attributes = @($root.Attributes | Where-Object {
        $_.NamespaceURI -ne $xmlnsNamespace
    })
    if ($attributes.Count -ne 0) {
        throw "$Label root has unexpected attributes."
    }
}

function Assert-ExactAttributes {
    param(
        [System.Xml.XmlElement]$Element,
        [AllowEmptyCollection()]
        [string[]]$Expected,
        [string]$Label
    )
    $actual = @($Element.Attributes | Where-Object {
        $_.NamespaceURI -ne $xmlnsNamespace
    } | ForEach-Object {
        "$(Get-QualifiedName $_)"
    })
    if ($Expected.Count -ne $actual.Count -or
        ($Expected.Count -gt 0 -and
            $null -ne (Compare-Object `
                ($Expected | Sort-Object) `
                ($actual | Sort-Object)))) {
        throw "$Label attributes differ from the exact allowlist."
    }
}

function Get-ElementChildren {
    param([System.Xml.XmlElement]$Element, [string]$Label)
    $children = @()
    foreach ($node in $Element.ChildNodes) {
        if ($node.NodeType -eq [System.Xml.XmlNodeType]::Element) {
            $children += $node
            continue
        }
        if ($node.NodeType -in @(
            [System.Xml.XmlNodeType]::Whitespace,
            [System.Xml.XmlNodeType]::SignificantWhitespace
        )) {
            continue
        }
        if ($node.NodeType -eq [System.Xml.XmlNodeType]::Text -and
            [string]::IsNullOrWhiteSpace($node.Value)) {
            continue
        }
        throw "$Label contains unexpected non-element content."
    }
    return @($children)
}

function Assert-Leaf {
    param([System.Xml.XmlElement]$Element, [string]$Label)
    foreach ($node in $Element.ChildNodes) {
        if ($node.NodeType -eq [System.Xml.XmlNodeType]::Element -or
            $node.NodeType -eq [System.Xml.XmlNodeType]::Comment -or
            $node.NodeType -eq [System.Xml.XmlNodeType]::ProcessingInstruction) {
            throw "$Label must be an exact text-only property."
        }
    }
}

function Assert-EmptyElement {
    param([System.Xml.XmlElement]$Element, [string]$Label)
    foreach ($node in $Element.ChildNodes) {
        if ($node.NodeType -in @(
            [System.Xml.XmlNodeType]::Whitespace,
            [System.Xml.XmlNodeType]::SignificantWhitespace
        )) {
            continue
        }
        if ($node.NodeType -eq [System.Xml.XmlNodeType]::Text -and
            [string]::IsNullOrWhiteSpace($node.Value)) {
            continue
        }
        throw "$Label must be an empty element."
    }
}

function Get-Entry {
    param(
        [System.IO.Compression.ZipArchive]$Archive,
        [string]$Name
    )
    $matches = @($Archive.Entries | Where-Object {
        $_.FullName -ceq $Name
    })
    if ($matches.Count -ne 1) {
        throw "Package entry '$Name' must occur exactly once with exact casing."
    }
    return $matches[0]
}

function Get-CanonicalRelationships {
    param(
        [System.Xml.XmlDocument]$Document,
        [string]$NuspecName,
        [string]$CoreName
    )
    Assert-Root $Document $relationshipsNamespace "Relationships" `
        "OPC relationships"
    $children = Get-ElementChildren $Document.DocumentElement `
        "OPC relationships"
    if ($children.Count -ne 2) {
        throw "The root OPC relationship set must contain exactly two entries."
    }

    $records = @()
    $ids = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($element in $children) {
        if ($element.NamespaceURI -ne $relationshipsNamespace -or
            $element.LocalName -ne "Relationship") {
            throw "The root OPC relationship set contains an unexpected element."
        }
        Assert-ExactAttributes $element @(
            "{}Id",
            "{}Target",
            "{}Type"
        ) "OPC Relationship"
        Assert-EmptyElement $element "OPC Relationship"
        $id = $element.GetAttribute("Id")
        $type = $element.GetAttribute("Type")
        $target = $element.GetAttribute("Target")
        if ($id -notmatch "^R[A-Za-z0-9]+$" -or -not $ids.Add($id)) {
            throw "OPC relationship IDs must be non-empty, well formed and unique."
        }
        $records += [ordered]@{
            type = $type
            target = $target
        }
    }

    $expected = @(
        "$manifestRelationshipType|/$NuspecName",
        "$coreRelationshipType|/$CoreName"
    ) | Sort-Object
    $actual = @($records | ForEach-Object {
        "$($_.type)|$($_.target)"
    } | Sort-Object)
    if ($null -ne (Compare-Object $expected $actual)) {
        throw "OPC relationships do not bind the exact nuspec and core parts."
    }

    return @($records | Sort-Object { "$($_.type)|$($_.target)" } |
        ForEach-Object {
            [ordered]@{
                type = $_.type
                target = if ($_.type -eq $coreRelationshipType) {
                    "/package/services/metadata/core-properties/{random-guid}.psmdcp"
                }
                else {
                    $_.target
                }
            }
        })
}

function Get-CanonicalContentTypes {
    param([System.Xml.XmlDocument]$Document)
    Assert-Root $Document $contentTypesNamespace "Types" "OPC content types"
    $children = Get-ElementChildren $Document.DocumentElement `
        "OPC content types"
    $defaults = @()
    $overrides = @()
    foreach ($element in $children) {
        if ($element.NamespaceURI -ne $contentTypesNamespace) {
            throw "OPC content types contain an unexpected namespace."
        }
        if ($element.LocalName -eq "Default") {
            Assert-ExactAttributes $element @(
                "{}ContentType",
                "{}Extension"
            ) "OPC Default content type"
            Assert-EmptyElement $element "OPC Default content type"
            $defaults += "$($element.GetAttribute("Extension"))|$($element.GetAttribute("ContentType"))"
            continue
        }
        if ($element.LocalName -eq "Override") {
            Assert-ExactAttributes $element @(
                "{}ContentType",
                "{}PartName"
            ) "OPC Override content type"
            Assert-EmptyElement $element "OPC Override content type"
            $overrides += "$($element.GetAttribute("PartName"))|$($element.GetAttribute("ContentType"))"
            continue
        }
        throw "OPC content types contain an unexpected element."
    }

    $expectedDefaults = @(
        "dll|application/octet",
        "md|application/octet",
        "nuspec|application/octet",
        "pdb|application/octet",
        "psmdcp|application/vnd.openxmlformats-package.core-properties+xml",
        "rels|application/vnd.openxmlformats-package.relationships+xml"
    ) | Sort-Object
    $sortedDefaults = @($defaults | Sort-Object)
    if ($null -ne (Compare-Object $expectedDefaults $sortedDefaults) -or
        $defaults.Count -ne $expectedDefaults.Count) {
        throw "OPC default content types differ from the exact package model."
    }
    if ($overrides.Count -ne 0) {
        throw "OPC content-type overrides are forbidden for this exact package."
    }
    return [ordered]@{
        defaults = $sortedDefaults
        overrides = @()
    }
}

function Get-CanonicalCoreProperties {
    param(
        [System.Xml.XmlDocument]$Document,
        [System.Xml.XmlElement]$Metadata
    )
    Assert-Root $Document $coreNamespace "coreProperties" `
        "OPC core properties"
    $children = Get-ElementChildren $Document.DocumentElement `
        "OPC core properties"
    $values = [ordered]@{}
    $createdPresent = $false
    foreach ($element in $children) {
        $key = Get-QualifiedName $element
        if ($values.Contains($key)) {
            throw "OPC core properties contain a duplicate '$key'."
        }
        Assert-Leaf $element "OPC core property '$key'"
        if ($key -eq "{$dctermsNamespace}created") {
            Assert-ExactAttributes $element @(
                "{$xsiNamespace}type"
            ) "OPC created property"
            $typeName = $element.GetAttribute("type", $xsiNamespace)
            $typeParts = @($typeName.Split(":"))
            if ($typeParts.Count -ne 2 -or
                $typeParts[1] -ne "W3CDTF" -or
                $element.GetNamespaceOfPrefix($typeParts[0]) -ne
                    $dctermsNamespace) {
                throw "The OPC creation timestamp shape is invalid."
            }

            $createdText = $element.InnerText
            $createdMatch = [regex]::Match(
                $createdText,
                "^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}" +
                    "(?:\.(?<fraction>\d{1,7}))?Z$",
                [Text.RegularExpressions.RegexOptions]::CultureInvariant)
            if (-not $createdMatch.Success) {
                throw "The OPC creation timestamp shape is invalid."
            }

            $timestampFormat = "yyyy-MM-dd'T'HH:mm:ss"
            if ($createdMatch.Groups["fraction"].Success) {
                $timestampFormat += "." +
                    ("f" * $createdMatch.Groups["fraction"].Length)
            }
            $timestampFormat += "'Z'"
            $parsed = [DateTimeOffset]::MinValue
            $timestampStyles =
                [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal
            if (-not [DateTimeOffset]::TryParseExact(
                $createdText,
                $timestampFormat,
                [Globalization.CultureInfo]::InvariantCulture,
                $timestampStyles,
                [ref]$parsed)) {
                throw "The OPC creation timestamp is invalid."
            }
            $createdPresent = $true
            $values[$key] = "{normalized-creation-timestamp}"
            continue
        }
        Assert-ExactAttributes $element @() "OPC core property '$key'"
        $values[$key] = $element.InnerText
    }

    $requiredKeys = @(
        "{$dcNamespace}creator",
        "{$dcNamespace}description",
        "{$dcNamespace}identifier",
        "{$coreNamespace}version",
        "{$coreNamespace}keywords",
        "{$coreNamespace}lastModifiedBy"
    )
    $allowedKeys = @($requiredKeys + "{$dctermsNamespace}created")
    if ($null -ne (Compare-Object `
        ($allowedKeys | Where-Object { $values.Contains($_) } | Sort-Object) `
        ($values.Keys | Sort-Object)) -or
        $null -ne ($requiredKeys | Where-Object { -not $values.Contains($_) })) {
        throw "OPC core properties differ from the exact field allowlist."
    }

    $bindings = [ordered]@{
        "{$dcNamespace}creator" = [string]$Metadata.authors
        "{$dcNamespace}description" = [string]$Metadata.description
        "{$dcNamespace}identifier" = [string]$Metadata.id
        "{$coreNamespace}version" = [string]$Metadata.version
        "{$coreNamespace}keywords" = ""
    }
    foreach ($binding in $bindings.GetEnumerator()) {
        if ($values[$binding.Key] -cne $binding.Value) {
            throw "OPC core property '$($binding.Key)' is not bound to nuspec semantics."
        }
    }
    if ([string]::IsNullOrWhiteSpace(
        $values["{$coreNamespace}lastModifiedBy"])) {
        throw "OPC lastModifiedBy must be present and non-empty."
    }

    $canonical = [ordered]@{}
    foreach ($key in @($values.Keys | Sort-Object)) {
        $canonical[$key] = $values[$key]
    }
    $canonical["creationTimestampPresent"] = $createdPresent
    return $canonical
}

$PackagePath = (Resolve-Path -LiteralPath $PackagePath).Path
$zip = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
try {
    $names = @($zip.Entries | ForEach-Object { $_.FullName })
    if (($names | Sort-Object -Unique).Count -ne $names.Count) {
        throw "Duplicate package entry names are forbidden."
    }
    $nuspecEntries = @($zip.Entries | Where-Object {
        $_.FullName -clike "*.nuspec"
    })
    $coreEntries = @($zip.Entries | Where-Object {
        $_.FullName -cmatch "^package/services/metadata/core-properties/[0-9a-f]{32}\.psmdcp$"
    })
    if ($nuspecEntries.Count -ne 1 -or $coreEntries.Count -ne 1) {
        throw "The package must contain exactly one nuspec and one GUID-named OPC core entry."
    }
    $nuspecName = $nuspecEntries[0].FullName
    $coreName = $coreEntries[0].FullName
    $semanticNames = @(
        $nuspecName,
        "README.md",
        "lib/net10.0/Deep.Protocol.ProfileCarrier.dll",
        "lib/net10.0/Deep.Protocol.ProfileCarrier.pdb"
    )
    $opcNames = @(
        "_rels/.rels",
        "[Content_Types].xml",
        $coreName
    )
    $allowedNames = @($semanticNames + $opcNames)
    if ($null -ne (Compare-Object `
        ($allowedNames | Sort-Object) `
        ($names | Sort-Object))) {
        throw "The package entry set differs from the exact semantic/OPC allowlist."
    }

    $nuspecDocument = Read-StrictXml `
        (Get-Bytes $nuspecEntries[0]) `
        "nuspec"
    $metadata = $nuspecDocument.package.metadata
    $repository = $metadata.repository
    if ($repository.type -ne "git" -or
        $repository.url -ne "https://github.com/XPointLabs/deep-protocol.git" -or
        $repository.commit -ne $ExpectedRepositoryCommit) {
        throw "The nuspec repository identity is not the verified exact commit."
    }
    $dependencyElements = @($metadata.dependencies.group.dependency)
    $actualDependencies = @($dependencyElements | ForEach-Object {
        "$($_.id)|$($_.version)"
    } | Sort-Object)
    $expectedDependencies = @(
        "Deep.Protocol|[0.3.0-p04.b887fa0]",
        "libsodium|[1.0.22]",
        "Sodium.Core|[1.4.1]"
    ) | Sort-Object
    if ($dependencyElements.Count -ne $expectedDependencies.Count -or
        $null -ne (Compare-Object $expectedDependencies $actualDependencies)) {
        throw "The package dependency graph differs from the exact P14E2 allowlist."
    }
    $normalizedNuspecBytes = [Text.Encoding]::UTF8.GetBytes(
        (ConvertTo-CanonicalXml $nuspecDocument))

    $relationships = Get-CanonicalRelationships `
        (Read-StrictXml `
            (Get-Bytes (Get-Entry $zip "_rels/.rels")) `
            "OPC relationships") `
        $nuspecName `
        $coreName
    $contentTypes = Get-CanonicalContentTypes `
        (Read-StrictXml `
            (Get-Bytes (Get-Entry $zip "[Content_Types].xml")) `
            "OPC content types")
    $coreProperties = Get-CanonicalCoreProperties `
        (Read-StrictXml `
            (Get-Bytes $coreEntries[0]) `
            "OPC core properties") `
        $metadata

    $entries = @()
    foreach ($name in @(
        "README.md",
        "lib/net10.0/Deep.Protocol.ProfileCarrier.dll",
        "lib/net10.0/Deep.Protocol.ProfileCarrier.pdb"
    )) {
        $bytes = Get-Bytes (Get-Entry $zip $name)
        $entries += [ordered]@{
            path = $name
            length = $bytes.Length
            sha256 = Get-Sha256 $bytes
        }
    }
    $entries += [ordered]@{
        path = "$nuspecName#canonical-xml"
        length = $normalizedNuspecBytes.Length
        sha256 = Get-Sha256 $normalizedNuspecBytes
    }
    $entries = @($entries | Sort-Object { $_.path })

    $manifest = [ordered]@{
        schema = "deep-p14-profile-carrier-normalized-package-v2"
        packageId = [string]$metadata.id
        version = [string]$metadata.version
        repositoryCommit = [string]$repository.commit
        opc = [ordered]@{
            relationships = $relationships
            contentTypes = $contentTypes
            coreProperties = $coreProperties
        }
        entries = $entries
    }
    $json = $manifest | ConvertTo-Json -Depth 12 -Compress
    $identityHash = Get-Sha256 ([Text.Encoding]::UTF8.GetBytes($json))
    [PSCustomObject]@{
        Schema = $manifest.schema
        Version = $manifest.version
        RepositoryCommit = $manifest.repositoryCommit
        Hash = $identityHash
        Manifest = $json
        DllHash = ($entries |
            Where-Object {
                $_.path -eq "lib/net10.0/Deep.Protocol.ProfileCarrier.dll"
            }
        ).sha256
    }
}
finally {
    $zip.Dispose()
}
