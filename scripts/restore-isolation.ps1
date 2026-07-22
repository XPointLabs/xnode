Set-StrictMode -Version Latest

function Assert-ExactSdk {
    param([Parameter(Mandatory)][string]$Version)

    $actual = (& dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $actual -ne $Version) {
        throw "The verification requires .NET SDK $Version exactly; found '$actual'."
    }
}

function Invoke-DotNet {
    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet failed with exit code $LASTEXITCODE."
    }
}

function Assert-NoGitAuthorityEnvironmentOverrides {
    $exactNames = @(
        'GIT_DIR',
        'GIT_WORK_TREE',
        'GIT_INDEX_FILE',
        'GIT_OBJECT_DIRECTORY',
        'GIT_ALTERNATE_OBJECT_DIRECTORIES',
        'GIT_COMMON_DIR',
        'GIT_CONFIG',
        'GIT_CONFIG_GLOBAL',
        'GIT_CONFIG_SYSTEM',
        'GIT_CONFIG_NOSYSTEM',
        'GIT_CONFIG_COUNT',
        'GIT_ATTR_NOSYSTEM',
        'GIT_CEILING_DIRECTORIES',
        'GIT_DISCOVERY_ACROSS_FILESYSTEM'
    )
    foreach ($entry in Get-ChildItem Env:) {
        if (($exactNames -contains $entry.Name) -or
            $entry.Name -match '^GIT_CONFIG_(KEY|VALUE)_\d+$') {
            throw "Git authority environment override is forbidden: '$($entry.Name)'."
        }
    }
}

function Assert-ExactRepositoryAuthority {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$ExpectedHead,
        [Parameter(Mandatory)][string]$ExpectedTree,
        [string]$Label = 'Repository'
    )

    Assert-NoGitAuthorityEnvironmentOverrides
    $RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
    if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
        throw "$Label worktree is absent."
    }

    $head = @(& git -C $RepositoryRoot rev-parse --verify HEAD)
    if ($LASTEXITCODE -ne 0 -or $head.Count -ne 1 -or $head[0].Trim() -cne $ExpectedHead) {
        throw "$Label HEAD is not exact."
    }
    $tree = @(& git -C $RepositoryRoot rev-parse 'HEAD^{tree}')
    if ($LASTEXITCODE -ne 0 -or $tree.Count -ne 1 -or $tree[0].Trim() -cne $ExpectedTree) {
        throw "$Label tree is not exact."
    }
    $shallow = @(& git -C $RepositoryRoot rev-parse --is-shallow-repository)
    if ($LASTEXITCODE -ne 0 -or $shallow.Count -ne 1 -or $shallow[0].Trim() -cne 'false') {
        throw "$Label repository is shallow."
    }
    if (@(& git -C $RepositoryRoot replace -l).Count -ne 0 -or $LASTEXITCODE -ne 0) {
        throw "$Label repository has replace refs."
    }

    foreach ($key in @(
        'core.ignorestat',
        'core.fsmonitor',
        'core.attributesfile',
        'core.worktree',
        'core.sparsecheckout',
        'core.sparsecheckoutcone',
        'index.sparse'
    )) {
        $values = @(& git -C $RepositoryRoot config --get-all $key)
        if ($LASTEXITCODE -notin @(0, 1) -or $values.Count -ne 0) {
            throw "$Label repository has forbidden Git config '$key'."
        }
    }

    $alternates = @(& git -C $RepositoryRoot config --get-all objects.alternateObjectDirectories)
    if ($LASTEXITCODE -notin @(0, 1) -or $alternates.Count -ne 0) {
        throw "$Label repository has object alternates."
    }
    $common = @(& git -C $RepositoryRoot rev-parse --git-common-dir)
    if ($LASTEXITCODE -ne 0 -or $common.Count -ne 1) {
        throw "Unable to resolve the $Label common Git directory."
    }
    $commonPath = $common[0]
    if (-not [IO.Path]::IsPathRooted($commonPath)) {
        $commonPath = Join-Path $RepositoryRoot $commonPath
    }
    if (Test-Path -LiteralPath (Join-Path $commonPath 'objects\info\alternates')) {
        throw "$Label repository has an alternates file."
    }
    if (Test-Path -LiteralPath (Join-Path $commonPath 'info\grafts')) {
        throw "$Label repository has grafts."
    }
    $infoAttributes = @(& git -C $RepositoryRoot rev-parse --git-path info/attributes)
    if ($LASTEXITCODE -ne 0 -or $infoAttributes.Count -ne 1) {
        throw "Unable to resolve $Label info attributes."
    }
    $infoAttributesPath = $infoAttributes[0]
    if (-not [IO.Path]::IsPathRooted($infoAttributesPath)) {
        $infoAttributesPath = Join-Path $RepositoryRoot $infoAttributesPath
    }
    if (Test-Path -LiteralPath $infoAttributesPath) {
        throw "$Label repository has uncommitted info attributes."
    }

    $assumed = @(& git -C $RepositoryRoot ls-files -v |
        Where-Object { $_ -cmatch '^[a-z] ' })
    $assumeExitCode = $LASTEXITCODE
    $skipped = @(& git -C $RepositoryRoot ls-files -t |
        Where-Object { $_ -cmatch '^S ' })
    $skipExitCode = $LASTEXITCODE
    if ($assumeExitCode -ne 0 -or $skipExitCode -ne 0 -or
        $assumed.Count -ne 0 -or $skipped.Count -ne 0) {
        throw "$Label repository has special index flags."
    }
    & git -C $RepositoryRoot diff-index --cached --quiet HEAD --
    if ($LASTEXITCODE -ne 0) {
        throw "$Label index differs from HEAD."
    }
    & git -C $RepositoryRoot diff-files --quiet --ignore-submodules=none --
    if ($LASTEXITCODE -ne 0) {
        throw "$Label worktree bytes differ from the index."
    }
    $status = @(& git -C $RepositoryRoot status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
        throw "$Label worktree must be clean."
    }
}

function Assert-SafeWorkRootAncestors {
    param([Parameter(Mandatory)][string]$WorkRoot)

    $discoveryFiles = @(
        'Directory.Build.props',
        'Directory.Build.targets',
        'Directory.Build.rsp',
        'Directory.Solution.props',
        'Directory.Solution.targets',
        'Directory.Packages.props',
        'NuGet.Config'
    )
    $current = Split-Path -Parent ([IO.Path]::GetFullPath($WorkRoot))
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        foreach ($fileName in $discoveryFiles) {
            $candidate = Join-Path $current $fileName
            if (Test-Path -LiteralPath $candidate) {
                throw "Unsafe build customization file found above the verification work root. '$candidate'."
            }
        }

        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            break
        }
        $current = $parent
    }
}

function Get-PinnedBuildArguments {
    param([Parameter(Mandatory)][string]$SourceRoot)

    $sourceRoot = [IO.Path]::GetFullPath($SourceRoot)
    return @(
        '-noAutoResponse',
        "-p:DirectoryBuildPropsPath=$(Join-Path $sourceRoot 'Directory.Build.props')",
        "-p:DirectoryBuildTargetsPath=$(Join-Path $sourceRoot 'Directory.Build.targets')",
        "-p:DirectorySolutionPropsPath=$(Join-Path $sourceRoot 'Directory.Solution.props')",
        "-p:DirectorySolutionTargetsPath=$(Join-Path $sourceRoot 'Directory.Solution.targets')",
        "-p:DirectoryPackagesPropsPath=$(Join-Path $sourceRoot 'Directory.Packages.props')"
    )
}

function New-ExactGitSourceSnapshot {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$DestinationRoot,
        [Parameter(Mandatory)][string]$ExpectedHead,
        [Parameter(Mandatory)][string]$ExpectedTree
    )

    Assert-ExactRepositoryAuthority `
        -RepositoryRoot $RepositoryRoot `
        -ExpectedHead $ExpectedHead `
        -ExpectedTree $ExpectedTree `
        -Label 'Snapshot source'
    $RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)
    $DestinationRoot = [IO.Path]::GetFullPath($DestinationRoot)
    if (Test-Path -LiteralPath $DestinationRoot) {
        throw 'Exact Git snapshot destination must be absent.'
    }

    $emptyConfig = Join-Path (Split-Path -Parent $DestinationRoot) 'empty-git.config'
    [IO.File]::WriteAllText($emptyConfig, '', [Text.UTF8Encoding]::new($false))
    $environmentNames = @(
        'GIT_CONFIG_NOSYSTEM',
        'GIT_CONFIG_GLOBAL',
        'GIT_ATTR_NOSYSTEM',
        'GIT_ALLOW_PROTOCOL'
    )
    $previous = @{}
    foreach ($name in $environmentNames) {
        $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    try {
        $env:GIT_CONFIG_NOSYSTEM = '1'
        $env:GIT_CONFIG_GLOBAL = $emptyConfig
        $env:GIT_ATTR_NOSYSTEM = '1'
        $env:GIT_ALLOW_PROTOCOL = 'file'
        & git -c core.autocrlf=false -c core.eol=lf clone `
            --no-hardlinks --no-checkout --no-tags $RepositoryRoot $DestinationRoot | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to create the exact local Git snapshot.'
        }
        & git -C $DestinationRoot -c core.autocrlf=false -c core.eol=lf `
            checkout --detach $ExpectedHead | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to materialize the exact local Git snapshot.'
        }
        & git -C $DestinationRoot remote remove origin
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to detach the exact local Git snapshot from its source.'
        }
        & git -C $DestinationRoot config --local core.autocrlf false
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to pin snapshot line-ending materialization.'
        }
        & git -C $DestinationRoot config --local core.eol lf
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to pin snapshot line-ending identity.'
        }
    }
    finally {
        foreach ($name in $environmentNames) {
            [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
        }
    }

    Assert-ExactRepositoryAuthority `
        -RepositoryRoot $DestinationRoot `
        -ExpectedHead $ExpectedHead `
        -ExpectedTree $ExpectedTree `
        -Label 'Materialized snapshot'
    $paths = @(& git -C $DestinationRoot ls-files --cached)
    if ($LASTEXITCODE -ne 0 -or $paths.Count -eq 0) {
        throw 'Unable to enumerate exact snapshot files.'
    }
    foreach ($relativePath in $paths) {
        $path = Join-Path $DestinationRoot $relativePath
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Exact snapshot file is absent: '$relativePath'."
        }
        $expectedBlob = @(& git -C $DestinationRoot rev-parse "$ExpectedHead`:$relativePath")
        $actualBlob = @(& git -C $DestinationRoot hash-object --no-filters -- $path)
        if ($LASTEXITCODE -ne 0 -or
            $expectedBlob.Count -ne 1 -or
            $actualBlob.Count -ne 1 -or
            $actualBlob[0].Trim() -cne $expectedBlob[0].Trim()) {
            throw "Exact snapshot blob mismatch: '$relativePath'."
        }
    }
    return $DestinationRoot
}

function Get-RepositoryBuildSnapshot {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string[]]$ProjectRoots
    )

    $snapshot = @{}
    foreach ($projectRoot in $ProjectRoots) {
        foreach ($directoryName in @('bin', 'obj')) {
            $directory = Join-Path (Join-Path $RepositoryRoot $projectRoot) $directoryName
            if (-not (Test-Path -LiteralPath $directory)) {
                continue
            }
            foreach ($file in Get-ChildItem -LiteralPath $directory -File -Recurse) {
                $rootPrefix = $RepositoryRoot.TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar) +
                    [IO.Path]::DirectorySeparatorChar
                $relative = $file.FullName.Substring($rootPrefix.Length)
                $snapshot[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            }
        }
    }
    return ,$snapshot
}

function Assert-SnapshotEqual {
    param(
        [Parameter(Mandatory)][hashtable]$Expected,
        [Parameter(Mandatory)][hashtable]$Actual
    )

    if ($Expected.Count -ne $Actual.Count) {
        throw "Repository build state changed: expected $($Expected.Count) files, found $($Actual.Count)."
    }
    foreach ($key in $Expected.Keys) {
        if (-not $Actual.ContainsKey($key) -or $Actual[$key] -ne $Expected[$key]) {
            throw "Repository build state changed at '$key'."
        }
    }
}

function Get-NormalizedPath {
    param([Parameter(Mandatory)][string]$Path)
    return [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
}

function Assert-AssetsPackageFolder {
    param(
        [Parameter(Mandatory)][string]$AssetsPath,
        [Parameter(Mandatory)][string]$ExpectedPackages
    )

    $assets = Get-Content -LiteralPath $AssetsPath -Raw | ConvertFrom-Json
    $folders = @($assets.packageFolders.PSObject.Properties.Name)
    if ($folders.Count -ne 1 -or
        (Get-NormalizedPath $folders[0]) -ne (Get-NormalizedPath $ExpectedPackages)) {
        throw "Unexpected packageFolders in '$AssetsPath': $($folders -join ', ')."
    }
}

function Assert-AssetsPackageFoldersUnderRoot {
    param(
        [Parameter(Mandatory)][string]$AssetsPath,
        [Parameter(Mandatory)][string]$ExpectedPackages,
        [Parameter(Mandatory)][string]$WorkRoot
    )

    $assets = Get-Content -LiteralPath $AssetsPath -Raw | ConvertFrom-Json
    $folders = @($assets.packageFolders.PSObject.Properties.Name)
    $expected = Get-NormalizedPath $ExpectedPackages
    $prefix = (Get-NormalizedPath $WorkRoot) + [IO.Path]::DirectorySeparatorChar
    if ($folders.Count -eq 0 -or
        -not ($folders | Where-Object { (Get-NormalizedPath $_) -eq $expected })) {
        throw "The isolated packages folder is absent from '$AssetsPath'."
    }
    foreach ($folder in $folders) {
        if (-not (Get-NormalizedPath $folder).StartsWith(
            $prefix,
            [StringComparison]::OrdinalIgnoreCase)) {
            throw "packageFolders escaped the work root in '$AssetsPath': '$folder'."
        }
    }
}

function Assert-MetadataSources {
    param(
        [Parameter(Mandatory)][string]$PackagesRoot,
        [Parameter(Mandatory)][string]$ExpectedSource,
        [Parameter(Mandatory)][int]$ExpectedCount
    )

    $metadataFiles = @(Get-ChildItem -LiteralPath $PackagesRoot -Recurse -File -Filter '.nupkg.metadata')
    if ($metadataFiles.Count -ne $ExpectedCount) {
        throw "Expected $ExpectedCount package metadata files, found $($metadataFiles.Count)."
    }
    foreach ($metadataFile in $metadataFiles) {
        $metadata = Get-Content -LiteralPath $metadataFile.FullName -Raw | ConvertFrom-Json
        if ((Get-NormalizedPath $metadata.source) -ne (Get-NormalizedPath $ExpectedSource)) {
            throw "Package '$($metadataFile.FullName)' came from '$($metadata.source)', not the vendor source."
        }
    }
}

function Assert-NoHttpCacheFiles {
    param([Parameter(Mandatory)][string]$HttpCache)
    if (@(Get-ChildItem -LiteralPath $HttpCache -Recurse -File).Count -ne 0) {
        throw 'The HTTP cache is not empty.'
    }
}

function Assert-DownloadDependencies {
    param(
        [Parameter(Mandatory)][string]$AssetsPath,
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$RuntimePackVersion
    )

    $assets = Get-Content -LiteralPath $AssetsPath -Raw | ConvertFrom-Json
    $dependencies = @($assets.project.frameworks.'net10.0'.downloadDependencies)
    $actual = @($dependencies | ForEach-Object { "$($_.name)/$($_.version)" } | Sort-Object)

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $expected = @(
        $manifest.packages |
            Where-Object role -eq 'win-arm64-sdk-runtime-pack' |
            ForEach-Object {
                if ($_.version -ne $RuntimePackVersion) {
                    throw "Runtime pack '$($_.id)' is not pinned to $RuntimePackVersion."
                }
                "$($_.id)/[$($_.version), $($_.version)]"
            } |
            Sort-Object
    )
    if (($actual -join "`n") -ne ($expected -join "`n")) {
        throw "downloadDependencies do not match the manifest.`nExpected:`n$($expected -join "`n")`nActual:`n$($actual -join "`n")"
    }
}

function Assert-ArtifactsUnderRoot {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$WorkRoot
    )

    $prefix = (Get-NormalizedPath $WorkRoot) + [IO.Path]::DirectorySeparatorChar
    foreach ($directory in Get-ChildItem -LiteralPath $SourceRoot -Directory -Recurse |
        Where-Object Name -in @('bin', 'obj')) {
        if (-not $directory.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Build artifact escaped the work root: '$($directory.FullName)'."
        }
    }
}

function Assert-RepositoryAssetsUsable {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string[]]$ProjectRoots
    )

    foreach ($projectRoot in $ProjectRoots) {
        $assetsPath = Join-Path (Join-Path $RepositoryRoot $projectRoot) 'obj\project.assets.json'
        if (-not (Test-Path -LiteralPath $assetsPath)) {
            continue
        }
        $assets = Get-Content -LiteralPath $assetsPath -Raw | ConvertFrom-Json
        foreach ($folder in $assets.packageFolders.PSObject.Properties.Name) {
            if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                throw "Repository assets reference a deleted package folder: '$folder'."
            }
        }
    }
}

function Remove-OwnedWorkRoot {
    param(
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][string]$ArtifactsRoot
    )

    $requiredPrefix = (Get-NormalizedPath $ArtifactsRoot) + [IO.Path]::DirectorySeparatorChar
    if (-not (Get-NormalizedPath $WorkRoot).StartsWith(
        $requiredPrefix,
        [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove a work root outside the owned verification directory.'
    }
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force
}
