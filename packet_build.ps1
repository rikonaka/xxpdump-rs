$binaryName = "xxpdump"
$outputDir = "./target"
$buildDir = "./target"
$windowsTargets = @("x86_64-pc-windows-msvc", "i686-pc-windows-msvc", 
                   "x86_64-pc-windows-gnu", "i686-pc-windows-gnu")

if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$compiledTargets = @()
foreach ($target in $windowsTargets) {
    $releasePath = Join-Path -Path $buildDir -ChildPath "$target/release/$binaryName.exe"
    $debugPath = Join-Path -Path $buildDir -ChildPath "$target/debug/$binaryName.exe"
    
    if (Test-Path -Path $releasePath -PathType Leaf -or Test-Path -Path $debugPath -PathType Leaf) {
        $compiledTargets += $target
    }
}

if (-not $compiledTargets) {
    Write-Error "No compiled Windows target architectures found"
    exit 1
}

Write-Host "Found the following Windows target architectures: $($compiledTargets -join ', ')"
Write-Host "Starting packaging process..."

foreach ($target in $compiledTargets) {
    $binaryPath = Join-Path -Path $buildDir -ChildPath "$target/release/$binaryName.exe"
    $buildType = "release"
    
    if (-not (Test-Path -Path $binaryPath -PathType Leaf)) {
        Write-Host "Release version for $target not found, trying debug version..."
        $binaryPath = Join-Path -Path $buildDir -ChildPath "$target/debug/$binaryName.exe"
        $buildType = "debug"
    }
    
    if (-not (Test-Path -Path $binaryPath -PathType Leaf)) {
        Write-Warning "Executable not found in $target, skipping this target architecture"
        continue
    }
    
    $tempDir = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_.FullName }
    
    Copy-Item -Path $binaryPath -Destination $tempDir.FullName
    
    $pdbPath = Join-Path -Path $buildDir -ChildPath "$target/$buildType/$binaryName.pdb"
    if (Test-Path -Path $pdbPath -PathType Leaf) {
        Copy-Item -Path $pdbPath -Destination $tempDir.FullName
        Write-Host "Included debug symbol file: $binaryName.pdb"
    }
    
    # foreach ($file in Get-ChildItem -Path . -Filter "README*", "LICENSE*", "*.md" -File) {
    #     Copy-Item -Path $file.FullName -Destination $tempDir.FullName
    # }
    
    $archiveName = Join-Path -Path $outputDir -ChildPath "$binaryName-$target.zip"
    Compress-Archive -Path (Join-Path -Path $tempDir.FullName -ChildPath *) -DestinationPath $archiveName -Force
    
    Remove-Item -Path $tempDir.FullName -Recurse -Force
    
    Write-Host "Created archive: $archiveName"
}

Write-Host "Packaging completed. All Windows target files saved to: $outputDir"
