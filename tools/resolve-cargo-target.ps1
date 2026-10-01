$ErrorActionPreference = 'Stop'

foreach ($scope in @('Process', 'User', 'Machine')) {
    $value = [Environment]::GetEnvironmentVariable('CARGO_TARGET_DIR', $scope)
    if ([string]::IsNullOrWhiteSpace($value)) { continue }
    $expanded = [Environment]::ExpandEnvironmentVariables($value.Trim())
    if ($expanded -notmatch '^[dD]:[\\/]') { continue }
    $target = [IO.Path]::GetFullPath($expanded)
    if ([IO.Path]::GetPathRoot($target) -ieq 'D:\') {
        Write-Output $target
        exit 0
    }
}

throw 'CARGO_TARGET_DIR must resolve to an absolute directory on D: (process, user, or machine environment).'
