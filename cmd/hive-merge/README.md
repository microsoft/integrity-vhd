# hive-merge

Exercises the registry hive merge that CIM layer generation relies on.

## Usage

```powershell
cd cmd\hive-merge

$work = $env:TEMP

# Build
$env:GOOS="windows"; go build .

# Generate a small sample base + delta hive pair (named after the
# SYSTEM_BASE/SYSTEM_DELTA intermediate files hcsshim writes per hive during CIM
# generation). Use a real layer's hive pair instead to test a specific layer.
.\hive-merge.exe --generate-sample-input $work\SYSTEM_BASE $work\SYSTEM_DELTA

# Merge the same base + delta hive twice into separate outputs...
.\hive-merge.exe $work\SYSTEM_BASE $work\SYSTEM_DELTA $work\SYSTEM_merged1
.\hive-merge.exe $work\SYSTEM_BASE $work\SYSTEM_DELTA $work\SYSTEM_merged2

# ...then compare. Identical hashes => the deterministic hive merge fix is present; differing => not.
Get-FileHash $work\SYSTEM_merged1, $work\SYSTEM_merged2
```
