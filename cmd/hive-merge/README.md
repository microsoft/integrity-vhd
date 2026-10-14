# hive-merge

Exercises the registry hive merge that CIM layer generation relies on.

## Usage

```powershell
cd cmd\hive-merge

$work = $env:TEMP

# Build
$env:GOOS="windows"; go build .

# Generate a small sample base + delta hive pair.
.\hive-merge.exe --generate-sample-input $work\SAMPLE_BASE $work\SAMPLE_DELTA

# Merge the same base + delta hive twice into separate outputs...
.\hive-merge.exe $work\SAMPLE_BASE $work\SAMPLE_DELTA $work\SAMPLE_merged1
.\hive-merge.exe $work\SAMPLE_BASE $work\SAMPLE_DELTA $work\SAMPLE_merged2

# ...then compare. Identical hashes => the deterministic hive merge fix is present; differing => not.
Get-FileHash $work\SAMPLE_merged1, $work\SAMPLE_merged2
```
