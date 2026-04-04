Task summary: Removed the retired `eden` PowerShell host and consolidated Eden routing to `eden-wsl`.

Files changed:
- `hosts.yaml`: deleted the `eden` host block and left `eden-wsl` unchanged.
- `hosts.example.yaml`: replaced the PowerShell example with a WSL2 example and removed `shell: powershell` from the example file.
- `tests/test_primitives.py`: updated the test host references from `eden` to `eden-wsl`.

Decisions or surprises: No surprises; the only extra adjustment was updating the example file comment so it no longer advertises PowerShell in the sample fleet config.
