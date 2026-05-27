# Run this in an ELEVATED PowerShell (Run as Administrator)
# Adds the YourDevice SSH key to the administrators_authorized_keys file

$keyFile = "C:\ProgramData\ssh\administrators_authorized_keys"
$laptopKey = "ssh-ed25519 YOUR_PUBLIC_KEY_HERE YourDevice"

# Read existing content (if any)
$existing = ""
if (Test-Path $keyFile) {
    $existing = Get-Content $keyFile -Raw
    Write-Host "Current contents of administrators_authorized_keys:" -ForegroundColor Cyan
    Write-Host $existing
}

# Check if key already present
if ($existing -and $existing.Contains("YourDevice")) {
    Write-Host "`nLaptop key already present!" -ForegroundColor Green
} else {
    # Append the key
    Add-Content -Path $keyFile -Value $laptopKey -Encoding UTF8
    Write-Host "`nLaptop key ADDED." -ForegroundColor Green
}

# Fix permissions: only SYSTEM and Administrators should have access
$acl = Get-Acl $keyFile
$acl.SetAccessRuleProtection($true, $false)  # disable inheritance
$acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
$systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$acl.AddAccessRule($adminRule)
$acl.AddAccessRule($systemRule)
Set-Acl -Path $keyFile -AclObject $acl
Write-Host "Permissions set (SYSTEM + Administrators only)." -ForegroundColor Green

# Restart sshd to pick up changes
Restart-Service sshd
Write-Host "sshd restarted." -ForegroundColor Green

# Verify
Write-Host "`nFinal contents:" -ForegroundColor Cyan
Get-Content $keyFile
Write-Host "`nsshd status:" -ForegroundColor Cyan
Get-Service sshd | Select-Object Name, Status
