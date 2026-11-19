$want = 'SecP384r1_MLKEM1024','X25519_MLKEM768','curve25519','MLKEM1024',
        'NistP384','NistP256','NistP521'

foreach ($g in @(Get-TlsEccCurve | ForEach-Object { $_ })) { Disable-TlsEccCurve -Name $g }
foreach ($g in $want) { Enable-TlsEccCurve -Name $g }

"Now:"; Get-TlsEccCurve
