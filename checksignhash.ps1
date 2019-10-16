$filez = Get-ChildItem "E:\Files" 
ForEach($file in $filez)
{
    $compname = $file.VersionInfo.CompanyName
    $signed = (Get-AuthenticodeSignature "C:\Files\$file").Status
    $hash = (Get-FileHash "C:\Files\$file" -Algorithm SHA256).Hash
    Write-Output("$compname :: $signed :: $file :: $hash")
}
