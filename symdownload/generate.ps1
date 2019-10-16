Function PDBGen {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $filePath
    )

    if(!(Test-Path $filePath)) {
        Write-Output "$filePath not found"
        return $false
    }

    
    $fName = Split-Path $filePath -Leaf
    $fNameNoExt = (Get-Item $filePath).BaseName
    
    $sPath = "SRV*$workDir\pdb\*https://msdl.microsoft.com/download/symbols"
    Try
    {
        $sPathEnv = Get-Childitem env:_NT_SYMBOL_PATH
        $sPath = $sPathEnv.value
    }
    Catch
    {
    }


    $workDir = $PSScriptRoot
    $output = "`"$workDir\work\$fName`""
    Write-Output "[+] Download des symbols de $fName"
    Start-Process -FilePath "$workDir\bin\symchk.exe" -ArgumentList "/if",$filePath,"/s",$sPath,"/op","/ocx",$output -Wait -NoNewWindow

    if(!(Test-Path "$workDir\work\$fName\$fNameNoExt.pdb")) {
        Write-Output "{!} Erreur de telechargement du symbole"
        return $false
    }
    
    $output = "`"$workDir\work\$fName\$fNameNoExt.pdb`""
     if(!(Test-Path "$workDir\work\$fName\$fNameNoExt.pdb")) {
        $output = ""
        Write-Output "{!} Mismatch sur le PDB de $fname"
        $filesList = Get-ChildItem -Path "$workDir\work\$fName\"
        foreach($file in $filesList) {
            if($file.Extension -eq ".pdb") {
                $realName = $file.Name
                $output = "`"$workDir\work\$fName\$realName.pdb`""
            }
        }
        if($output -eq "") {
            Write-Output "{!} Erreur sur le PDB"
            return $false
        }
     }
    Write-Output "[+] Parsing des symbols de $fName"
    Start-Process -FilePath "$workDir\bin\symexp.exe" -ArgumentList $output -RedirectStandardOutput "$workDir\work\$fName\$fNameNoExt.h"  -Wait -NoNewWindow

    Write-Output "[+] Generation du HTML"
    $data = ""
    $structsList = @()
    $started = $false
    foreach($line in Get-Content "$workDir\work\$fName\$fNameNoExt.h") {
        
        if($line.StartsWith("typedef ")) {
            if(!$started){
                $started = $true
            }
            else {
                $structsList += $data
            }
            $data = $line

        }
        else{
            if($started){
                $data = "$data`n$line"
            }
        }
    }

    if($structsList.Count -eq 0) {
        return $false;
    }
    
    $outFile = "$workDir\work\$fName\index.html"
    '<!DOCTYPE html>
    <html lang="en">
    <head>
    <script src="../../web/bootstrap.min.js"></script>
    <script src="../../web/jquery.min.js"></script>
    <link rel="stylesheet" href="../../web/bootstrap.min.css">
    </head>
    <body>
    <div class="navbar navbar-expand-sm bg-dark">
    <div class="col-sm-2 text-light">Structures/Enums:</div>
    <div class="col-sm-2 text-light">
        <select id="selStruct">
        <option value="">-</option>' | Out-File -FilePath $outFile

    $divs = ''
    $namesList = @()
    foreach ($structData in $structsList) {
        $line1 = $structData.Split("`n")[0]
        $structName = $line1.split(" ")[2]
        $namesList += $structName

        "<option value='$structName'>$structName</option>" | Out-File -FilePath $outFile -Append
        $divs += "<div id='$structName' class='card collapse'><div class='card-header'>$structName</div><div class='card-body'><pre>$structData</pre></div></div>"
    }
    "</select>
    </div>
    </div>
    <br />
    $divs
    <script>
        var current = `"`";
       `$('#selStruct').change(function(){
        ov = `$(this).val();
        `$('#'+ov).collapse();
        if(current != `"`") {
        `$('#'+current).collapse(`"hide`");
        }
        current = ov;
        });
    </script>
    </body>
    </html>" | Out-File -FilePath $outFile -Append

     return $true

}



$htmlFile = "$PSScriptRoot\view.html"

$filesList = Get-ChildItem -Path "C:\Windows\System32\drivers"
foreach($file in $filesList) {
    if($file.PSIsContainer -eq $false) {
        $fName = $file.Name
        if ((PDBGen -filePath $file.FullName) -eq $true) {
            $fNameNoExt = $file.BaseName
            Write-Output $fName
            "<option value=`"$fName`">$fNameNoExt</option>" | Out-File -FilePath $htmlFile -Append
        }
        else {
            if(Test-Path "$PSScriptRoot\work\$fName") {
                Remove-Item -Path "$PSScriptRoot\work\$fName" -Recurse -Force
            }
        }
    }
}

'</select>
</div>
</div>
<div class="w-80 h-80 mx-auto">
<iframe src="" id="y" class="border w-100 h-100"></iframe>
</div>
</body>
</html>' | Out-File -FilePath $htmlFile -Append

