### Virus Total API bulk hashes tool codename: Canguro ###
### Author: Omar Dominguez ###
### To run the script you need:  Python2.7 installed and cacatua.py script  ###
### Input file: hash (MD5, SHA1, SHA256, SHA512)  ###
### Output file: JSON VT result ###
echo          "::::::::::::::::::::::    Canguro    :::::::::::::::::::::::::"
echo          "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo          ":::::::::::::: Tool for bulking hashes in VT ::::::::::::::::::::"
echo          "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo ""
$proxyUser= Read-Host "Enter the user for proxy: "
$proxyPass= Read-Host -assecurestring "Enter the password for proxy: "
$proxyPass= [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($proxyPass))
$fileBulk= Read-Host "Enter the FileName with the HASHES"
echo "###############################################################"
echo "Reading the file, lookup MD5..."
Get-Content $fileBulk | Measure-Object –Line
echo "Contacting VT and bulking results with cacatua engine [wait]..."
$resBulk = $fileBulk + ".res"
cat $fileBulk | ForEach-Object { echo "[>>] Querying info for $_ " ; C:\Python27\python.exe .\cacatua.py --user-proxy $proxyUser --password-proxy $proxyPass --md5 $_ >>  $resBulk; sleep 17 }
echo "All modules exited sucessfully, results in: "
echo $resBulk
echo "Canguro goes to sleep [ZzzzZzzzZzzz]"
Read-Host "Press enter to continue..."
