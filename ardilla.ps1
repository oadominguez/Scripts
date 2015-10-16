### POWERSHELL SCRIPT CODENAME: Ardilla ###
### Author: Omar Dominguez ###
### To run the script you need:  Python2.7 installed and huron.py script ###
### Input file: URL txt file with newline separators ###
### Output file: .res file with results ###
echo          "::::::::::::::::::::    Ardilla   ::::::::::::::::::::::::::::"
echo          "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo          "::::::::::::::: Tool for bulking URL in VT ::::::::::::::::::"
echo          "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo ""
$proxyUser= Read-Host "Enter the user for proxy: "
$proxyPass= Read-Host -assecurestring "Enter the password for proxy: "
$proxyPass= [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($proxyPass))
$fileBulk= Read-Host "Enter the FileName with the URLS"
echo "###############################################################"
echo "Reading the file, lookup URL..."
Get-Content $fileBulk | Measure-Object –Line
echo "Contacting VT and bulking results with huron engine [wait]..."
$resBulk = $fileBulk + ".res"
cat $fileBulk | ForEach-Object { C:\Python27\python.exe .\huron.py --search --user-proxy $proxyUser --password-proxy $proxyPass --url $_; sleep 17 ; echo "[>>] Querying info for $_ " }
cat $fileBulk | ForEach-Object { C:\Python27\python.exe .\huron.py --report --user-proxy $proxyUser --password-proxy $proxyPass --url $_ >> $resBulk ; sleep 17 ; echo "[>>] Getting report for $_" }
echo "All modules exited sucessfully, results in: "
echo $resBul
echo "Ardilla goes to sleep [ZzzzZzzzZzzz]"
Read-Host "Press enter to continue..."
