### BlueCoat SR bulk URL tool codename: Panda ###
### Author: Omar Dominguez ###
### To run the script you need: Tucan.bat and MSYS ###
### Input: File with URL, newline format  ###
### Output file: File.res with the results ###

echo          "::::::::::::::::::::::    Panda    :::::::::::::::::::::::::::"
echo          "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo          "::::::::: Tool for bulking URL in BlueCoat :::::::::::::::::::"
echo          "::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::"
echo ""
$proxyUser= Read-Host "Enter the user for proxy: "
$proxyPass= Read-Host -assecurestring "Enter the password for proxy: "
$proxyPass= [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($proxyPass))
$fileBulk= Read-Host "Enter the FileName with the URLs"
echo "###############################################################"
echo "Reading the file, lookup protocols..."
Get-Content $fileBulk | Measure-Object –Line
echo "Contacting VT and bulking results with tucan engine [wait]..."
$resBulk = $fileBulk + ".res"
cat $fileBulk | ForEach-Object { echo "[>>] Querying info for $_ " ; cmd.exe /q /c "tucan.bat $proxyUser $proxyPass $_ $resBulk"; sleep 17 }
echo "All modules exited sucessfully, results in: "
echo $resBulk
echo "Panda goes to sleep [ZzzzZzzzZzzz]"
Read-Host "Press enter to continue..."
