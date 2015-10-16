::  BlueCoat SR bulk URL tool codename: Tucan ###
::  Author: Omar Dominguez ###
::  To run the script you need: MSYS, curl ###
:: Input: Proxy settings ###
::  Output file: Query from SiteReview ###
set user=%1
set password=%2
set url=%3
set salida=%4
curl -X POST http://sitereview.bluecoat.com/rest/categorization -d "url=%url%" -x https://PROXY:port -U %user%:%password% | gawk -F 'catnum' '{print $2 $3}' | gawk -F',' '{print $1}'| sed -e "s/<[^>]\+>/ /g" | gawk -F">" '{print $2}' |  sed -e "s/.$//" >> %salida%
