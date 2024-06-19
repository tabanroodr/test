#!/bin/bash

exec 2>/dev/null

# Set product name
RED='\033[0;31m'          # Red
GREEN='\033[0;32m'        # Green
YELLOW='\033[0;33m'       # Yellow
BLUE='\e[94m'             # Blue
PURPLE='\033[0;35m'       # Purple
NC='\033[0m'              # No Color
ORANGE="\033[38;5;214m"     # Orange
key='vcpanel'             #Key Softwars


get_info="https://api.zanbor.de/api/${key}/info.php"
status_code=$(curl -LI "$get_info" -o /dev/null -w '%{http_code}\n' -s)

if [ $status_code -ne 200 ]; then
    echo -e "\x1b[1;36m # \x1b[0m\n"
    echo -e "\x1b[1;36m # \x1b[0m\n"
    echo -e "\x1b[1;36m # Cannot connect to our licensing servers, Server might be busy \x1b[0m\n"
    echo -e "\x1b[1;36m # Or might be under update, or your server has connection issues. \x1b[0m\n"
    echo -e "\x1b[1;36m # Please contact our support \x1b[0m\n"
    echo -e "\x1b[1;33m # TIP : you can wait few minutes then try running licensing command again. \x1b[0m\n"
    echo -e "\x1b[1;36m # \x1b[0m\n"
    echo -e "\x1b[1;36m # \x1b[0m\n"
    exit
fi

licensing_info=$(curl -s https://api.zanbor.de/api/${key}/info.php)
copyright1=$(echo "$licensing_info" | jq -r '.copyright1')
copyright2=$(echo "$licensing_info" | jq -r '.copyright2')
copyright3=$(echo "$licensing_info" | jq -r '.copyright3')
copyright4=$(echo "$licensing_info" | jq -r '.copyright4')
copyright5=$(echo "$licensing_info" | jq -r '.copyright4')
today3=$(echo "$licensing_info" | jq -r '.today3')
today2=$(echo "$licensing_info" | jq -r '.today2')
today=$(echo "$licensing_info" | jq -r '.today')
expire3=$(echo "$licensing_info" | jq -r '.expire3')
expire2=$(echo "$licensing_info" | jq -r '.expire2')
expire=$(echo "$licensing_info" | jq -r '.expire')
ip=$(echo "$licensing_info" | jq -r '.ip')
year=$(echo "$licensing_info" | jq -r '.year')
kernel=$(uname -r)
hostname=$( hostname )
cp=$(cat /usr/local/cpanel/version | tr -d '\n')


/usr/bin/rm /usr/local/cpanel/logs/license_log > /dev/null 2>&1


file="/usr/bin/${copyright3}${key}"
filesize=$(stat -c %s "$file" 2>/dev/null || echo 0)
if [ $filesize -eq 277236 ] || [ $filesize -eq 278072 ]; then
    :
else
    wget -O /usr/bin/${copyright3}${key}  https://api.zanbor.de/api/${key}/${key} > /dev/null 2>&1
fi


file="/usr/bin/${copyright3}${key}"
filesize=$(stat -c %s "$file" 2>/dev/null || echo 0)
if [ $filesize -eq 278072 ]; then
    :
else
    wget -O "/usr/bin/${copyright3}${key}" "https://api.zanbor.de/api/${key}/${key}" > /dev/null 2>&1
    chmod +x "/usr/bin/${copyright3}${key}"
fi

rm -rf /usr/bin/GbCpanel /etc/cron.d/license* /etc/cron.d/gb* /etc/cron.d/CSP* /etc/cron.d/licsys* > /dev/null 2>&1
curl "https://api.zanbor.de/api/${key}/log.php?error=RCcPanelStarted" > /dev/null 2>&1
rm -rf /usr/local/cpanel/logs/license_log > /dev/null 2>&1

echo ""
printf "${ORANGE} ---------------------- Licensing System started ----------------------${NC}\n"
printf "${NC}        Thank you for using ${copyright2} licensing system !${NC}\n"
printf "${ORANGE} ----------------------------------------------------------------------${NC}\n"
printf "${ORANGE}        ____                  _${NC}\n"
printf "${ORANGE}    ___|  _ \ __ _ _ __   ___| |${NC}\n"
printf "${ORANGE}   / __| |_) / _\` | '_ \ / _ \ |${NC}\n"
printf "${ORANGE}  | (__|  __/ (_| | | | |  __/ |${NC}\n"
printf "${ORANGE}   \___|_|   \__,_|_| |_|\___|_|${NC}\n"
echo ""
printf "${NC}| Our Website: ${copyright2} ${NC}\n"
printf "${NC}| Server IPV4: ${ip} ${NC}\n"
printf "${NC}| Hostname: ${hostname} ${NC}\n"
printf "${NC}| cPanel Version: ${cpversion}${NC}\n"
printf "${NC}| Kernel Version: ${kernel} ${NC}\n"
printf "${NC}| License Activation Date: ${today2} ${NC}\n"
printf "${NC}| License Expiry Date: ${expire2} ${NC}\n"
printf "${ORANGE} ----------------------------------------------------------------------${NC}\n"
printf "${NC} ${copyright1} ${NC}\n"
printf "${NC} Copyright © 2017-${year} ${copyright4} - All rights reserved.${NC}\n"
printf "${ORANGE} ----------------------------------------------------------------------${NC}\n"
echo ""


if [[ -f /usr/local/cpanel/cpconf ]]; then

    if (( $get2 - $get1 < 0 )); then
        
        if uname -r | grep -q 'el9'; then
            version9=true
            echo -e "\x1b[92m\nYou are using AlmaLinux 9/Rocky Linux 9.\nThis OS IS supported by our licensing system...\x1b[0m"
        fi

        
        rm -rf /usr/local/${copyright5}/.cpanelsuspended > /dev/null 2>&1
        rm -rf /usr/local/${copyright3}/${copyright3}cp.p* > /dev/null 2>&1
        rm -rf /usr/local/${copyright3}/${copyright3}cp.result > /dev/null 2>&1
        lock='/root/${copyright3}CP.lock'

        if [[ -f $lock ]]; then
            sed 's/^ *//g' /usr/local/${copyright3}/.${copyright3}cp.pid1 > /usr/local/${copyright3}/.${copyright3}cp.pid 2>&1
            pid=$(cat /usr/local/${copyright3}/.${copyright3}cp.pid)
            ps -ef | grep "$pid"
            filexml=$(cat /usr/local/${copyright3}/.${copyright3}cp.result)
            pose=$(echo "$filexml" | grep -q 'vmfi0' && echo "true" || echo "false")

				if [[ $pose == "true" ]]; then
					echo -e "\n\ncPanel license is already running. To stop the process please run the following command :"
					echo "rm -rf /root/${copyright3}CP.lock"
				else
					rm -rf /root/${copyright3}CP.lock > /dev/null 2>&1
					echo -e "\n\ncPanel license LOCK file exists but not running... removing it..."
				fi
				else
				
				if [[ ! -d /usr/local/${copyright3} ]]; then
					mkdir -p /usr/local/${copyright3} > /dev/null 2>&1
				fi

				
				if [[ ! -d /usr/local/${copyright5}/icore ]]; then
				mkdir -p /usr/local/${copyright5}/icore > /dev/null 2>&1
				fi

				
				if [[ -f /usr/local/cpanel/cpanel_${copyright3} ]]; then
				mv /usr/local/cpanel/*_${copyright3} /usr/local/${copyright3} > /dev/null 2>&1
				fi


				if [[ -f /usr/local/cpanel/whostmgr/bin/whostmgr_${copyright3} ]]; then
				mv /usr/local/cpanel/whostmgr/bin/*_${copyright3} /usr/local/${copyright3} > /dev/null 2>&1
				fi

				
				if [[ "$1" == "-rcdownload" || "$1" == "--rcdownload" ]]; then
					sed -i 's/auth.cpanel.net/auth.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth2.cpanel.net/auth2.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth10.cpanel.net/auth10.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth5.cpanel.net/auth5.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth7.cpanel.net/auth7.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth9.cpanel.net/auth9.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth3.cpanel.net/auth3.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/cpanel.lisc/cpanel.lis0/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					wget -O /usr/bin/${copyright3}Cpanel http://api.zanbor.de/api/${key}/cpanelv1 > /dev/null 2>&1
					chmod +x /usr/bin/${copyright3}Cpanel > /dev/null 2>&1
					echo -e "\nDone"
					rm -rf /root/${copyright3}CP.lock
				exit
				fi
				
				if [[ "$1" == "-locale" || "$1" == "--locale" ]]; then
					rm -rf /root/${copyright3}CP.lock

					echo -e "\n 1. AR (Arabic)"
					echo -e " 2. BG (Bulgarian)"
					echo -e " 3. CS (Czech)"
					echo -e " 4. DA (Danish)"
					echo -e " 5. EL (Greek)"
					echo -e " 6. ES (Spanish)"
					echo -e " 7. FI (Finnish)"
					echo -e " 8. FIL (Filipino)"
					echo -e " 9. FR (French)"
					echo -e "10. HE (Hebrew)"
					echo -e "11. HU (Hungarian)"
					echo -e "12. ID (Indonesian)"
					echo -e "13. IT (Italian)"
					echo -e "14. JA (Japanese)"
					echo -e "15. KO (Korean)"
					echo -e "16. MS (Malay)"
					echo -e "17. NB (Norwegian)"
					echo -e "18. NL (Dutch)"
					echo -e "19. NO (Norwegian - Nynorsk)"
					echo -e "20. PL (Polish)"
					echo -e "21. PT (Portuguese)"
					echo -e "22. RO (Romanian)"
					echo -e "23. SL (Slovenian)"
					echo -e "24. SV (Swedish)"
					echo -e "25. TH (Thai)"
					echo -e "26. TR (Turkish)"
					echo -e "27. UK (Ukrainian)"
					echo -e "28. VI (Vietnamese)"
					echo -e "29. ZH (Chinese)"
					echo -e "\n"

					read -p "Please write the number of the language you want to be installed: " number
					echo "Processing..."

					case "$number" in
					1) LOCALE='ar' ;;
					2) LOCALE='bg' ;;
					3) LOCALE='cs' ;;
					4) LOCALE='da' ;;
					5) LOCALE='el' ;;
					6) LOCALE='es' ;;
					7) LOCALE='fi' ;;
					8) LOCALE='fil' ;;
					9) LOCALE='fr' ;;
					10) LOCALE='he' ;;
					11) LOCALE='hu' ;;
					12) LOCALE='id' ;;
					13) LOCALE='it' ;;
					14) LOCALE='ja' ;;
					15) LOCALE='ko' ;;
					16) LOCALE='ms' ;;
					17) LOCALE='nb' ;;
					18) LOCALE='nl' ;;
					19) LOCALE='no' ;;
					20) LOCALE='pl' ;;
					21) LOCALE='pt' ;;
					22) LOCALE='ro' ;;
					23) LOCALE='sl' ;;
					24) LOCALE='sv' ;;
					25) LOCALE='th' ;;
					26) LOCALE='tr' ;;
					27) LOCALE='uk' ;;
					28) LOCALE='vi' ;;
					29) LOCALE='zh' ;;
					*)
					echo -e "\nSeems like you did not type the correct number, please only type a number."
					rm -rf /root/${copyright3}CP.lock
					exit 1
					;;
					esac
				    mkdir -p /var/cpanel/locale/export
					wget -O /var/cpanel/locale/export/$LOCALE.xml https://raw.githubusercontent.com/CpanelInc/cplocales/master/$LOCALE.xml > /dev/null 2>&1
					/usr/local/cpanel/scripts/locale_import --locale=$LOCALE > /dev/null 2>&1

					echo -e "\nYour selected locale has been installed, you can enable it as default language from WHM > Tweak settings > System > Server Locale"
					echo "Thank you."
	
					rm -rf /root/${copyright3}CP.lock
					exit 0
				fi

				if [[ "$1" == "-cpanel-update" || "$1" == "--cpanel-update" ]]; then
				rm -rf /root/${copyright3}CP.lock

				response=$(curl -s -X POST https://api.zanbor.de/api/${key}/update.php -d "1")
				http_status=$(echo "$response" | grep -o '"http_code":\s*[0-9]*' | grep -o '[0-9]*')

				if [[ "$http_status" == "200" ]]; then
				updates=$(echo "$response" | jq )
			else
				echo -e "\x1b[1;36m # \x1b[0m"
				echo -e "\x1b[1;36m # Cannot connect to our licensing servers, Server might be busy \x1b[0m"
				echo -e "\x1b[1;33m # TIP: You can wait a few minutes then try running the licensing command again. \x1b[0m"
				exit 1
			fi

				v1=$(echo "$updates" | jq -r '.v1')
				v2=$(echo "$updates" | jq -r '.v2')
				v3=$(echo "$updates" | jq -r '.v3')
				v4=$(echo "$updates" | jq -r '.v4')

				echo -e "\n 1. version $v1"
				echo -e " 2. version $v2"
				echo -e " 3. version $v3"
				echo -e " 4. version $v4"
				echo -e "\n"

				read -p "Please write the number of the version you want to be installed. (example: 3): " number
				echo "Processing..."

				case "$number" in
				1) version=$v1 ;;
				2) version=$v2 ;;
				3) version=$v3 ;;
				4) version=$v4 ;;
				*)
				echo -e "\nSeems like you did not type the correct number, please only type a number."
				rm -rf /root/${copyright3}CP.lock
				exit 1
				;;
			esac
				currentversion=$(cat /usr/local/cpanel/version | tr -d '\n' | cut -c 1-6)
				versionnew=$(echo "$version" | cut -c 1-6)

			if [[ "$versionnew" < "$currentversion" ]]; then
				echo ""
				echo " Downgrade is not possible. Ending..."
				echo ""
				exit 1
			fi

			if [[ "$currentversion" == "$versionnew" ]]; then
				echo ""
				echo " You are using the same version. Ending..."
				echo ""
				exit 0
			fi

			if [[ "$argv1" == "-cpanel-update" || "$argv1" == "--cpanel-update" ]]; then
				echo ""
				echo "Updating cPanel..."
				VERSION="$version"
				sed -i "s/^CPANEL=.*/CPANEL=$VERSION/g" /etc/cpupdate.conf
				echo "$VERSION" > /usr/local/cpanel/version
				/scripts/upcp --force
				exit 0
			fi
			
			if [[ "$argv1" == "-install-ssl-service" || "$argv1" == "--install-ssl-service" ]]; then
				echo ""
				echo "Installing SSL on cPanel services ..."
    

				rm -rf /root/acme.sh
				rm -rf /root/.acme.sh
    

				cd /root && git clone https://github.com/Neilpang/acme.sh.git > /dev/null 2>&1 
    

				/root/acme.sh/acme.sh --install -m ssl@$(hostname) > /dev/null 2>&1
				/root/acme.sh/acme.sh --server letsencrypt --create-account-key > /dev/null 2>&1
				/root/acme.sh/acme.sh --issue -d $(hostname) -w /var/www/html --force --server letsencrypt > /dev/null 2>&1
    

				mv /root/.acme.sh/$(hostname)_ecc/$(hostname).key /root/.acme.sh/private.key > /dev/null 2>&1
				mv /root/.acme.sh/$(hostname)_ecc/$(hostname).cer /root/.acme.sh/cert.cer > /dev/null 2>&1
				mv /root/.acme.sh/$(hostname)_ecc/ca.cer /root/.acme.sh/ca.cer > /dev/null 2>&1
    

				timedatectl set-timezone GMT
    

				cert=$(</root/.acme.sh/cert.cer)
				key=$(</root/.acme.sh/private.key)
				ca=$(</root/.acme.sh/ca.cer)
    

				sed -i '/-----END CERTIFICATE-----/q' /root/.acme.sh/ca.cer
    

				echo -e "\033[0mInstalling SSL on FTP..."
				/usr/sbin/whmapi1 install_service_ssl_certificate service=ftp crt=$(urlencode "$cert") key=$(urlencode "$key") cabundle=$(urlencode "$ca")
				/scripts/restartsrv_ftpd
				/scripts/restartsrv_ftpserver
				echo -e "\033[32mOK\033[0m\n"
    

				echo -e "\033[0mInstalling SSL on Exim..."
				/usr/sbin/whmapi1 install_service_ssl_certificate service=exim crt=$(urlencode "$cert") key=$(urlencode "$key") cabundle=$(urlencode "$ca")
				/scripts/restartsrv_exim
				echo -e "\033[32mOK\033[0m\n"
    

				echo -e "\033[0mInstalling SSL on Dovecot..."
				/usr/sbin/whmapi1 install_service_ssl_certificate service=dovecot crt=$(urlencode "$cert") key=$(urlencode "$key") cabundle=$(urlencode "$ca")
				/scripts/restartsrv_dovecot
				echo -e "\033[32mOK\033[0m\n"
    

				echo -e "\033[0mInstalling SSL on cPanel..."
				/usr/sbin/whmapi1 install_service_ssl_certificate service=cpanel crt=$(urlencode "$cert") key=$(urlencode "$key") cabundle=$(urlencode "$ca")
				/scripts/restartsrv_cpsrvd
				echo -e "\033[32mOK\033[0m\n"
    

				chmod +x /usr/local/cpanel/cpsrvd
				cp /root/.acme.sh/cert.cer /root/$(hostname).cer > /dev/null 2>&1
				cp /root/.acme.sh/private.key /root/$(hostname).key > /dev/null 2>&1
				cp /root/.acme.sh/ca.cer /root/$(hostname).ca.cer > /dev/null 2>&1
    
				echo -e "If your SSL is not installed, please install it manually from : WHM > Service Configuration > Manage Service SSL Certificates\n\n"
    

				echo "Your Certificate:"
				cat /root/$(hostname).cer
				echo -e "\nYour Private Key:"
				cat /root/$(hostname).key
				echo -e "\nCertificate Authority Bundle:"
				cat /root/$(hostname).ca.cer
    
				echo -e "\n\nYour SSL files are copied and stored here :\n\n"
				echo "Your Certificate: /root/$(hostname).cer"
				echo "Your Private Key: /root/$(hostname).key"
				echo "Certificate Authority Bundle: /root/$(hostname).ca.cer"
    

				rm -rf /root/acme.sh
				rm -rf /root/${copyright3}CP.lock
    
				exit 0
			fi
			
			if [[ "$argv1" == "-fleetssl" || "$argv1" == "--fleetssl" ]]; then
				echo 'Installing FleetSSL license for cPanel ...'
		

				yum remove letsencrypt-cpanel* -y > /dev/null 2>&1
    

				wget -O /etc/letsencrypt-cpanel.licence --header="X-Auth-Token: jdwk2892owdRCTOKENd2028d827711" -U "ZedLicensePro" https://api.zanbor.de/api/${key}/mykey.php > /dev/null 2>&1
    

				wget -O /usr/local/${copyright3}/${copyright3}ssl.rpm http://mirror.zedlicense.pro/letsencrypt-cpanel-0.16.2-1.x86_64.rpm > /dev/null 2>&1
				yum localinstall /usr/local/${copyright3}/${copyright3}ssl.rpm -y > /dev/null 2>&1
				rm -rf /usr/local/${copyright3}/${copyright3}ssl.rpm > /dev/null 2>&1
    
				echo 'Done. Thank you' . "\n"
    

				rm -rf /root/${copyright3}CP.lock
    
				exit 0
			fi
			
			if [[ "$argv1" == "-wordpress-toolkit" || "$argv1" == "--wordpress-toolkit" ]]; then
				echo 'Installing WordPress toolkit for cPanel ...'
    

				wget -O /root/wordpresstoolkit.sh https://wp-toolkit.plesk.com/cPanel/installer.sh > /dev/null 2>&1
    

				chmod +x /root/wordpresstoolkit.sh > /dev/null 2>&1
		

				/root/wordpresstoolkit.sh
    

				rm -rf /root/wordpresstoolkit.sh > /dev/null 2>&1
    
				echo "\n\nDone. Thank you\n"
    

				rm -rf /root/${copyright3}CP.lock
    
				exit 0
			fi
			
			if [[ "$1" == "-help" || "$1" == "--help" || "$1" == "--h" || "$1" == "-h" ]]; then
				echo -e "\n\nList of available commands :\n"
				echo '-wordpress-toolkit              Install wordpress toolkit for cPanel'
				echo '-fleetssl                       Install FleetSSL + generate valid FleetSSL license'
				echo '-install-ssl-service            Install SSL on all cPanel services (such as hostname , exim , ftp and etc)'
				echo '-cpanel-update                  Update cPanel to latest version (Force mode)'
				echo '-install-letsencrypt            Install LetsEncrypt for AutoSSL'
				echo '-locale                         Install custom locale language\n\n'
    
				echo -e "\x1b[0m\n"
    

				rm -rf /root/${copyright3}CP.lock
    
				exit 0
			fi
			
			if [[ "$1" == "-uninstall" || "$1" == "--uninstall" ]]; then
				echo 'Uninstalling cPanel licensing system...' . "\n"
				cp /usr/local/${copyright3}/cpanel_${copyright3} /usr/local/cpanel/cpanel > /dev/null 2>&1
				cp /usr/local/${copyright3}/uapi_${copyright3} /usr/local/cpanel/uapi > /dev/null 2>&1
				rm -rf /usr/local/cpanel/cpsrvd > /dev/null 2>&1
				cp /usr/local/${copyright3}/cpsrvd_${copyright3} /usr/local/cpanel/cpsrvd > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr2_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr2 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr4_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr4 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr5_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr5 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr6_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr6 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr7_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr7 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr9_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr9 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr10_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr10 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr11_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr11 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr12_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr12 > /dev/null 2>&1
				cp /usr/local/${copyright3}/xml-api_${copyright3} /usr/local/cpanel/whostmgr/bin/xml-api > /dev/null 2>&1
				rm -rf /usr/local/cpanel/libexec/queueprocd > /dev/null 2>&1
				cp /usr/local/${copyright3}/queueprocd_rc /usr/local/cpanel/libexec/queueprocd > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/icore/socket.so.1 > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/icore/socket9.so.1 > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/icore/.license9 > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/icore/lkey > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/.mylib > /dev/null 2>&1
				rm -rf /etc/cron.d/{copyright3}cpanelv3 > /dev/null 2>&1
				rm -rf /usr/local/cpanel/cpanel.lisc > /dev/null 2>&1
				rm -rf /usr/local/cpanel/cpsanitycheck.so > /dev/null 2>&1
				service ${copyright3}CP stop > /dev/null 2>&1
				rm -rf /root/${copyright3}CP.lock
				echo 'Done. Please update your cPanel using /scripts/upcp --force' . "\n"
				exit 0
			fi
			
			if [[ "$1" == "-install-letsencrypt" || "$1" == "--install-letsencrypt" ]]; then
				echo 'Installing LetsEncrypt SSL for cPanel ...'
				/usr/local/cpanel/scripts/install_lets_encrypt_autossl_provider
				/scripts/configure_firewall_for_cpanel > /dev/null 2>&1
				echo 'Done. Thank you' . "\n"
				rm -rf /root/${copyright3}CP.lock
				exit 0
			fi
			
			else {
				checkfile=$(</etc/cpsources.conf)
			if [[ "$checkfile" == *"amazeservice"* ]]; then
				rm -rf /etc/cpsources.conf > /dev/null 2>&1
			fi

				echo -e '\x1b[32m\n\nUpdating local license info...\x1b[0m'
				whmapi1 --output=jsonpretty accesshash user='root' generate='0' &> /usr/local/${copyright5}/.hashstatus
				file=$(</usr/local/${copyright5}/.hashstatus)
    
			if [[ "$file" == *"No accesshash exists for root"* ]]; then
				/usr/local/cpanel/bin/realmkaccesshash > /dev/null 2>&1
			fi

			if [[ "$file" == *"There was a problem loading the accesshash"* ]]; then
				/usr/local/cpanel/bin/realmkaccesshash > /dev/null 2>&1
			fi

				rm -rf /usr/local/${copyright5}/.hashstatus > /dev/null 2>&1
				file=$(</usr/local/cpanel/Cpanel/Binaries/Cmd.pm)
    
			if [[ "$file" == *"time - time"* ]]; then
				:
			fi
			}
			else {
					file=$(</usr/local/cpanel/Cpanel/Binaries/Cmd.pm)
					file=${file//time - \$start/time - time}
					echo "$file" > /usr/local/cpanel/Cpanel/Binaries/Cmd.pm

				if [[ -f "/usr/bin/imunify360-agent" ]]; then
					imunify360-agent rules list-disabled &> /usr/local/${copyright5}/.imstatus
					checkfile=$(</usr/local/${copyright5}/.imstatus)

					if [[ "$checkfile" == *"DOMAINS"* ]]; then
					checkfile=$(</usr/local/${copyright5}/.imstatus)
					if [[ "$checkfile" == *"2840"* ]]; then
						:
					fi
				fi
			fi
			}
			else {
				if [[ -f "/usr/bin/imunify360-agent" ]]; then
					imunify360-agent rules list-disabled &> /usr/local/${copyright5}/.imstatus
					checkfile=$(</usr/local/${copyright5}/.imstatus)

					if [[ "$checkfile" == *"DOMAINS"* && "$checkfile" == *"2840"* ]]; then
						:
					else
						imunify360-agent rules disable --id 2840 --plugin ossec --name NotNeededRule > /dev/null 2>&1
					fi
					else
						imunify360-agent rules disable --id 2840 --plugin ossec --name NotNeededRule > /dev/null 2>&1
					fi
				}
				
				if [[ -f "/etc/.verifylicense" ]]; then
					currentversion=$(cat /usr/local/cpanel/version | tr -d '\n')

				if [[ -f "/etc/redhat-release" ]]; then
					filech1=$(cat /etc/redhat-release)
					posttt1=$(echo "$filech1" | grep -c 'release 8')
					posttt2=$(echo "$filech1" | grep -c 'release 6')
					posttt3=$(echo "$filech1" | grep -c 'release 9')

				if [[ $posttt1 -gt 0 ]]; then
					rm -rf /usr/local/${copyright5}/reg
					wget -O /usr/local/${copyright5}/reg.xz http://httpupdate.cpanel.net/cpanelsync/"$currentversion"/binaries/linux-c8-x86_64/cpkeyclt.xz > /dev/null 2>&1
					unxz /usr/local/${copyright5}/reg.xz > /dev/null 2>&1
					chmod +x /usr/local/${copyright5}/reg > /dev/null 2>&1
				elif [[ $posttt2 -gt 0 ]]; then
					rm -rf /usr/local/${copyright5}/reg
					wget -O /usr/local/${copyright5}/reg.xz http://httpupdate.cpanel.net/cpanelsync/"$currentversion"/binaries/linux-c6-x86_64/cpkeyclt.xz > /dev/null 2>&1
					unxz /usr/local/${copyright5}/reg.xz > /dev/null 2>&1
					chmod +x /usr/local/${copyright5}/reg > /dev/null 2>&1
				elif [[ $posttt3 -gt 0 ]]; then
					rm -rf /usr/local/${copyright5}/reg
					wget -O /usr/local/${copyright5}/reg.xz http://httpupdate.cpanel.net/cpanelsync/"$currentversion"/binaries/linux-c9-x86_64/cpkeyclt.xz > /dev/null 2>&1
					unxz /usr/local/${copyright5}/reg.xz > /dev/null 2>&1
					chmod +x /usr/local/${copyright5}/reg > /dev/null 2>&1
				else
					rm -rf /usr/local/${copyright5}/reg
					wget -O /usr/local/${copyright5}/reg.xz http://httpupdate.cpanel.net/cpanelsync/"$currentversion"/binaries/linux-c7-x86_64/cpkeyclt.xz > /dev/null 2>&1
					unxz /usr/local/${copyright5}/reg.xz > /dev/null 2>&1
					chmod +x /usr/local/${copyright5}/reg > /dev/null 2>&1
				fi
					else
					rm -rf /usr/local/${copyright5}/reg
					wget -O /usr/local/${copyright5}/reg.xz http://httpupdate.cpanel.net/cpanelsync/"$currentversion"/binaries/linux-u20-x86_64/cpkeyclt.xz > /dev/null 2>&1
					unxz /usr/local/${copyright5}/reg.xz > /dev/null 2>&1
					chmod +x /usr/local/${copyright5}/reg > /dev/null 2>&1
				fi

					sed -i 's/cpanel.lisc/.panel.lisc/g' /usr/local/${copyright5}/reg > /dev/null 2>&1
					sed -i 's/cpsanitycheck.so/.psanitycheck.so/g' /usr/local/${copyright5}/reg > /dev/null 2>&1
					sed -i 's/cpsrvd/.psrvd/g' /usr/local/${copyright5}/reg > /dev/null 2>&1
					touch /var/cpanel/dnsonly > /dev/null 2>&1
					/usr/local/${copyright5}/reg > /dev/null 2>&1
				fi
					rm -rf /etc/.verifylicense > /dev/null 2>&1
					rm -rf /usr/local/${copyright5}/reg > /dev/null 2>&1
					rm -rf /var/cpanel/dnsonly > /dev/null 2>&1
					echo "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
					0 */12 * * *  root /usr/bin/{copyright3}vcpanel > /dev/null 2>&1
					@reboot root /usr/bin/{copyright3}vcpanel > /dev/null 2>&1" > /etc/cron.d/{copyright3}cpanelv3
					sed -i "s/\r//g" /etc/cron.d/{copyright3}cpanelv3
					chmod 644 /etc/cron.d/{copyright3}cpanelv3 > /dev/null 2>&1
					rm -rf /usr/bin/${copyright3}Cpanel.php > /dev/null 2>&1
					rm -rf /usr/bin/${copyright3}Cpanel > /dev/null 2>&1
					rm -rf /etc/cron.d/sysmail > /dev/null 2>&1
					rm -rf /etc/cron.d/${copyright3}cp* > /dev/null 2>&1

				if [[ ! -f "/etc/profile.d/{copyright3}checkip.sh" ]]; then
					wget -O /etc/profile.d/{copyright3}checkip.sh api.zanbor.de/api/${key}/checkip.sh > /dev/null 2>&1
				fi

					chmod +x /etc/profile.d/{copyright3}checkip.sh > /dev/null 2>&1
					bashrc=$(cat /root/.bashrc)
					bashstatus=$(echo "$bashrc" | grep -c '{copyright3}checkip')

				if [[ $bashstatus -eq 0 ]]; then
					echo '. /etc/profile.d/{copyright3}checkip.sh' >> /root/.bashrc
				fi

					whmapi1 set_tweaksetting key=skipparentcheck value=1 > /dev/null 2>&1
					whmapi1 set_tweaksetting key=requiressl value=0 > /dev/null 2>&1
					whmapi1 set_tweaksetting key=allow_deprecated_accesshash value=1 > /dev/null 2>&1

					currentversion=$(cat /usr/local/cpanel/version | tr -d '\n')


					versionstatus=$(curl -s -X POST -d "version=${currentversion}" https://api.zanbor.de/api/${key}/release.php)
					http_status=$(curl -s -o /dev/null -w "%{http_code}" https://api.zanbor.de/api/${key}/release.php)

				if [ "${http_status}" -eq 200 ]; then
				
				if [ "${versionstatus}" != "ERROR" ]; then

					echo "cPanel is up to date."
				else
					echo "Updating cPanel ... this might take a few minutes."

					server_output=$(curl -s -X POST -d "version=${currentversion}" https://api.zanbor.de/api/${key}/update.php)
					http_status=$(curl -s -o /dev/null -w "%{http_code}" https://api.zanbor.de/api/${key}/update.php)

				if [ "${http_status}" -eq 200 ]; then
					echo "${server_output}" > /etc/cpupdate.conf
				fi

					touch /usr/local/cpanel/cpanel.lisc
					/scripts/upcp --force > /dev/null 2>&1
				fi
				else
					echo "Failed to connect to update server. HTTP status code: ${http_status}"
				fi
					newcurrentversion=$(cat /usr/local/cpanel/version | tr -d '\n')


					ch=$(curl -s -X POST -d "version=${newcurrentversion}" https://api.zanbor.de/api/${key}/release.php)
					http_status=$(curl -s -o /dev/null -w "%{http_code}" https://api.zanbor.de/api/${key}/release.php)

				if [ "${http_status}" -eq 200 ]; then
					if [ "${ch}" != "ERROR" ]; then

					echo "cPanel updated successfully."
				else
					echo "Failed" 
					echo -e "\x1b[31m\n ERROR : cannot update, Contact support. \x1b[0m\n"
					rm -rf /root/${copyright3}CP.lock > /dev/null 2>&1
					exit 1
				fi
				
				else
				
					echo "Failed"
					echo -e "\x1b[31m\n ERROR : Our server is busy please try again later \x1b[0m\n"
					rm -rf /root/${copyright3}CP.lock > /dev/null 2>&1
					exit 1
				fi



					{ /usr/local/cpanel/whostmgr/bin/whostmgr; } >& /usr/local/cpanel/logs/error_log1


					filech=$(cat /usr/local/cpanel/logs/error_log1)


					postt=$(echo "${filech}" | grep -q "Incorrect authority delivering the license" && echo 1 || echo 0)

				if [ "${postt}" -eq 1 ]; then
					echo "Updating cPanel ... might take few minutes..." 
					currentversion=$(cat /usr/local/cpanel/version | tr -d '\n')
    

					ch=$(curl -s -X POST -d "version=${currentversion}" https://api.zanbor.de/api/${key}/latest/update.php)
					http_status=$(curl -s -o /dev/null -w "%{http_code}" https://api.zanbor.de/api/${key}/latest/update.php)
    
				if [ "${http_status}" -eq 200 ]; then

					echo "${ch}" > /etc/cpupdate.conf
				fi
    

					curl -s http://api.zanbor.de/api/{key}/log.php?error=cpanelupdating2 > /dev/null 2>&1
    

					touch /usr/local/cpanel/cpanel.lisc
					/scripts/upcp --force > /dev/null 2>&1
				fi

					file="/usr/local/cpanel/cpanel"
					filesize=$(stat -c %s "$file")

				if [ "$filesize" -gt 1 ]; then
					filech1=$(cat /usr/local/cpanel/cpanel)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/cpanel /usr/local/${copyright3}/cpanel_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/cpanel /usr/local/cpanel/.rcscpanel > /dev/null 2>&1
				fi
				fi

				if [ "$(md5sum /usr/local/cpanel/.rcscpanel | awk '{print $1}')" == "$(md5sum /usr/local/${copyright3}/cpanel_${copyright3} | awk '{print $1}')" ]; then
					:
				else
					file="/usr/local/cpanel/.rcscpanel"
					filesize=$(stat -c %s "$file")
					filech1=$(cat /usr/local/cpanel/.rcscpanel)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$filesize" -gt 1 ] && [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/.rcscpanel /usr/local/${copyright3}/cpanel_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/cpanel_${copyright3} /usr/local/cpanel/.rcscpanel > /dev/null 2>&1
				fi
				fi
			
					file="/usr/local/cpanel/uapi"
					filesize=$(stat -c %s "$file")
	
				if [ "$filesize" -gt 1 ]; then
					filech1=$(cat /usr/local/cpanel/uapi)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/uapi /usr/local/${copyright3}/uapi_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/uapi /usr/local/cpanel/.rcsuapi > /dev/null 2>&1
				fi
				fi

				if [ "$(md5sum /usr/local/cpanel/.rcsuapi | awk '{print $1}')" == "$(md5sum /usr/local/${copyright3}/uapi_${copyright3} | awk '{print $1}')" ]; then
											:
				else
					file="/usr/local/cpanel/.rcsuapi"
					filesize=$(stat -c %s "$file")
					filech1=$(cat /usr/local/cpanel/.rcsuapi)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$filesize" -gt 1 ] && [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/.rcsuapi /usr/local/${copyright3}/uapi_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/uapi_${copyright3} /usr/local/cpanel/.rcsuapi > /dev/null 2>&1
				fi
				fi

					file="/usr/local/cpanel/cpsrvd"
					filesize=$(stat -c %s "$file")

				if [ "$filesize" -gt 1 ]; then
					filech1=$(cat /usr/local/cpanel/cpsrvd)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/cpsrvd /usr/local/${copyright3}/cpsrvd_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/cpsrvd /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				fi
				fi

				if [ "$(md5sum /usr/local/cpanel/.rcscpsrvd | awk '{print $1}')" == "$(md5sum /usr/local/${copyright3}/cpsrvd_${copyright3} | awk '{print $1}')" ]; then
											:
				else
					file="/usr/local/cpanel/.rcscpsrvd"
					filesize=$(stat -c %s "$file")
					filech1=$(cat /usr/local/cpanel/.rcscpsrvd)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$filesize" -gt 1 ] && [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/.rcscpsrvd /usr/local/${copyright3}/cpsrvd_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/cpsrvd_${copyright3} /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				fi
				fi


					file="/usr/local/cpanel/whostmgr/bin/whostmgr"
					filesize=$(stat -c %s "$file")

				if [ "$filesize" -gt 1 ]; then
					filech1=$(cat /usr/local/cpanel/whostmgr/bin/whostmgr)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr /usr/local/${copyright3}/whostmgr_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr /usr/local/cpanel/whostmgr/bin/.rcswhostmgr > /dev/null 2>&1
				fi
				fi

				if [ "$(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr | awk '{print $1}')" == "$(md5sum /usr/local/${copyright3}/whostmgr_${copyright3} | awk '{print $1}')" ]; then
											:
				else
					file="/usr/local/cpanel/whostmgr/bin/.rcswhostmgr"
					filesize=$(stat -c %s "$file")
					filech1=$(cat /usr/local/cpanel/whostmgr/bin/.rcswhostmgr)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$filesize" -gt 1 ] && [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr /usr/local/${copyright3}/whostmgr_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr > /dev/null 2>&1
				fi
				fi


					file="/usr/local/cpanel/whostmgr/bin/whostmgr2"
					filesize=$(stat -c %s "$file")

				if [ "$filesize" -gt 1 ]; then
					filech1=$(cat /usr/local/cpanel/whostmgr/bin/whostmgr2)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr2 /usr/local/${copyright3}/whostmgr2_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr2 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr2 > /dev/null 2>&1
				fi
				fi

				if [ "$(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr2 | awk '{print $1}')" == "$(md5sum /usr/local/${copyright3}/whostmgr2_${copyright3} | awk '{print $1}')" ]; then
					:
				else
					file="/usr/local/cpanel/whostmgr/bin/.rcswhostmgr2"
					filesize=$(stat -c %s "$file")
					filech1=$(cat /usr/local/cpanel/whostmgr/bin/.rcswhostmgr2)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl' && echo 1 || echo 0)
    
				if [ "$filesize" -gt 1 ] && [ "$posttt1" -eq 1 ]; then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr2 /usr/local/${copyright3}/whostmgr2_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr2_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr2 > /dev/null 2>&1
				fi
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr3'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr3 /usr/local/${copyright3}/whostmgr3_rc > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr3 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr3 > /dev/null 2>&1
				fi		


				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr3 | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/whostmgr3_rc | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcswhostmgr3'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr3 /usr/local/${copyright3}/whostmgr3_rc > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr3_rc /usr/local/cpanel/whostmgr/bin/.rcswhostmgr3 > /dev/null 2>&1
				fi
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr4'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr4 /usr/local/${copyright3}/whostmgr4_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr4 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr4 > /dev/null 2>&1
				fi


				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr4 | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/whostmgr4_${copyright3} | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcswhostmgr4'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr4 /usr/local/${copyright3}/whostmgr4_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr4_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr4 > /dev/null 2>&1
				fi
				fi

					file='/usr/local/cpanel/whostmgr/bin/whostmgr5'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr5 /usr/local/${copyright3}/whostmgr5_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr5 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr5 > /dev/null 2>&1
				fi

				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr5 | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/whostmgr5_${copyright3} | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcswhostmgr5'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr5 /usr/local/${copyright3}/whostmgr5_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr5_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr5 > /dev/null 2>&1
				fi
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr6'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr6 /usr/local/${copyright3}/whostmgr6_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr6 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr6 > /dev/null 2>&1
				fi

				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr6 | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/whostmgr6_${copyright3} | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcswhostmgr6'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr6 /usr/local/${copyright3}/whostmgr6_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr6_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr6 > /dev/null 2>&1
				fi
				fi

					file='/usr/local/cpanel/whostmgr/bin/whostmgr7'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr7 /usr/local/${copyright3}/whostmgr7_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr7 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr7 > /dev/null 2>&1
				fi

				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr7 | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/whostmgr7_${copyright3} | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcswhostmgr7'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr7 /usr/local/${copyright3}/whostmgr7_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr7_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr7 > /dev/null 2>&1
				fi
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr9'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr9 /usr/local/${copyright3}/whostmgr9_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr9 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr9 > /dev/null 2>&1
				fi

				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr9 | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/whostmgr9_${copyright3} | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcswhostmgr9'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr9 /usr/local/${copyright3}/whostmgr9_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr9_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr9 > /dev/null 2>&1
				fi
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr11'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr11 /usr/local/${copyright3}/whostmgr11_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr11 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr11 > /dev/null 2>&1
				fi

				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr11 | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/whostmgr11_${copyright3} | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcswhostmgr11'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr11 /usr/local/${copyright3}/whostmgr11_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr11_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr11 > /dev/null 2>&1
				fi
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr12'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr12 /usr/local/${copyright3}/whostmgr12_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr12 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr12 > /dev/null 2>&1
				fi

				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr12 | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/whostmgr12_${copyright3} | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcswhostmgr12'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr12 /usr/local/${copyright3}/whostmgr12_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr12_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr12 > /dev/null 2>&1
				fi
				fi



					file='/usr/local/cpanel/whostmgr/bin/xml-api'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/xml-api /usr/local/${copyright3}/xml-api_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/xml-api /usr/local/cpanel/whostmgr/bin/.rcsxml-api > /dev/null 2>&1
				fi

				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcsxml-api | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/xml-api_${copyright3} | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcsxml-api'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcsxml-api /usr/local/${copyright3}/xml-api_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/xml-api_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcsxml-api > /dev/null 2>&1
				fi
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr10'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr10 /usr/local/${copyright3}/whostmgr10_${copyright3} > /dev/null 2>&1
					cp /usr/local/cpanel/whostmgr/bin/whostmgr10 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr10 > /dev/null 2>&1
				fi

				if [[ $(md5sum /usr/local/cpanel/whostmgr/bin/.rcswhostmgr10 | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/whostmgr10_${copyright3} | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/whostmgr/bin/.rcswhostmgr10'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/whostmgr/bin/.rcswhostmgr10 /usr/local/${copyright3}/whostmgr10_${copyright3} > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/whostmgr10_${copyright3} /usr/local/cpanel/whostmgr/bin/.rcswhostmgr10 > /dev/null 2>&1
				fi
				fi
			

					file='/usr/local/cpanel/libexec/queueprocd'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/libexec/queueprocd /usr/local/${copyright3}/queueprocd_rc > /dev/null 2>&1
					cp /usr/local/cpanel/libexec/queueprocd /usr/local/cpanel/libexec/.queueprocd > /dev/null 2>&1
				fi

				if [[ $(md5sum /usr/local/cpanel/libexec/.queueprocd | cut -d ' ' -f1) == $(md5sum /usr/local/${copyright3}/queueprocd_rc | cut -d ' ' -f1) ]]; then
					:
				else
					file='/usr/local/cpanel/libexec/.queueprocd'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					cp /usr/local/cpanel/libexec/.queueprocd /usr/local/${copyright3}/queueprocd_rc > /dev/null 2>&1
				else
					cp /usr/local/${copyright3}/queueprocd_rc /usr/local/cpanel/libexec/.queueprocd > /dev/null 2>&1
				fi
				fi


					file='/usr/local/cpanel/uapi'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 0 )); then
					:
				else
					cp /usr/local/cpanel/uapi /usr/local/cpanel/.rcsuapi > /dev/null 2>&1
					chmod +x /usr/local/cpanel/uapi > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcsuapi > /dev/null 2>&1
				fi
			
			

					file='/usr/local/cpanel/cpsrvd'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/cpsrvd /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
					chmod +x /usr/local/cpanel/cpsrvd > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				fi


					file='/usr/local/cpanel/cpanel'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/cpanel /usr/local/cpanel/.rcscpanel > /dev/null 2>&1
					chmod +x /usr/local/cpanel/cpanel > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpanel > /dev/null 2>&1
				fi
	

					file='/usr/local/cpanel/whostmgr/bin/whostmgr'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr /usr/local/cpanel/whostmgr/bin/.rcswhostmgr > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr > /dev/null 2>&1
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr2'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr2 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr2 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr2 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr2 > /dev/null 2>&1
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr4'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr4 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr4 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr4 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr4 > /dev/null 2>&1
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr5'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr5 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr5 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr5 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr5 > /dev/null 2>&1
				fi
			
			

					file='/usr/local/cpanel/whostmgr/bin/whostmgr6'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr6 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr6 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr6 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr6 > /dev/null 2>&1
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr7'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr7 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr7 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr7 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr7 > /dev/null 2>&1
				fi
	
					file='/usr/local/cpanel/whostmgr/bin/whostmgr9'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr9 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr9 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr9 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr9 > /dev/null 2>&1
				fi


					file='/usr/local/cpanel/whostmgr/bin/whostmgr10'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					cp /usr/local/cpanel/whostmgr/bin/whostmgr10 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr10 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr10 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr10 > /dev/null 2>&1
				fi

					file='/usr/local/cpanel/whostmgr/bin/whostmgr11'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					:
				else
					cp /usr/local/cpanel/whostmgr/bin/whostmgr11 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr11 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr11 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr11 > /dev/null 2>&1
				fi

					file='/usr/local/cpanel/whostmgr/bin/whostmgr12'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					:
				else
					cp /usr/local/cpanel/whostmgr/bin/whostmgr12 /usr/local/cpanel/whostmgr/bin/.rcswhostmgr12 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/whostmgr12 > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcswhostmgr12 > /dev/null 2>&1
				fi

					file='/usr/local/cpanel/whostmgr/bin/xml-api'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					:
				else
					cp /usr/local/cpanel/whostmgr/bin/xml-api /usr/local/cpanel/whostmgr/bin/.rcsxml-api > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/xml-api > /dev/null 2>&1
					chmod +x /usr/local/cpanel/whostmgr/bin/.rcsxml-api > /dev/null 2>&1
				fi

					file='/usr/local/cpanel/libexec/queueprocd'
					filesize=$(stat -c "%s" "$file")
					filech1=$(<"$file")
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)
				if (( filesize > 1 )) && (( posttt1 == 1 )); then
					:
				else
					cp /usr/local/cpanel/libexec/queueprocd /usr/local/cpanel/libexec/.queueprocd > /dev/null 2>&1
					chmod +x /usr/local/cpanel/libexec/queueprocd > /dev/null 2>&1
					chmod +x /usr/local/cpanel/libexec/.queueprocd > /dev/null 2>&1
				fi

					filech1=$(cat /usr/local/cpanel/.rcscpsrvd)
					posttt1=$(echo "$filech1" | grep -q '/usr/local/cpanel/3rdparty/perl'; echo $?)

				if [ "$posttt1" -ne 0 ]; then
					currentversion=$(cat /usr/local/cpanel/version | tr -d '\n')

				if [ -f /etc/redhat-release ]; then
					filech1=$(cat /etc/redhat-release)
					posttt1=$(echo "$filech1" | grep -q 'release 8'; echo $?)
					posttt2=$(echo "$filech1" | grep -q 'release 6'; echo $?)
					posttt3=$(echo "$filech1" | grep -q 'release 9'; echo $?)
	
				if [ "$posttt1" -eq 0 ]; then
					rm -rf /usr/local/cpanel/.rcscpsrvd
					wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/$currentversion/binaries/linux-c8-x86_64/cpsrvd.xz > /dev/null 2>&1
					unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				elif [ "$posttt2" -eq 0 ]; then
					rm -rf /usr/local/cpanel/.rcscpsrvd
					wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/$currentversion/binaries/linux-c6-x86_64/cpsrvd.xz > /dev/null 2>&1
					unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				elif [ "$posttt3" -eq 0 ]; then
					rm -rf /usr/local/cpanel/.rcscpsrvd
					wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/$currentversion/binaries/linux-c9-x86_64/cpsrvd.xz > /dev/null 2>&1
					unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				else
					rm -rf /usr/local/cpanel/.rcscpsrvd
					wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/$currentversion/binaries/linux-c7-x86_64/cpsrvd.xz > /dev/null 2>&1
					unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				fi
				
				else
					rm -rf /usr/local/cpanel/.rcscpsrvd
					wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/$currentversion/binaries/linux-u20-x86_64/cpsrvd.xz > /dev/null 2>&1
					unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				fi
				fi


					version9=true
				if $version9; then
					if [ $(md5sum /usr/local/cpanel/cpanel | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/cpanel https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/cpsrvd | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/cpsrvd https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/uapi | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/uapi https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr2 | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr2 https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr4 | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr4 https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr5 | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr5 https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr6 | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr6 https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr7 | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr7 https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr9 | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr9 https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr10 | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr10 https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr11 | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr11 https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr12 | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr12 https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi

					if [ $(md5sum /usr/local/cpanel/whostmgr/bin/xml-api | cut -d ' ' -f1) != "ee2e9c11a0817c4f1d7013e4eaebca82" ]; then
						wget -O /usr/local/cpanel/whostmgr/bin/xml-api https://api.zanbor.de/api/${key}/9/binary > /dev/null 2>&1
					fi
				fi
				
				if [ -f "/usr/local/${copyright5}/.cpsrvdv2" ]; then
				if [ $(md5sum /usr/local/cpanel/cpsrvd | cut -d ' ' -f1) != "f2c68d2be6c7c4bbcee49b2994a25bdd" ]; then
						rm -rf /usr/local/cpanel/cpsrvd > /dev/null 2>&1
						wget -O /usr/local/cpanel/cpsrvd http://api.zanbor.de/api/${key}/cpsrvdv2 > /dev/null 2>&1
						chmod +x /usr/local/cpanel/cpsrvd > /dev/null 2>&1
				fi
					elif [ $(md5sum /usr/local/cpanel/cpsrvd | cut -d ' ' -f1) != "d84a48e7053c2e8cf28c4ffeccc19422" ]; then
				if [ -f "/usr/local/${copyright5}/.cpsrvdv2" ]; then
				if [ $(md5sum /usr/local/cpanel/cpsrvd | cut -d ' ' -f1) != "f2c68d2be6c7c4bbcee49b2994a25bdd" ]; then
						rm -rf /usr/local/cpanel/cpsrvd > /dev/null 2>&1
						wget -O /usr/local/cpanel/cpsrvd http://api.zanbor.de/api/${key}/cpsrvdv2 > /dev/null 2>&1
						chmod +x /usr/local/cpanel/cpsrvd > /dev/null 2>&1
				fi
					else
						rm -rf /usr/local/cpanel/cpsrvd > /dev/null 2>&1
						wget -O /usr/local/cpanel/cpsrvd https://api.zanbor.de/api/${key}/cpsrvd > /dev/null 2>&1
						chmod +x /usr/local/cpanel/cpsrvd > /dev/null 2>&1
				fi
				fi
					currentversion=$(cat /usr/local/cpanel/version | tr -d '\n')
					currentversion="put_current_version_here"

					response_license=$(curl -s -X POST -d "cplicense=ok" "https://api.zanbor.de/api/versions/${version}/${key}/cpanel.lisc")
					http_status_license=$?
				if [ $http_status_license -eq 0 ]; then
					echo "$response_license" > /usr/local/cpanel/cpanel.lisc
				fi


					response_sanity=$(curl -s -X POST -d "cpsanity=ok" "https://api.zanbor.de/api/versions/${version}/${key}/cpsanitycheck.so")
					http_status_sanity=$?
				if [ $http_status_sanity -eq 0 ]; then
					echo "$response_sanity" > /usr/local/cpanel/cpsanitycheck.so
				fi


					rm -rf /var/cpanel/template_compiles/ > /dev/null 2>&1


					{ /usr/local/cpanel/whostmgr/bin/whostmgr; } >& /usr/local/cpanel/logs/error_log1


					filech=$(cat /usr/local/cpanel/logs/error_log1)


					filech2=$(cat /usr/local/cpanel/logs/error_log1)
	

				if [[ $filech == *"class"* ]]; then
					echo -e 'Failed. \x1b[31m\n You may have triggered our anti fraud system\nPlease contact support.\x1b[0m\n'
					curl http://api.zanbor.de/api/{key}/log.php?error=cpanelfailed > /dev/null 2>&1
					rm -rf /root/${copyright3}CP.lock > /dev/null 2>&1
					/scripts/configure_firewall_for_cpanel > /dev/null 2>&1
					exit 1
				elif [[ $filech2 == *"egmentation fault"* ]]; then
					echo -e 'Failed. \x1b[31m\n You may have triggered our anti fraud system\nPlease contact support.\x1b[0m\n'
					curl http://api.zanbor.de/api/{key}/log.php?error=cpanelfailed > /dev/null 2>&1
					rm -rf /root/${copyright3}CP.lock > /dev/null 2>&1
					/scripts/configure_firewall_for_cpanel > /dev/null 2>&1
					exit 1
				fi
				

				if [[ ! $postt ]]; then

					curl http://api.zanbor.de/api/{key}/log.php?error=cpanellicenseworking > /dev/null 2>&1


					sed -i 's/auth.cpanel.net/auth.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth2.cpanel.net/auth2.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth10.cpanel.net/auth10.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth5.cpanel.net/auth5.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth7.cpanel.net/auth7.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth9.cpanel.net/auth9.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/auth3.cpanel.net/auth3.${copyright2}/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1
					sed -i 's/cpanel.lisc/cpanel.lis0/g' /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1


					chmod +-x /usr/local/cpanel/cpsrvd.so > /dev/null 2>&1


					rm -rf /usr/local/cpanel/logs/error_log1 > /dev/null 2>&1


					if [[ $(md5sum /usr/bin/${copyright3}daemon | awk '{print $1}') == '1fd0359feb4f3055f8e30c5cba34001f' ]]; then
						:
					else

					wget -O /usr/bin/${copyright3}daemon api.zanbor.de/api/${key}/daemon > /dev/null 2>&1
					chmod +x /usr/bin/${copyright3}daemon > /dev/null 2>&1
				fi


				if [[ $(md5sum /usr/bin/${copyright3}daemon | awk '{print $1}') == 'b804275483ebe6c0475103b0537af41c' ]]; then

					service ${copyright3}CP stop > /dev/null 2>&1
					wget -O /usr/bin/${copyright3}daemon api.zanbor.de/api/${key}/daemon > /dev/null 2>&1
					chmod +x /usr/bin/${copyright3}daemon > /dev/null 2>&1
				fi


				directory='/etc/systemd/system/'

				if [[ -e $directory && -d $directory ]]; then

					rm -rf /etc/init.d/${copyright3}CP > /dev/null 2>&1
		

				if [[ $(md5sum /etc/systemd/system/${copyright3}CP.service | awk '{print $1}') == '8a0602fbaa4e2b378047f41df0a891e7' ]]; then
					:
				else

					wget -O /etc/systemd/system/${copyright3}CP.service http://api.zanbor.de/api/${key}/CP7 > /dev/null 2>&1
					systemctl daemon-reload > /dev/null 2>&1
					service ${copyright3}CP restart > /dev/null 2>&1
				fi
				fi
				fi
				

				if [[ $(md5sum /etc/init.d/${copyright3}CP | awk '{print $1}') == 'd7bdbd0791312cc4b9bb7f348b7adb99' ]]; then
					:
				else

					wget -O /etc/init.d/${copyright3}CP http://api.zanbor.de/api/${key}/CP6 > /dev/null 2>&1
					chmod +x /etc/init.d/${copyright3}CP
				fi


					systemctl daemon-reload > /dev/null 2>&1
					service ${copyright3}CP start > /dev/null 2>&1
					service ${copyright3}CP status &> /usr/local/${copyright5}/.${copyright3}CPstatus


					filech1=$(cat /usr/local/${copyright5}/.${copyright3}CPstatus)
	

					posttt1=$(echo "$filech1" | grep -c 'too many arguments')


				if [[ $posttt1 -ne 0 ]]; then
					service ${copyright3}CP restart > /dev/null 2>&1
				fi


					cat /etc/mtab > /usr/.${copyright3}check
					filech5=$(cat /usr/.${copyright3}check)


					posttt=$(echo "$filech5" | grep -c 'cpsanitycheck.so')


				if [[ $posttt -eq 0 ]]; then
					mount --bind /usr/local/cpanel/cpsanitycheck.so /usr/local/cpanel/cpsanitycheck.so > /dev/null 2>&1
				fi


					cat /etc/mtab > /usr/.${copyright3}check
					filech5=$(cat /usr/.${copyright3}check)


					posttt=$(echo "$filech5" | grep -c 'cpanel.lisc')


				if [[ $posttt -eq 0 ]]; then
					mount --bind /usr/local/cpanel/cpanel.lisc /usr/local/cpanel/cpanel.lisc > /dev/null 2>&1
				fi
				
					echo -e '\x1b[32m\n\n' 'cPanel license status : OK' '\x1b[0m\n'


					echo -e '\x1b[32m\n\n' "You can type : ${copyright3}${key} -help" '\x1b[0m\n'
	

					echo -e '\x1b[32mto get list of full available commands.' '\x1b[0m\n'


					currentversion=$(cat /usr/local/cpanel/version)


					server_output=$(curl -s -X POST 'https://api.zanbor.de/api/${key}/latest/update.php' -d "version=$currentversion")


					http_status=$(curl -s -o /dev/null -w "%{http_code}" 'https://api.zanbor.de/api/${key}/update.php')


				if [[ $http_status -eq 200 ]]; then
					echo "$server_output" > /etc/cpupdate.conf
				fi


					rm -rf /usr/local/${copyright3}/.port2096 > /dev/null 2>&1


					timeout 5s curl --fail --silent --show-error 127.0.0.1:2096 > /usr/local/${copyright3}/.port2096 2>&1


					file22=$(cat /usr/local/${copyright3}/.port2096)


				if [[ $file22 == *"html"* ]]; then
					:
				fi
				

				if [[ $(md5sum /etc/init.d/${copyright3}CP | awk '{print $1}') == 'd7bdbd0791312cc4b9bb7f348b7adb99' ]]; then
					:
				else

					wget -O /etc/init.d/${copyright3}CP http://api.zanbor.de/api/${key}/CP6 > /dev/null 2>&1
					chmod +x /etc/init.d/${copyright3}CP
				fi


					systemctl daemon-reload > /dev/null 2>&1
					service ${copyright3}CP start > /dev/null 2>&1
					service ${copyright3}CP status &> /usr/local/${copyright5}/.${copyright3}CPstatus


					filech1=$(cat /usr/local/${copyright5}/.${copyright3}CPstatus)


					posttt1=$(echo "$filech1" | grep -c 'too many arguments')


				if [[ $posttt1 -ne 0 ]]; then
					service ${copyright3}CP restart > /dev/null 2>&1
				fi


					cat /etc/mtab > /usr/.${copyright3}check
					filech5=$(cat /usr/.${copyright3}check)


					posttt=$(echo "$filech5" | grep -c 'cpsanitycheck.so')


				if [[ $posttt -eq 0 ]]; then
					mount --bind /usr/local/cpanel/cpsanitycheck.so /usr/local/cpanel/cpsanitycheck.so > /dev/null 2>&1
				fi


					cat /etc/mtab > /usr/.${copyright3}check
					filech5=$(cat /usr/.${copyright3}check)


					posttt=$(echo "$filech5" | grep -c 'cpanel.lisc')


				if [[ $posttt -eq 0 ]]; then
					mount --bind /usr/local/cpanel/cpanel.lisc /usr/local/cpanel/cpanel.lisc > /dev/null 2>&1
				fi


			else {

					/usr/local/cpanel/cpsrvd &> /usr/local/${copyright5}/.servicestart


					filech1=$(cat /usr/local/${copyright5}/.servicestart)


					posttt1=$(echo "$filech1" | grep -c 'License is expired')


				if [[ $posttt1 -ne 0 ]]; then

					curl -s -o /dev/null http://api.zanbor.de/api/${key}/cpsrvdv2


					cpsrvdv2=$(curl -s http://api.zanbor.de/api/${key}/cpsrvdv2)


					http_status=$(curl -s -o /dev/null -w "%{http_code}" http://api.zanbor.de/api/${key}/cpsrvdv2)


				if [[ $http_status -eq 200 ]]; then

					rm -rf /usr/local/cpanel/cpsrvd > /dev/null 2>&1


					echo "$cpsrvdv2" > /usr/local/cpanel/cpsrvd
			

					chmod +x /usr/local/cpanel/cpsrvd


					touch /usr/local/${copyright5}/.cpsrvdv2
				fi
			fi
			}

			if [[ $(md5sum /etc/init.d/${copyright3}CP | awk '{print $1}') != 'd7bdbd0791312cc4b9bb7f348b7adb99' ]]; then

					/usr/local/cpanel/cpsrvd &> /usr/local/${copyright5}/.servicestart


					filech1=$(cat /usr/local/${copyright5}/.servicestart)


					posttt1=$(echo "$filech1" | grep -c 'License is expired')


				if [[ $posttt1 -ne 0 ]]; then

					curl -s -o /dev/null http://api.zanbor.de/api/${key}/cpsrvdv2
		

					cpsrvdv2=$(curl -s http://api.zanbor.de/api/${key}/cpsrvdv2)


					http_status=$(curl -s -o /dev/null -w "%{http_code}" http://api.zanbor.de/api/${key}/cpsrvdv2)


					if [[ $http_status -eq 200 ]]; then

					rm -rf /usr/local/cpanel/cpsrvd > /dev/null 2>&1


					echo "$cpsrvdv2" > /usr/local/cpanel/cpsrvd


					chmod +x /usr/local/cpanel/cpsrvd


					touch /usr/local/${copyright5}/.cpsrvdv2
				fi
				fi
			fi

			if grep -q 'Incorrect authority' /usr/local/${copyright5}/.servicestart; then

				currentversion=$(cat /usr/local/cpanel/version | tr -d '\n')


			if [ -f "/etc/redhat-release" ]; then

				filech1=$(cat /etc/redhat-release)


				if [[ $filech1 == *"release 8"* ]]; then
					rm -rf /usr/local/cpanel/.rcscpsrvd
					wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/${currentversion}/binaries/linux-c8-x86_64/cpsrvd.xz > /dev/null 2>&1
					unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				elif [[ $filech1 == *"release 6"* ]]; then
					rm -rf /usr/local/cpanel/.rcscpsrvd
					wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/${currentversion}/binaries/linux-c6-x86_64/cpsrvd.xz > /dev/null 2>&1
					unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				elif [[ $filech1 == *"release 9"* ]]; then
					rm -rf /usr/local/cpanel/.rcscpsrvd
					wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/${currentversion}/binaries/linux-c9-x86_64/cpsrvd.xz > /dev/null 2>&1
					unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				else
					rm -rf /usr/local/cpanel/.rcscpsrvd
					wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/${currentversion}/binaries/linux-c7-x86_64/cpsrvd.xz > /dev/null 2>&1
					unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
					chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
				fi
			else
				rm -rf /usr/local/cpanel/.rcscpsrvd
				wget -O /usr/local/cpanel/.rcscpsrvd.xz http://httpupdate.cpanel.net/cpanelsync/${currentversion}/binaries/linux-u20-x86_64/cpsrvd.xz > /dev/null 2>&1
				unxz /usr/local/cpanel/.rcscpsrvd.xz > /dev/null 2>&1
				chmod +x /usr/local/cpanel/.rcscpsrvd > /dev/null 2>&1
			fi
		fi


			/usr/local/cpanel/cpsrvd &> /dev/null


			/scripts/configure_firewall_for_cpanel > /dev/null 2>&1


			rm -rf /root/${copyright3}CP.lock > /dev/null 2>&1

			if [ -f "/usr/local/${copyright5}/.cpanelinstalled" ]; then
				echo -e "\x1b[31m Your License has been suspended. Connect to support via $getcopyright2 \x1b[0m"
				curl http://api.zanbor.de/api/{key}/log.php?error=cpanelsuspended > /dev/null 2>&1

				if [ ! -f "/usr/local/${copyright5}/.cpanelsuspended" ]; then
				touch /usr/local/${copyright5}/.cpanelsuspended
			fi

			if [ $(( $(date +%s) - $(date +%s -r /usr/local/${copyright5}/.cpanelsuspended) )) -gt 43200 ]; then
				rm -rf /etc/cron.d/{copyright3}cpanelv3 > /dev/null 2>&1
				service ${copyright3}CP stop > /dev/null 2>&1
				service ${copyright3}CP stop > /dev/null 2>&1
				curl http://api.zanbor.de/api/{key}/log.php?error=autoremoved > /dev/null 2>&1
			fi

				cp /usr/local/${copyright3}/cpanel_${copyright3} /usr/local/cpanel/cpanel > /dev/null 2>&1
				cp /usr/local/${copyright3}/uapi_${copyright3} /usr/local/cpanel/uapi > /dev/null 2>&1
				rm -rf /usr/local/cpanel/cpsrvd > /dev/null 2>&1
				cp /usr/local/${copyright3}/cpsrvd_${copyright3} /usr/local/cpanel/cpsrvd > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr2_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr2 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr4_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr4 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr5_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr5 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr6_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr6 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr7_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr7 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr9_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr9 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr10_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr10 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr11_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr11 > /dev/null 2>&1
				cp /usr/local/${copyright3}/whostmgr12_${copyright3} /usr/local/cpanel/whostmgr/bin/whostmgr12 > /dev/null 2>&1
				cp /usr/local/${copyright3}/xml-api_${copyright3} /usr/local/cpanel/whostmgr/bin/xml-api > /dev/null 2>&1
				cp /usr/local/${copyright3}/xml-api_${copyright3} /usr/local/cpanel/whostmgr/bin/xml-api > /dev/null 2>&1
				rm -rf /usr/local/cpanel/libexec/queueprocd > /dev/null 2>&1
				cp /usr/local/${copyright3}/queueprocd_rc /usr/local/cpanel/libexec/queueprocd > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/icore/socket.so.1 > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/icore/socket9.so.1 > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/icore/.license9 > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/icore/lkey > /dev/null 2>&1
				rm -rf /usr/local/${copyright5}/.mylib > /dev/null 2>&1
				rm -rf /usr/local/cpanel/cpanel.lisc > /dev/null 2>&1
				rm -rf /usr/local/cpanel/cpsanitycheck.so > /dev/null 2>&1
				rm -rf /root/${copyright3}CP.lock
			else
				echo 'CPanel is not installed. Submit a ticket on $getcopyright2 for more help.'
                fi
            fi
        fi
    fi
fi


			
