#!/bin/bash
nse(){
    echo -e "\n[${GREEN}+${RESET}] running ${YELLOW}nse${RESET} scans"
    if [ -f "$OUTPUTDIR/open-ports/21.txt" ]; 
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}21${RESET}"
	nmap -sC -sV -p 21 -iL "$OUTPUTDIR/open-ports/21.txt" \
	     --script=ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor -oN "nse_scans/ftp.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/22.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}22${RESET}"
	nmap -sC -sV -p 22 -iL "$OUTPUTDIR/open-ports/22.txt" \
	     --script=ssh2-enum-algos -oN "$OUTPUTDIR/nse_scans/ssh.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/23.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}23${RESET}"
	nmap -sC -sV -p 23 -iL "$OUTPUTDIR/open-ports/23.txt" \
	     --script=telnet-encryption,banner,telnet-ntlm-info,tn3270-info -oN "$OUTPUTDIR/nse_scans/telnet.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/25.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}25${RESET}"
	nmap -sC -sV -p 25 -iL "$OUTPUTDIR/open-ports/25.txt" \
	     --script=smtp-commands,smtp-open-relay,smtp-ntlm-info,smtp-enum-users.nse \
	     --script-args smtp-enum-users.methods={EXPN,VRFY} -oN "$OUTPUTDIR/nse_scans/smtp.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/53.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}53${RESET}"
	nmap -sU -p 53 -iL "$OUTPUTDIR/open-ports/53.txt" \
	     --script=dns-recursion,dns-service-discovery,dns-cache-snoop.nse,dns-nsec-enum \
	     --script-args dns-nsec-enum.domains=example.com -oN "$OUTPUTDIR/nse_scans/dns.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/80.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}80${RESET}"
	nmap -sC -sV -p 80 -iL "$OUTPUTDIR/open-ports/80.txt" \
	     --script=http-default-accounts,http-enum,http-title,http-methods,http-robots.txt,http-trace,http-shellshock,http-dombased-xss,http-phpself-xss,http-wordpress-enum,http-wordpress-users \
	     -oN "$OUTPUTDIR/nse_scans/http.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/110.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}110${RESET}"
	nmap -sC -sV -p 110 -iL "$OUTPUTDIR/open-ports/110.txt" \
	     --script=pop3-capabilities -oN "$OUTPUTDIR/nse_scans/pop3.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/111.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}111${RESET}"
	nmap -sV -p 111 -iL "$OUTPUTDIR/open-ports/111.txt" \
	     --script=nfs-showmount,nfs-ls -oN "$OUTPUTDIR/nse_scans/nfs111.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/123.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}123${RESET}"
	nmap -sU -p 123 -iL "$OUTPUTDIR/open-ports/123.txt" \
	     --script=ntp-info,ntp-monlist -oN "$OUTPUTDIR/nse_scans/ntp.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/161.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}161${RESET}"
	nmap -sC -sU -p 161 -iL "$OUTPUTDIR/open-ports/161.txt" \
	     --script=snmp-interfaces,snmp-sysdescr,snmp-netstat,snmp-processes -oN "$OUTPUTDIR/nse_scans/snmp.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/443.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}443${RESET}"
	nmap -sC -sV -p 443 -iL "$OUTPUTDIR/open-ports/443.txt" \
	     --script=http-default-accounts,http-title,http-methods,http-robots.txt,http-trace,http-shellshock,http-dombased-xss,http-phpself-xss,http-wordpress-enum \
	     -oN "$OUTPUTDIR/nse_scans/https.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE

	nmap -sC -sV -p 443 -iL "$OUTPUTDIR/open-ports/443.txt" --version-light \
	 --script=ssl-poodle,ssl-heartbleed,ssl-enum-ciphers,ssl-cert-intaddr \
	 --script-args vulns.showall -oN "$OUTPUTDIR/nse_scans/ssl.txt" \
	 --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/445.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}445${RESET}"
	nmap -sC -sV  -p 445 -iL "$OUTPUTDIR/open-ports/445.txt" \
	     --script=smb-enum-shares.nse,smb-os-discovery.nse,smb-enum-users.nse,smb-security-mode,smb-vuln-ms17-010,smb-vuln-ms08-067,smb2-vuln-uptime \
	     -oN "$OUTPUTDIR/nse_scans/smb.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/1521.txt" ];
    then
	nmap -p 1521-1560 -iL "$OUTPUTDIR/open-ports/1521.txt" \
	     --script=oracle-sid-brute -oN "$OUTPUTDIR/nse_scans/oracle.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/2049.txt" ];
    then
	nmap -sV -p 2049 -iL "$OUTPUTDIR/open-ports/2049.txt" \
	     --script=nfs-showmount,nfs-ls -oN "$OUTPUTDIR/nse_scans/nfs2049.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/3306.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}3306${RESET}"
	nmap -sC -sV -p 3306 -iL "$OUTPUTDIR/open-ports/3306.txt" \
	     --script=mysql-empty-password,mysql-users,mysql-enum,mysql-audit \
	     --script-args "mysql-audit.username='root', \mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit'" \
	     -oN "$OUTPUTDIR/nse_scans/mysql.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    
	nmap -sC -sV -p 3306 -iL "$OUTPUTDIR/open-ports/3306.txt" \
	     --script=mysql-empty-password,mysql-users,mysql-enum,mysql-audit \
	     --script-args "mysql-audit.username='root', \mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit'" \
	     -oN "$OUTPUTDIR/nse_scans/mysql.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/5900.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}5900${RESET}"
	nmap -sC -sV -p 5900 -iL "$OUTPUTDIR/open-ports/5900.txt" \
	     --script=banner,vnc-title -oN "$OUTPUTDIR/nse_scans/vnc.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/8080.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}8080${RESET}"
	nmap -sC -sV -p 8080 -iL "$OUTPUTDIR/open-ports/8080.txt" \
	     --script=http-default-accounts,http-title,http-robots.txt,http-methods,http-shellshock,http-dombased-xss,http-phpself-xss \
	     -oN "$OUTPUTDIR/nse_scans/http8080.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/8443.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}8443${RESET}"
	nmap -sC -sV -p 8443 -iL "$OUTPUTDIR/open-ports/8443.txt" \
	     --script=http-default-accounts,http-title,http-robots.txt,http-methods,http-shellshock,http-dombased-xss,http-phpself-xss \
	     -oN "$OUTPUTDIR/nse_scans/https8443.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
    if [ -f "$OUTPUTDIR/open-ports/27017.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}27017${RESET}"
	nmap -sC -sV -p 27017 -iL "$OUTPUTDIR/open-ports/27017.txt" \
	     --script=mongodb-info,mongodb-databases -oN "$OUTPUTDIR/nse_scans/mongodb.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
    else
	:
    fi
}

#-- other scans
otherScans(){
    echo -e "\n[${GREEN}+${RESET}] running ${YELLOW}other${RESET} scans"
    if [ -f "$OUTPUTDIR/open-ports/500.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}500${RESET}"
	nmap -sU -p 500 -iL "$OUTPUTDIR/open-ports/500.txt" \
	     --script=ike-version -oN "$OUTPUTDIR/nse_scans/ike.txt" \
	     --stats-every 60s --min-hostgroup $MINHOST --min-rate=$MINRATE
	for ip in $(cat "$OUTPUTDIR/open-ports/500.txt")
	do	    
	    ike-scan -A -M $ip --id=GroupVPN | tee -a "$OUTPUTDIR/nse_scans/IKE-$ip.txt"
	done
    else
	:
    fi

    if [ -f "$OUTPUTDIR/open-ports/139.txt" ] || [ -f "$OUTPUTDIR/open-ports/445.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] Running further scans for SMB ports${RESET}"
	for ip in $(cat "$OUTPUTDIR/open-ports/139.txt")
	do
	    nbtscan $ip | tee -a "$OUTPUTDIR/nse_scans/nbtscan-$ip.txt"
	done
	for ip in $(cat "$OUTPUTDIR/open-ports/445.txt")
	do
	    nbtscan $ip | tee -a "$OUTPUTDIR/nse_scans/nbtscan-$ip.txt"
	done
    else
	:
    fi
    
    if [ -f "$OUTPUTDIR/open-ports/443.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] running scans for port ${YELLOW}443${RESET}"
	for ip in $(cat "$OUTPUTDIR/open-ports/443.txt")
	do
	    curl -v https://$ip/ -H "Host: hostname" \
		 --max-time 10 \
		 -H "Range: bytes=0-18446744073709551615" -k | tee -a "$OUTPUTDIR/nse_scans/MS15034-$ip.txt"
	    curl -Ikv -X GET -0 \
		 --max-time 10 \
		 -H 'Host:' https://$ip/autodiscover/autodiscover.xml \
		| tee -a "$OUTPUTDIR/nse_scans/internal-ip-header-check-$ip.txt"
	done
    else
	:
    fi            
}

discoveryScans(){
    # These scans look to enumerate information based off of common word lists or dictionaries.
    if [ -f "$OUTPUTDIR/open-ports/80.txt" ];
    then
	echo -e "\n[${GREEN}+${RESET}] Running world list scan for port ${YELLOW}80${RESET}"
	echo -e "\nDirb default wordlist of 4612 words"
	for ip in $(cat "$OUTPUTDIR/open-ports/80.txt")
	do
	    dirb http://$ip | tee -a "$OUTPUTDIR/nse_scans/dirb-$ip.txt"
	done 
    else
	:
    fi
}