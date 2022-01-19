#-- scan functions
#-- masscan
masscanResolver(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}masscan${RESET} scans"
    echo -e "\n[${GREEN}+${RESET}] Resolving all ${YELLOW}hostnames${RESET} in targets.ip"
    for item in $(cat ./targets.ip);
    do
        if [[ $item =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || [[ $item =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$ ]];
        then
            echo $item >> masscan/resolv.ip
        else
            echo -e "$(dig +short $item | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u | tr -s ' ' '\n')" >> masscan/resolv.ip
            echo -e "$(dig +short $item | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}' | sort -u | tr -s ' ' '\n')" >> masscan/resolv.ip
        fi
    done
}

massscanPortScan(){
    MAXRATE=
    if  [[ -z "$MAXRATE" ]]; then
        read -p "[!] Set Masscans value for --max-rate (500): " MAXRATE
    fi
    if [[ -z "$MAXRATE" ]];
    then
        MAXRATE=500
    fi
    echo -e "\n[+] ${BOLD}Masscan Starting"
    echo -e "\n[${GREEN}+${RESET}] Running a ${YELLOW}port scan${RESET} for all IPs in masscan/alive.ip"
    masscan --open -iL masscan/resolv.ip \
            --excludefile exclude.ip \
            -oG masscan/scans/$PORTRANGE.gnmap -v \
            -p $PORTRANGE \
            --max-rate=$MAXRATE
}

#-- nmap
pingSweep(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}nmap${RESET} scans"
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap ping sweep${RESET} for all ip in targets.ip"
    nmap --open -sn -PE -iL targets.ip \
         -oA nmap/scans/PingSweep --excludefile exclude.ip --min-hostgroup $MINHOST --min-rate=$MINRATE
    grep "Up" nmap/scans/PingSweep.gnmap | cut -d " " -f2 | sort -u > nmap/alive.ip
}

nmapPortScan(){
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap port scan${RESET} for all ip in nmap/alive.ip"
    nmap --open -iL nmap/alive.ip \
         -sU -sS -sV -O -Pn -n -oA nmap/scans/portscan -v \
         -p T:$PORTRANGE,U:53,69,123,161,500,1434 \
         --min-hostgroup $MINHOST --min-rate=$MINRATE
}
