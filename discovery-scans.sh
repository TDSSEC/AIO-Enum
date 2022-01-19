#-- scan functions
# Arguments
nmapSettings(){
    PORTANGE=
    if  [[ -z "$PORTRANGE" ]]; then
        read -p "[!] Set TCP port range (1-65535): " PORTRANGE
    fi
    if [[ -z "$PORTRANGE" ]];
    then
        PORTRANGE=1-65535
    fi
    MINHOST=
    if  [[ -z "$MINHOST" ]]; then
        read -p "[!] Set Nmap value for --min-host (50): " MINHOST
    fi
    if [[ -z "$MINHOST" ]];
    then
        MINHOST=500
    fi
    MINRATE=
    if  [[ -z "$MINRATE" ]]; then
        read -p "[!] Set Nmap value for --min-rate (200): " MINRATE
    fi
    if [[ -z "$MINRATE" ]];
    then
        MINRATE=200
    fi
}
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

# nmap pingsweep with --min-rate & --min-hostgroup pre-configured
pingSweepDefault(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}nmap${RESET} scans"
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap ping sweep${RESET} for all ip in targets.ip"
    nmap --open -sn -PE -iL targets.ip \
         -oA nmap/scans/PingSweep --excludefile exclude.ip --min-hostgroup 50 --min-rate=200
    grep "Up" nmap/scans/PingSweep.gnmap | cut -d " " -f2 | sort -u > nmap/alive.ip
}

# regardless of host being 'Up' from a pingsweep, run a portscan of all targets
nmapAllHostsPortScan(){
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap port scan${RESET} for all ip in nmap/alive.ip"
    nmap --open -iL targets.ip \
         -sU -sS -sV -O -Pn -n -oA nmap/scans/portscan -v \
         -p T:$PORTRANGE,U:53,69,123,161,500,1434 \
         --min-hostgroup $MINHOST --min-rate=$MINRATE
}

#only scan targets that responded to an ICMP pingsweep
nmapPortScan(){
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap port scan${RESET} for all ip in nmap/alive.ip"
    nmap --open -iL nmap/alive.ip \
         -sU -sS -sV -O -Pn -n -oA nmap/scans/portscan -v \
         -p T:$PORTRANGE,U:53,69,123,161,500,1434 \
         --min-hostgroup $MINHOST --min-rate=$MINRATE
}
