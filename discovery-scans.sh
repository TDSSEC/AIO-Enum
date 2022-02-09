#-- scan functions
# Arguments
nmapSettings(){
    echo -e "\n[${GREEN}+${RESET}] Using nmap settings:\n    tcp port range: ${GREEN}${TCPPORTRANGE}${RESET}\n    udp port range: ${GREEN}${UDPPORTRANGE}${RESET}\n    minimum host group: ${GREEN}${MINHOST}${RESET}\n    minimum rate: ${GREEN}${MINRATE}${RESET}"
}

#-- masscan
masscanResolver(){
    echo -e "\n[${GREEN}+${RESET}] Using masscan settings:\n    tcp port range: ${GREEN}${TCPPORTRANGE}${RESET}\n    udp port range: ${GREEN}${UDPPORTRANGE}${RESET}\n    max rate: ${GREEN}${MAXRATE}${RESET}"
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}masscan${RESET} scans"
    echo -e "\n[${GREEN}+${RESET}] Resolving all ${YELLOW}hostnames${RESET} in targets.ip"
    for item in $(cat ./targets.ip);
    do
        if [[ $item =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || [[ $item =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}$ ]];
        then
            echo $item >> "$OUTPUTDIR/masscan/resolv.ip"
        else
            echo -e "$(dig +short $item | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u | tr -s ' ' '\n')" >> "$OUTPUTDIR/masscan/resolv.ip"
            echo -e "$(dig +short $item | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,2}' | sort -u | tr -s ' ' '\n')" >> "$OUTPUTDIR/masscan/resolv.ip"
        fi
    done
}

massscanPortScan(){
    masscanResolver
    if [ ! -z "$MASSCANINTERFACE" ]
    then
        MASSCANINTERFACE="--interface ${MASSCANINTERFACE} "
    fi
    echo -e "\n[${GREEN}+${RESET}] Running a ${YELLOW}port scan${RESET} for all IPs in masscan/alive.ip"
    masscan --open -iL "$OUTPUTDIR/masscan/resolv.ip" \
            --excludefile exclude.ip $MASSCANINTERFACE\
            -oG "$OUTPUTDIR/masscan/scans/masscan.gnmap" -v \
            -p "$TCPPORTRANGE,U:$UDPPORTRANGE" \
            --max-rate=$MAXRATE
}

#------ nmap ---------------
pingSweep(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}nmap${RESET} scans"
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap ping sweep${RESET} for all ip in targets.ip"
    nmap --open -sn -PE -iL targets.ip \
         -oA "$OUTPUTDIR/nmap/scans/PingSweep" --excludefile exclude.ip --min-hostgroup $MINHOST --min-rate=$MINRATE
    grep "Up" "$OUTPUTDIR/nmap/scans/PingSweep.gnmap" | cut -d " " -f2 | sort -u > "$OUTPUTDIR/nmap/alive.ip"
}

# nmap pingsweep with --min-rate & --min-hostgroup pre-configured
pingSweepDefault(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}nmap${RESET} scans"
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap ping sweep${RESET} for all ip in targets.ip"
    nmap --open -sn -PE -iL targets.ip \
         -oA "$OUTPUTDIR/nmap/scans/PingSweep" --excludefile exclude.ip --min-hostgroup 50 --min-rate=200
    grep "Up" "$OUTPUTDIR/nmap/scans/PingSweep.gnmap" | cut -d " " -f2 | sort -u > "$OUTPUTDIR/nmap/alive.ip"
}

# regardless of host being 'Up' from a pingsweep, run a portscan of all targets
# No version or OS detection in this one
nmapFastPortScan(){
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap port scan${RESET} for all ip in nmap/alive.ip. No version or OS detection"
    nmap --open -iL targets.ip \
         -sU -sS -Pn -n -oA "$OUTPUTDIR/nmap/scans/portscan" -v \
         -p T:$TCPPORTRANGE,U:$UDPPORTRANGE \
         --min-hostgroup $MINHOST --min-rate=$MINRATE
}

nmapAllHostsPortScan(){
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap port scan${RESET} for all ip in nmap/alive.ip"
    nmap --open -iL targets.ip \
         -sU -sS -sV -O -Pn -n -oA "$OUTPUTDIR/nmap/scans/portscan" -v \
         -p T:$TCPPORTRANGE,U:$UDPPORTRANGE \
         --min-hostgroup $MINHOST --min-rate=$MINRATE
}

#only scan targets that responded to an ICMP pingsweep
nmapPortScan(){
    echo -e "\n[${GREEN}+${RESET}] Running an ${YELLOW}nmap port scan${RESET} for all ip in nmap/alive.ip"
    nmap --open -iL "$OUTPUTDIR/nmap/alive.ip" \
         -sU -sS -sV -O -Pn -n -oA "$OUTPUTDIR/nmap/scans/portscan" -v \
         -p T:$TCPPORTRANGE,U:$UDPPORTRANGE \
         --min-hostgroup $MINHOST --min-rate=$MINRATE
}
