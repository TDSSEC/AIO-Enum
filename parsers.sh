#-- combining masscan and nmap results
combiner(){
    echo -e "\n[${GREEN}+${RESET}] Combining ${YELLOW}nmap${RESET} and ${YELLOW}masscan${RESET} scans"
    touch "$OUTPUTDIR/alive.ip"
    touch "$OUTPUTDIR/masscan/alive.ip"
    cp "$OUTPUTDIR/masscan/scans/"* "$OUTPUTDIR/scans"
    cp "$OUTPUTDIR/nmap/scans/"* "$OUTPUTDIR/scans"
    cat "$OUTPUTDIR/masscan/scans/masscan.gnmap" | head -n -1 | tail -n +3 | cut -d ' ' -f 3 | sort -u > "$OUTPUTDIR/masscan/alive.ip"
    cat "$OUTPUTDIR/masscan/alive.ip" "$OUTPUTDIR/nmap/alive.ip" | sort -u >> "$OUTPUTDIR/alive.ip"
}

#progress bar
prog() {
    local w=80 p=$1;  shift
    # create a string of spaces, then change them to dots
    printf -v dots "%*s" "$(( $p*$w/$MAXPORT ))" ""; dots=${dots// /#};
    # print those dots on a fixed-width space plus the percentage etc. 
    printf "\r\e[K|%-*s| %3d  %s" "$w" "$dots" "$p" "$*"; 
}

parser(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}parser${RESET} for ${YELLOW}nse${RESET} scans"
 
    for n in $(seq $MINPORT $MAXPORT);   
    do
	if [ $(cat "$OUTPUTDIR/scans/"*.gnmap | egrep " $n\/open\/tcp/" | cut -d " " -f 2 | wc -l) -eq '0' ];
	then
	    prog "$n" out of $MAXPORT TCP ports...
	   # sleep .1 	
	else
	    cat "$OUTPUTDIR/scans/"*.gnmap | egrep " $n\/open\/tcp/" | cut -d " " -f 2 >> "$OUTPUTDIR/open-ports/$n.txt"
	fi
	if [ $(cat "$OUTPUTDIR/scans/"*.gnmap | egrep " $n\/open\/udp/" | cut -d " " -f 2 | wc -l) -eq '0' ];
	then
	    prog "$n" out of $MAXPORT UDP ports...
	   # sleep .1 
	else
	    cat "$OUTPUTDIR/scans/"*.gnmap | egrep " $n\/open\/udp/" | cut -d " " -f 2 >> "$OUTPUTDIR/open-ports/$n.txt"
	fi
    done
}
#nmap to CSV - requires python3
#https://github.com/laconicwolf/Nmap-Scan-to-CSV
csvParser(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}parser${RESET} for ${YELLOW}NMAP XML to CSV${RESET}"
    if ! hash python3; then
	echo "python3 is not installed"
	exit 1
    else
    	wget https://raw.githubusercontent.com/TDSSEC/Nmap-Scan-to-CSV/master/nmap_xml_parser.py 
	$(which python3) nmap_xml_parser.py -f "$OUTPUTDIR/scans/"*.xml -csv "$OUTPUTDIR/host-info.csv"
    fi
}
#-- summary
summary(){
    echo -e "\n[${GREEN}+${RESET}] Generating a summary of the scans..."
    for ip in $(cat "$OUTPUTDIR/alive.ip"); do
	echo -e $ip > "$OUTPUTDIR/open-ports/$ip.txt"
	awk \/$ip\/ "$OUTPUTDIR/masscan/scans/masscan.gnmap" | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> "$OUTPUTDIR/tempports.tmp"
	awk \/$ip\/ "$OUTPUTDIR/nmap/scans/portscan.gnmap" | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> "$OUTPUTDIR/tempports.tmp"
    cat "$OUTPUTDIR/tempports.tmp" | sort -u >> "$OUTPUTDIR/open-ports/$ip.txt"
    rm -f "$OUTPUTDIR/tempports.tmp"
    done
    echo -e "\n[${GREEN}+${RESET}] there are $(cat "$OUTPUTDIR/alive.ip" | wc -l ) ${YELLOW}alive hosts${RESET} and $(egrep -o '[0-9]*/open/*[tcp/udp]*/' "$OUTPUTDIR/scans/"*.gnmap | cut -d ':' -f 2 | sort | uniq | wc -l) ${YELLOW}unique ports/services${RESET}" | tee -a "$OUTPUTDIR/discovered_ports.txt"
}

summaryPingSweep(){
    echo -e "\n[${GREEN}+${RESET}] ${YELLOW}There are $(cat "$OUTPUTDIR/nmap/alive.ip" | wc -l ) alive hosts${RESET}"
}
