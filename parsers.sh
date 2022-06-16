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
    printf -v dots "%*s" "$(( $p*$w/65535 ))" ""; dots=${dots// /#};
    # print those dots on a fixed-width space plus the percentage etc. 
    printf "\r\e[K|%-*s| %3d  %s" "$w" "$dots" "$p" "$*"; 
}

parser(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}parser${RESET} for ${YELLOW}nse${RESET} scans"

    for n in $(seq 1 65535);
    do
	if [ $(cat "$OUTPUTDIR/scans/"*.gnmap | egrep " $n\/open\/tcp/" | cut -d " " -f 2 | wc -l) -eq '0' ];
	then
	    prog "$n" out of 65535 TCP ports...
	   # sleep .1
	else
	    cat "$OUTPUTDIR/scans/"*.gnmap | egrep " $n\/open\/tcp/" | cut -d " " -f 2 >> "$OUTPUTDIR/open-ports/$n.txt"
	fi
	if [ $(cat "$OUTPUTDIR/scans/"*.gnmap | egrep " $n\/open\/udp/" | cut -d " " -f 2 | wc -l) -eq '0' ];
	then
	    prog "$n" out of 65535 UDP ports...
	   # sleep .1
	else
	    cat "$OUTPUTDIR/scans/"*.gnmap | egrep " $n\/open\/udp/" | cut -d " " -f 2 >> "$OUTPUTDIR/open-ports/$n.txt"
	fi
    done
}
#nmap to CSV - using style sheet and xsltproc
csvParser(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}parser${RESET} for ${YELLOW}NMAP XML to CSV${RESET}"
    xsltproc -o "$OUTPUTDIR/csv_and_html_files/nmap-results.csv" xml-to-csv.xsl "$OUTPUTDIR/scans/"*.xml
}

#nmap to HTML using xsltproc
htmlParser(){
    echo -e "\n[${GREEN}+${RESET}] Running ${YELLOW}parser${RESET} for ${YELLOW}NMAP XML to HTML${RESET}"
    xsltproc -o "$OUTPUTDIR/csv_and_html_files/nmap-results.html" "$OUTPUTDIR/scans/"*.xml
}

#-- summary
summary(){
    MASSCAN_FILE="$OUTPUTDIR/masscan/scans/masscan.gnmap"
    echo -e "\n[${GREEN}+${RESET}] Generating a summary of the scans..."
    for ip in $(cat "$OUTPUTDIR/alive.ip"); do
	echo -e $ip > "$OUTPUTDIR/open-ports/$ip.txt"
	if [ -f "$MASSCAN_FILE" ]; then #if masscan was executed, check both masscan and nmap
            awk \/$ip\/ "$OUTPUTDIR/masscan/scans/masscan.gnmap" | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> "$OUTPUTDIR/tempports.tmp"
	    awk \/$ip\/ "$OUTPUTDIR/nmap/scans/portscan.gnmap" | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> "$OUTPUTDIR/tempports.tmp"
	    cat "$OUTPUTDIR/tempports.tmp" | sort -u >> "$OUTPUTDIR/open-ports/$ip.txt"
	    rm -f "$OUTPUTDIR/tempports.tmp"
	else #just check nmap files
	    awk \/$ip\/ "$OUTPUTDIR/nmap/scans/portscan.gnmap" | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> "$OUTPUTDIR/tempports.tmp"
            cat "$OUTPUTDIR/tempports.tmp" | sort -u >> "$OUTPUTDIR/open-ports/$ip.txt"
            rm -f "$OUTPUTDIR/tempports.tmp"
	fi
    done
    echo -e "\n[${GREEN}+${RESET}] there are $(cat "$OUTPUTDIR/alive.ip" | wc -l ) ${YELLOW}alive hosts${RESET} and $(egrep -o '[0-9]*/open/*[tcp/udp]*/' "$OUTPUTDIR/scans/"*.gnmap | cut -d ':' -f 3 | sort | uniq | wc -l) ${YELLOW}unique ports/services${RESET}" | tee -a "$OUTPUTDIR/discovered_ports.txt"
}

summaryPingSweep(){
    echo -e "\n[${GREEN}+${RESET}] ${YELLOW}There are $(cat "$OUTPUTDIR/nmap/alive.ip" | wc -l ) alive hosts${RESET}"
}
