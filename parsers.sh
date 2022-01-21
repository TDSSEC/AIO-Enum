#-- combining masscan and nmap results
combiner(){
    echo -e "\n[${GREEN}+${RESET}] Combining ${YELLOW}nmap${RESET} and ${YELLOW}masscan${RESET} scans"
    touch alive.ip
    touch masscan/alive.ip
    cp masscan/scans/* scans
    cp nmap/scans/* scans
    cat masscan/scans/$PORTRANGE.gnmap | head -n -1 | tail -n +3 | cut -d ' ' -f 2 | sort -u > masscan/alive.ip
    cat masscan/alive.ip nmap/alive.ip | sort -u >> alive.ip
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
	if [ $(cat scans/*.gnmap | egrep " $n\/open\/tcp/" | cut -d " " -f 2 | wc -l) -eq '0' ];
	then
	    prog "$n" out of $MAXPORT TCP ports...
	   # sleep .1 	
	else
	    cat scans/*.gnmap | egrep " $n\/open\/tcp/" | cut -d " " -f 2 >> open-ports/$n.txt
	fi
	if [ $(cat scans/*.gnmap | egrep " $n\/open\/udp/" | cut -d " " -f 2 | wc -l) -eq '0' ];
	then
	    prog "$n" out of $MAXPORT UDP ports...
	   # sleep .1 
	else
	    cat scans/*.gnmap | egrep " $n\/open\/udp/" | cut -d " " -f 2 >> open-ports/$n.txt
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
	$(which python3) nmap_xml_parser.py -f scans/*.xml -csv host-info.csv
    fi
}
#-- summary
summary(){
    echo -e "\n[${GREEN}+${RESET}] Generating a summary of the scans..."
    for ip in $(cat ./alive.ip); do
	echo -e $ip > ./open-ports/$ip.txt
	awk \/$ip\/ masscan/scans/$PORTRANGE.gnmap | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> ./open-ports/$ip.txt
	awk \/$ip\/ nmap/scans/portscan.gnmap | egrep -o '*[0-9]*/open/*[tcp/udp]*/' | sort | uniq | awk -F '/' '{print $1"/"$3}' >> ./open-ports/$ip.txt
    done
    echo -e "\n[${GREEN}+${RESET}] there are $(cat ./alive.ip | wc -l ) ${YELLOW}alive hosts${RESET} and $(egrep -o '[0-9]*/open/' scans/*.gnmap | cut -d ':' -f 2 | sort | uniq | wc -l) ${YELLOW}unique ports/services${RESET}" | tee -a discovered_ports.txt
}

summaryPingSweep(){
    echo -e "\n[${GREEN}+${RESET}] ${YELLOW}There are $(cat nmap/alive.ip | wc -l ) alive hosts${RESET}"
}
