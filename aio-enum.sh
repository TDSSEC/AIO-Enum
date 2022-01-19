#!/bin/bash

# written by tdssec

RED="\033[01;31m"
GREEN="\033[01;32m"
YELLOW="\033[01;33m"
BLUE="\033[01;34m"
BOLD="\033[01;01m"
RESET="\033[00m"

# sources
source ./nmap-nse-scans.sh
source ./discovery-scans.sh

#-- check for root or exit
if [ $EUID != 0 ]
then
    echo -e "\n[${RED}!${RESET}] must be ${RED}root${RESET}"
    exit 1
fi

declare -a tools=("masscan" "dig" "curl" "nmap" "ike-scan" "nbtscan" "wfuzz")

# check all prerequisite tools are installed, or quit
for tool in ${tools[*]}
do
    #echo ${tool[*]}
    if ! which "$tool" > /dev/null
    then
	echo -e "\n[${RED}!${RESET}] $tool ${RED}not${RESET} found"
	echo -e "\n[${RED}!${RESET}] Ensure the following tools are installed: ${tools[*]}"
	exit 1
    fi
done
# populate files and folders
declare -a files=("./targets.ip" "./exclude.ip")
declare -a folders=("scans" "open-ports" "nse_scans" "masscan/scans/" "nmap/scans/")

for file in ${files[*]}
do
    if [ ! -f "$file" ]
    then
	touch $file
        echo -e "\n[${GREEN}+${RESET}] Populate the ${YELLOW} $file ${RESET} file"
	exit 1
    fi
done

for folder  in ${folders[*]}
do
    if [ ! -d "$folder" ]
    then
	mkdir -p $folder         
    fi
done

#-- Nmap variables
MINHOST=$1
if  [[ -z "$MINHOST" ]]; then
    MINHOST=50
fi

MINRATE=$2
if  [[ -z "$MINRATE" ]]; then
    MINRATE=500
fi

#-- port variables
PORTRANGE=$3
if  [[ -z "$PORTRANGE" ]]; then
    PORTRANGE=1-65535
fi
MINPORT=$(echo $PORTRANGE | cut -d '-' -f 1)
MAXPORT=$(echo $PORTRANGE | cut -d '-' -f 2)

# Your IP Address
ipChecker(){
    echo -e "\n ${RED}[!] ENSURE YOU ARE SOURCING FROM AN INSCOPE IP" ${RESET}
    pubIP=$(curl -s https://ifconfig.me | cut -d '%' -f1)
    echo -e "\nYour Public IP is: " ${RED}$pubIP${RESET}
    intIP=$(ip -o -4 addr list | awk ' {print $4}' | cut -d/ -f1)
    echo -e "\nYour Internal IP(s) are: " ${RED}$intIP${RESET}
    read -p "Press Enter to continue"
}

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


menuChoice(){
    read -p "Choose an option: " choice
    case "$choice" in
  	1 ) echo "[1] selected, identifying alive IPs and ports only"
	    masscanResolver
	    massscanPortScan
	    pingSweep
	    nmapPortScan
	    combiner
	    parser
	    summary;;
	2 ) echo "[2] selected, running -- Masscan|Nmap|NSEs"
	    masscanResolver
	    massscanPortScan
	    pingSweep
	    nmapPortScan
	    combiner
	    parser
	    nse
	    otherScans
	    summary;;
	3 ) echo "[3] selected, running -- Masscan | Nmap | NSEs | Dictionary attacks!"
	    masscanResolver
	    massscanPortScan
	    pingSweep
	    nmapPortScan
	    combiner
	    parser
	    nse
	    otherScans
	    discoveryScans # for dictionary attacks
	    summary;;
	4 ) echo "[4] selected, running -- Nmap|NSEs"
	    pingSweep
	    nmapPortScan
	    combiner
	    parser
	    nse
	    otherScans
	    summary;;
	* ) echo "[!] Incorrect choice - Quitting!"
	    exit 1;;
    esac
}

#Start the script
if (( "$#" < 3 )); #If not provided the 3 arguments - show usage
then
    ipChecker
    MINHOST=50
    MINRATE=500
    PORTRANGE=1-65535
    echo -e "${RED}[!] Not entered all 3 arguments - Setting default values as shown in the usage example below!"${RESET}
    echo -e "Defaulting to ALL TCP ports and UDP ports 53,69,123,161,500,1434\n"
    echo -e "Usage Example: sudo bash ./aio-enum.sh 50 500 1-1024"
    echo -e "./autoenum.sh [Nmap min hostgroup] [Nmap min rate] [Port range]\n"
    echo -e "[1] Identify Alive IPs and Ports only "
    echo -e "[2] Default Scans (Masscan, Nmap and NSE scripts) "
    echo -e "[3] Default Scans + web applications dir/page enumeration "
    echo -e "[4] Nmap pingsweep, portscan and NSE scripts only "
    menuChoice
elif (( "$#" == 3 ));
then
    ipChecker
    echo -e "Arguments taken:"
    echo -e "--min-hostgroup: " $1
    echo -e "--min-rate: " $2
    echo -e "--port-range: " $3
    echo -e "\n[1] Identify Alive IPs and Ports only "
    echo -e "[2] Default Scans (Masscan, Nmap and NSE scripts) "
    echo -e "[3] Default Scans + web applications dir/page enumeration "
    echo -e "[4] Nmap pingsweep, portscan and NSE scripts only "
    menuChoice 
fi
