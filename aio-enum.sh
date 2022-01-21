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
source ./parsers.sh

#-- check for root or exit
if [ $EUID != 0 ]
then
    echo -e "\n[${RED}!${RESET}] must be ${RED}root${RESET}"
    exit 1
fi

declare -a tools=("masscan" "dig" "curl" "nmap" "ike-scan" "nbtscan" "wfuzz" "git")

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

# Your IP Address
ipChecker(){
    echo -e "\n ${RED}[!] ENSURE YOU ARE SOURCING FROM AN INSCOPE IP" ${RESET}
    pubIP=$(curl -s https://ifconfig.me | cut -d '%' -f1)
    echo -e "\nYour Public IP is: " ${RED}$pubIP${RESET}
    intIP=$(ip -o -4 addr list | awk ' {print $4}' | cut -d/ -f1)
    echo -e "\nYour Internal IP(s) are: " ${RED}$intIP${RESET}
    read -p "Press Enter to continue"
}

######################## Help
#help message
help(){
	echo "Usage: ./aio-enum.sh [-][1|2|3|4|5|6|h|v]"
	echo "Options: "
	echo "-1| --default) Identify Alive IPs and Ports"
	echo "-2| --quick)   Portscan hosts replying to ICMP"
	echo "-3| --scans)   Masscan, Nmap and Nmap NSE scripts"
	echo "-4| --all)     Masscan, Nmap, Nmap NSE scripts and Web dir/page enum"
	echo "-5| --nmap)    Nmap and NSE scripts - No masscan"
	echo "-6| --icmp)    Nmap pingSweep only"
	echo "-7| --csv)     Nmap XML to CSV"
	echo "-h| --help)    Print this help"
	echo "-v| --version) Print version and exit"
}

# Transform long options to short ones (getopts wont parse)
for arg in "$@"; do
    shift
    case "$arg" in
      "--help") set -- "$@" "-h" ;;
      "--default") set -- "$@" "-1" ;;
      "--quick") set -- "$@" "-2" ;;
      "--scans") set -- "$@" "-3" ;;
      "--all") set -- "$@" "-4" ;;
      "--nmap") set -- "$@" "-5" ;;
      "--icmp") set -- "$@" "-6" ;;
      "--csv") set -- "$@" "-7" ;;
      "--version") set -- "$@" "-v" ;;
      *)        set -- "$@" "$arg"
    esac
done

#OPTIND=1 
# getopts to parse options
while getopts ":h1234567v" flag; do
    case "${flag}" in
	h) #display help
	    help
	    exit;;
	1)  echo "[1] selected, running a PingSweep and Portscan on all targets"
	    ipChecker
	    nmapSettings
	    masscanResolver
	    massscanPortScan
	    pingSweep
	    nmapAllHostsPortScan
	    combiner
	    parser
	    summary;;
	2)  echo "[2] selected, running Portscans on hosts that reply to ICMP"
            ipChecker
	    nmapSettings
	    masscanResolver
            massscanPortScan
            pingSweep
            nmapPortScan
            combiner
            parser
            summary;;
	3)  echo "[3] selected, running -- Masscan|Nmap|NSEs"
	    ipChecker
	    nmapSettings
	    masscanResolver
	    massscanPortScan
	    pingSweep
	    nmapPortScan
	    combiner
	    parser
	    nse
	    otherScans
	    summary;;
	4)  echo "[4] selected, running -- Masscan | Nmap | NSEs | Dictionary attacks!"
	    ipChecker
	    nmapSettings
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
	5)  echo "[5] selected, running -- Nmap|NSEs"
	    ipChecker
	    nmapSettings
	    pingSweep
	    nmapPortScan
	    combiner
	    parser
	    nse
	    otherScans
	    summary;;
	6)  echo "[6] nmap pingsweep only"
	    ipChecker
	    pingSweep
	    summaryPingSweep;;
	7)  echo "[7] Nmap to CSV"
	    csvParser;;
	v)  echo "version 1.2"
	    exit;;
	*)  echo -e "Error: Invalid option\n"
	    echo "Usage: ./aio-enum.sh [-h | --help]"
	    exit 1;;
    esac
done
#shift $(expr $OPTIND - 1)

if [ "$#" == "0" ]; then
	echo -e "\n[+] No options provided!"
	echo -e "Executing ICMP pingsweep & portscan..."
	ipChecker
	MINHOST=50
	MINRATE=500
	PORTRANGE=1-65535
	pingSweep
	summaryPingSweep
	nmapPortScan
	summary
fi
