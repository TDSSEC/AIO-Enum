#!/bin/bash

# written by tdssec

RED="\033[01;31m"
GREEN="\033[01;32m"
YELLOW="\033[01;33m"
BLUE="\033[01;34m"
BOLD="\033[01;01m"
RESET="\033[00m"

# defaults
TCPPORTRANGE=1-65535
UDPPORTRANGE=53,69,123,161,500,1434
MINRATE=200
MINHOST=50
MAXRATE=500
SCANTYPE=help
TOOLSINSTALLED=1
OUTPUTDIR="$(pwd)/$(date +'%Y-%m-%d-%H:%M')"

# Sources
SCRIPTDIR=$(dirname "$0")
source "$SCRIPTDIR/getopts-long.sh"

#-- check for root or exit
if [ $EUID != 0 ]
then
    echo -e "\n[${RED}!${RESET}] must be ${RED}root${RESET}"
    exit 1
fi

declare -a tools=("masscan" "dig" "curl" "nmap" "ike-scan" "nbtscan" "wfuzz" "xsltproc")

# check all prerequisite tools are installed, or quit
for tool in ${tools[*]}
do
    #echo ${tool[*]}
    if ! which "$tool" > /dev/null
    then
	    echo -e "\n[${RED}!${RESET}] $tool ${RED}not${RESET} found"
	    TOOLSINSTALLED=0
    fi
done
if [ $TOOLSINSTALLED != 1 ]
then
	echo -e "\n[${RED}!${RESET}] Ensure the following tools are installed: ${tools[*]}"
	exit 1
fi

setup(){
	# sources
	source "$SCRIPTDIR/nmap-nse-scans.sh"
	source "$SCRIPTDIR/discovery-scans.sh"
	source "$SCRIPTDIR/parsers.sh"

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
		if [ ! -d "$OUTPUTDIR/$folder" ]
		then
			mkdir -p "$OUTPUTDIR/$folder"
		fi
	done

	# Check targets.ip isn't empty
	if [ ! -s targets.ip ]
	then
		echo -e "\n [${RED}!${RESET}] targets.ip file isn't populated with target IP addresses"
		exit 1
	fi
}

# Your IP Address
ipChecker(){
    echo -e "\n ${RED}[!] ENSURE YOU ARE SOURCING FROM AN INSCOPE IP" ${RESET}
    pubIP=$(curl -s https://ifconfig.me | cut -d '%' -f1)
    echo -e "\nYour Public IP is: " ${RED}$pubIP${RESET}
    intIP=$(ip -o -4 addr list | grep -v '127.0.0.1'| awk ' {print $4}' | cut -d/ -f1)
    echo -e "\nYour Internal IP(s) are: " ${RED}$intIP${RESET}
	echo -e "\n ${RED}[!] Ctrl+c${RESET} now if you do not want to proceed"
	for i in {5..1}
	do
		echo -ne "Continuing in ${RED}$i${RESET}\033[0K\r"
		sleep 1
	done
}

######################## Help
#help message
help(){
	echo "Usage: ./aio-enum.sh [-1 | --default]"
	echo "Options: "
	echo "-1| --default) Identify Alive IPs and Ports"
	echo "-2| --quick)   Portscan hosts replying to ICMP"
	echo "-3| --scans)   Masscan, Nmap and Nmap NSE scripts"
	echo "-4| --all)     Masscan, Nmap, Nmap NSE scripts and Web dir/page enum"
	echo "-5| --nmap)    Nmap and NSE scripts - No masscan"
	echo "-6| --icmp)    Nmap pingSweep only"
	echo "-h| --help)    Print this help"
	echo "-v| --version) Print version and exit"
	echo -e "\nOptional Arguments: "
	echo "--tcpportrange)      TCP Ports for scanning in nmap format, e.g. 1-1024,8080,8443. *Default is all ports"
	echo "--udpportrange)      UDP ports for scanning in nmap format, e.g. 161,500. *Default is 53,69,123,161,500,1434"
	echo "--nmap-minhost)      Minimum hostgroup size for nmap. *Default value is 50"
	echo "--nmap-minrate)      Minimum rate for nmap. *Default value is 200"
	echo "--masscan-maxrate)   Maximum rate for masscan. *Default value is 500"
	echo "--masscan-interface) Network interface that masscan should use"
	echo "--outputdir)         Output directory for all files"
}

declare -A longopts=([help]='' [default]='' [quick]='' [scans]='' [all]='' [nmap]='' [icmp]='' [version]='' [tcpportrange]=: [udpportrange]=: [nmap-minhost]=: [nmap-minrate]=: [masscan-maxrate]=: [masscan-interface]=: [outputdir]=:)
while getopts_long longopts h1234567v opt "$@"; do
    case "$opt" in
	    help|h)
		    SCANTYPE=help;;
		tcpportrange)
			TCPPORTRANGE=$OPTARG;;
		udpportrange)
			UDPPORTRANGE=$OPTARG;;
		nmap-minhost)
			MINHOST=$OPTARG;;
		nmap-minrate)
			MINRATE=$OPTARG;;
		masscan-maxrate)
			MAXRATE=$OPTARG;;
		masscan-interface)
			MASSCANINTERFACE=$OPTARG;;
		outputdir)
			OUTPUTDIR=$OPTARG;;
		default|1)
			echo "[1] selected, running a PingSweep and Portscan on all targets"
			SCANTYPE=default;;
		quick|2)
			echo "[2] selected, running Portscans on hosts that reply to ICMP"
			SCANTYPE=quick;;
		scans|3)
			echo "[3] selected, running -- Masscan|Nmap|NSEs"
			SCANTYPE=scans;;
		all|4)
			echo "[4] selected, running -- Masscan | Nmap | NSEs | Dictionary attacks!"
			SCANTYPE=all;;
		nmap|5)
			echo "[5] selected, running -- Nmap|NSEs"
			SCANTYPE=nmap;;
		icmp|6)
			echo "[6] nmap pingsweep only"
			SCANTYPE=icmp;;
		version|v)
			echo "version 1.3"
		    exit;;
		*)
			echo -e "Error: Invalid option\n"
	    	echo "Usage: ./aio-enum.sh [-h | --help]"
	    	exit 1;;
    esac
done

case $SCANTYPE in
	help)
		help
		exit;;
	default)
		setup
		ipChecker
		nmapSettings
		massscanPortScan
		pingSweep
		nmapFastPortScan
		combiner
		parser
		summary
		csvParser
		htmlParser;;
	quick)
		setup
		ipChecker
		nmapSettings
		massscanPortScan
		pingSweep
		nmapPortScan
		combiner
#		parser
		summary
		csvParser
		htmlParser;;
	scans)
		setup
		ipChecker
		nmapSettings
		massscanPortScan
		pingSweep
		nmapPortScan
		combiner
		parser
		nse
		otherScans
		summary
		csvParser
		htmlParser;;
	all)
		setup
		ipChecker
		nmapSettings
		massscanPortScan
		pingSweep
		nmapPortScan
		combiner
		parser
		nse
		otherScans
		discoveryScans # for dictionary attacks
		summary
		csvParser
		htmlParser;;
	nmap)
		setup
		ipChecker
		nmapSettings
		pingSweep
		nmapPortScan
		combiner
		parser
		nse
		otherScans
		summary
		csvParser
		htmlParser;;
	icmp)
		setup
		ipChecker
		pingSweep
		summaryPingSweep;;
esac

if [ "$#" == "0" ]; then
	echo -e "\n[+] No options provided!"
	help
fi
