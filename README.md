# What is this? 
Another Pen Testing Enumeration Tool!

AIO-Enum combines multiple tools to automate the majority of enumeration that is commonly performed on network security assessments & penetration tests.  

**Enumeration:** - It starts by identifying hosts it can interact with using `nmap` & `masscan`, and then enumerates ports and services that are open. For example, if port 21 is open, it will now perform checks for `ftp anonymous login` & `ftp version info` on applicable hosts.  
**Summary:** - After the script ends, it provides information on alive hosts and ports. Providing `CSV` and `HTML` output.

---

- [1. Installation](#1-installation)
- [2. Usage](#2-usage)
- [3. Scan Details](#3-scan-details)

---

## 1. Installation

### Prerequisites
This script utilizes the following tools and will not run unless they are installed.  
If it cannot detect a tool is installed, it will notify you what is missing.
``` 
masscan
dig
curl
nmap
ike-scan
nbtscan
dirb
hping3
xsltproc
```
### Setup
```
# First run `aio_enum.py`
sudo python3 aio_enum.py --help
```
```
# Next populate the `targets.ip` file
echo "192.168.100.0/24" >> targets.ip
```
The list of targets should each be on a new line as such:  
```
x.x.x.x  
y.y.y.y/32  
domain  
```

If you have a list of targets in comma separated lists, paste them into `targets.ip` and then run the below to remove the commas and put each IP onto a new line:  
`cat targets.ip| tr ',' '\n' | tr -d "^ " | tee targets.ip`

```
# Next populate the `exclude.ip` file
echo "192.168.100.5" >> exclude.ip
```

## 2. Usage
By default, **aio_enum.py** will scan **ALL TCP** ports and UDP ports `53,69,123,161,500,1434`.
Run the following to view the available options:
```
python3 aio_enum.py -h
```
```
usage: python aio_enum.py [options]

Python rewrite of AIO-Enum

options:
  -h, --help            show this help message and exit
  -1, --default         Identify Alive IPs and Ports
  -2, --quick           Portscan hosts replying to ICMP
  -3, --scans           Masscan, Nmap and Nmap NSE scripts
  -4, --all             Masscan, Nmap, Nmap NSE scripts and Web dir/page enum
  -5, --nmap            Nmap and NSE scripts - No masscan
  -6, --icmp            Nmap ping sweep only
  -v, --version         Print version and exit
  --tcpportrange TCPPORTRANGE
                        TCP port range in nmap format
  --top100              Top 100 most common TCP Ports
  --top1000             Top 1000 most common TCP Ports
  --udpportrange UDPPORTRANGE
                        UDP port range in nmap format
  --nmap-minhost NMAP_MINHOST
                        Minimum hostgroup size for nmap
  --nmap-minrate NMAP_MINRATE
                        Minimum rate for nmap
  --masscan-maxrate MASSCAN_MAXRATE
                        Maximum rate for masscan
  --masscan-interface MASSCAN_INTERFACE
                        Network interface that masscan should use
  --outputdir OUTPUTDIR
                        Output directory for all files
  --nessus-file NESSUS_FILE
                        Path to a Nessus report for correlation
  --allow-unsafe-nse    Enable intrusive NSE script allowlist
  --validate-services   Run extended service validation and enumeration tasks

```


## 3. Scan Details
All options that utilise nmap portscan functionality will finish with a CSV and HTML file being accessible.
All options will provide a summary on the number of alive IP addresses and unique ports that are open.
|              Option | Usage            | Detail                           |
|---------------------|-------------------|-----------------------------------------|
|  1  | Alive IPs and Port Enumeration  |  `masscan` and `nmap` are used to perform a pingsweep and portscan. Both tools are parsed to display the no. of Alive IP addresses and no. of open ports. **No further probing of open ports is performed!**|
|  2 | Quick IP scan                   |  This will use `masscan`, performing a dns resolution and completing a port scan. It will then run `nmap`, performing a pingsweep and port scan against the hosts that replied to ICMP only! |
|  3 | Default Scan    |  IP and Port enumeration followed by running `nmap` NSE scripts to search for vulnerabilities. |
|  4 | All                 |  This performs the same as the above option, but also allows for brute force and dictionary attacks. For example, port 80 being open will utilize `dirb` to enumerate active directories/pages based off of a word list |
|  5 | Nmap & NSE Scripts              |  `Nmap` ping sweep + port scan and finishes with NSE scripts. No dictionary attacks. |
|  6 | Nmap pingsweep                  |  `Nmap` pingsweep only |

