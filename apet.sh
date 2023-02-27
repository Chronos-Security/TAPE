#!/bin/bash



#######################  Install applications  #########################
# sudo apt install seclists impacket ldapsearch
########################################################################



#########################  Define variables  ########################### 
# define IP to be used *in script* 
IP="$2"
URL="http://$IP"

# define IP and URL *in terminal*
ip="export IP=$IP; export URL=http://$IP"

# create files and directories
files="mkdir recon vulns files; touch users.txt passwords.txt hashes.txt creds.txt recon/nmap.init recon/nmap.alltcp recon/ports "

# reconnaisance
# other options for enumeration - in arguments
nmap_full_1="nmap -Pn -p- -v -T4 --max-retries 5 \$IP -oN recon/nmap.init"
nmap_full_2="cat recon/nmap.init | grep "open" | cut -d"/" -f1 | tr '\n' ',' | sed 's/.$//g' > recon/ports"
nmap_vuln="nmap -Pn -sC -sV -v -A -T4 -p- --max-retries 5 --open \$IP -oN recon/nmap.vuln"
nmap_udp="nmap -sU -sV -sC -n -F -T4 \$IP -oN recon/nmap.udp"

# ftp
ftp_nmap="nmap --script=*ftp* -p21 \$IP -oN recon/ftp"

# web 
wfuzz_dirs="wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --hc 404 -f recon/wfuzz-dirs.out \$URL/FUZZ/"
wfuzz_files="wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --hc 404 -f recon/wfuzz-files.out \$URL/FUZZ"
nikto_scan="nikto --host \$URL -C all -o recon/nikto.txt"

# rpccbind
rpcbind_info="rpcinfo \$IP"

# msrpc
msrpc_nmap="nmap -sV -script msrpc-enum -Pn \$IP -oN recon/msrpc"
msrpc_endpoints="impacket-rpcdump \$IP"
msrpc_samr="impacket-samrdump \$IP"
msrpc_client="rpcclient -U "" -N \$IP"

# netBIOS
netbios_nmap="sudo nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n \$IP -oN recon/nbtstat"
netbios_name="nmblookup -A \$IP"
netbios_scan="nbtscan -v \$IP"

# SMB
smb_enumlinux="enum4linux -aA \$IP"
smb_map="smbmap -H \$IP -r"
smb_client="smbclient -N -L \\\\\$IP"

# LDAP
ldap_nmap="nmap -n -sV --script 'ldap* and not brute' \$IP -oN recon/ldap"

# NFS
nfs_shares="showmount -e \$IP"
# modify in diagram 
nfs_nmap="nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount \$IP -oN recon/nfs"

# mysql
mysql_nmap="nmap -sV -Pn -T4 -vv -script=mysql* \$IP -p 3306 -oN recon/mysql"
########################################################################




##########################  User arguments  ############################
# define function to display the commands
function display_commands {
	echo """These are the commands:
	ftp: 		$ftp_nmap
 
	http: 		$wfuzz_dirs
  			$wfuzz_files
  			$nikto_scan
  
	rpcbind: 	$rpcbind_info

	msrpc:		$msrpc_nmap
			$msrpc_endpoints
			$msrpc_samr
			$msrpc_client

	netbios:	$netbios_nmap
			$netbios_name
			$netbios_scan

	smb:		$smb_enumlinux
			$smb_map
			$smb_client

	ldap:		$ldap_nmap

	nfs:		$nfs_shares
			$nfs_nmap

	mysql:		$mysql_nmap
	"""
}

# define function to display the help menu
function display_help {
  echo "Usage: $0 [OPTIONS] -H argument"
  echo ""
  echo "OPTIONS:"
  echo "  -h, --help         	 	Display help menu"
  echo "  -c, --commands         	Display commands"
  echo "  -H, --host argument		Provide an argument (domain or IP address)"
  echo ""
  echo "Examples:"
  echo "  $0 -H example.com"
  echo "  $0 -H 127.0.0.1"
}

# initialize flags
help_menu=false
commands=false
arg=""

# process arguments
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    -h|--help)
      help_menu=true
      shift
      ;;
    -c|--commands)
      commands=true
      shift
      ;;
    -H|--host)
      arg="$2"
      shift
      shift
      ;;
    *)
      echo "Invalid option: $key"
      exit 1
      ;;
  esac
done

# display help menu if -h flag is set
if [ "$help_menu" = true ]; then
  display_help
  exit 0
fi

# display commands if -c flag is set
if [ "$commands" = true ]; then
  display_commands
  exit 0
fi

# check if argument was provided for -H flag
if [ -z "$arg" ]; then
  echo "No argument provided for \"-H\" flag"
  echo
  display_help
  exit 1
fi

# process argument if -H flag is set
if [[ $arg =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "Argument provided is an IP address: $arg"
elif [[ $arg =~ ([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+ ]]; then
    echo "Argument provided is a domain: $arg"
else
    echo "Invalid argument: $arg"
    exit 1
fi
########################################################################




########################  Define pane movement  ########################
vert_split="xdotool key Ctrl+Shift+e ; sleep 0.2"
oriz_split="xdotool key Ctrl+Shift+o ; sleep 0.2"
next_pane="xdotool key Shift+CTRL+n ; sleep 0.2"
prev_pane="xdotool key Shift+CTRL+p ; sleep 0.2"
new_tab="xdotool key Ctrl+Shift+t ; sleep 0.2"
########################################################################



##########################  Define functions  ##########################
# automate commands typing
function type_com {
	local arg=$1
	xdotool type "$1"
	sleep 0.3
	xdotool key Return
}

# define pane phases
tab=0
function which_pane {

	if [[ $tab -eq 0 || $tab -eq 4 ]]; then
		tab=0
		# create tab
		eval $new_tab 
		eval $type_ip
		tab=$(($tab+1))
	elif [[ $tab -eq 1 ]]; then
		# vert oriz
		eval $vert_split
		eval $type_ip
		tab=$(($tab+1))
	elif [[ $tab -eq 2 ]]; then
		# oriz split
		eval $oriz_split
		eval $type_ip
		tab=$(($tab+1))
	elif [[ $tab -eq 3 ]]; then
		# oriz split
		eval $next_pane
		eval $oriz_split
		eval $type_ip
		tab=$(($tab+1))
	fi
}

# enumeration with different tools based on nmap output
function case_type {
	cat recon/nmap.init | grep 'open' | while read -r line; do
	port=$(echo $line | cut -d"/" -f1)
	protocol=$(echo $line | cut -d" " -f3)
	# echo $port : $protocol
	case $protocol in
	 	*"ftp"* )
			which_pane
	 		type_com "$ftp_nmap"	
	 		;;
	 	*"http"* )
			which_pane
			type_com "URL=http://$IP:$port"
			type_com "$wfuzz_dirs"
			
			which_pane
			type_com "URL=http://$IP:$port"
			type_com "$wfuzz_files"
			
			which_pane
			type_com "URL=http://$IP:$port"
			type_com "$nikto_scan"
			;;
		"rpcbind"* )
			which_pane
			type_com "$rpcbind_info"
			;;
		*"msrpc"* )
			which_pane
			type_com "$msrpc_nmap"
			which_pane
			type_com "$msrpc_endpoints"
			which_pane
			type_com "$msrpc_samr"
			which_pane
			type_com "$msrpc_client"
			;;
		*"netbios"* )
			which_pane
			type_com "$netbios_nmap"
			which_pane
			type_com "$netbios_name"
			which_pane
			type_com "$netbios_scan"
			which_pane
			type_com "$smb_enumlinux"
			which_pane
			type_com "$smb_map"
			which_pane
			type_com "$smb_client"
			;;
		*"ldap"* )
			which_pane
			type_com "$ldap_nmap"
			;;
		*"nfs"* )	
			which_pane
			type_com "$nfs_shares"
			which_pane
			type_com "$nfs_nmap"
			;;
		*"mysql"* )
			which_pane
			type_com "$mysql_nmap"
			;;
	esac 
	done
}
########################################################################



######################  Start enumeration process ######################
# start a new Terminator window
terminator &
sleep 0.3

# maximize terminal on screen
xdotool key --clearmodifiers Super+Up

# initial part of the enumeration
type_com "$ip"
type_com "$files"
type_com "clear"
type_com "$nmap_full_1"

# check if the first nmap scan has finished so we can start the full enumeration
while true; do
	if [[ `grep PORT recon/nmap.init` ]]; then
		
		# if the full nmap scan is done, then continue with enumeration
		if [[ `grep PORT recon/nmap.alltcp` ]]; then
			case_type
			break
		fi

		# start second nmap scan
		type_com "$nmap_full_2"

		# prepare the final nmap command
		ports=`cat recon/ports`
		sleep 0.5
		nmap_full_3="nmap -Pn -sC -sV -n -v -A -T4 -p $ports $IP -oN recon/nmap.alltcp"
		type_com "$nmap_full_3"
	fi
	sleep 2

done


#########################  THINGS TO BE ADDED  #########################
# nmap vuln and UDP scan
# more error handling 
# message with what ports haven't been enumerated
########################################################################
