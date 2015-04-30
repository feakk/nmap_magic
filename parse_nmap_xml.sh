#!/bin/bash
# Parses NMAP XML output into TSV format and performs some useful post-analysis
# By: Paul <dot> J <dot> Haas <at> gmail <dot> com under a GPLv3 Public License
# This script should not be used for DNS identification via nmap/commands execution. It should use the results if they are handy however
# TODO: scan coverage, list which scripts have been run, generate some nmap run lines
# Need to figure out default port list, fast list, how to expand ranges and merge stuff
# TODO: Deal with OS detection output lines & CPE details
# TODO: http://nmap.org/book/output-formats-output-to-html.html processing XML to HTML xsltproc nmap-output.xml -o nmap-output.html ; java -jar saxon9.jar -s:nmap-output.xml -o:nmap-output.html ; java -jar xalan.jar -IN nmap-output.xml -OUT nmap-output.html
# TODO: Improve script processing, eliminating bad and non-relevant output.
# TODO: change service?/tcpwrapped to unknown or blank. Change ssl/service? to ssl/unknown. If we have service and service? but no output after, it is likely that it should be unknown as well
# TODO Address UNIFY slowdown using 'join': http://stackoverflow.com/questions/2619562/joining-multiple-fields-using-unix-join
# replace xmlstarlet (which is showing it's age and is buggy every update) with xidel
# May be worth recreating my XML to SQL perl script.

# Scan times: xmlstarlet sel -T -t -m //host -v "address[@addrtype='ipv4']/@addr" -o ',' -v @starttime -o ',' -v @endtime -n *.xml | awk -F',' -v OFS=',' '{print $1,strftime("%c",$2),strftime("%c",$3)}'

# SCRIPT directory and directory which the SCRIPT are run can be different
SCRIPT=$(realpath $0)
SCRIPTPATH=$(dirname $SCRIPT)
RUNDIR=$(pwd -P)

# Necessary to match/output these characters manually in newer versions of xmlstarlet
TAB=$'\t'
NEWLINE=$'\n'
CR=$'\r'

OUTDIR=${1-'out'}
OUTPUT="$OUTDIR/statistics.txt"
OSDIR="$OUTDIR/OS"
PORTDIR="$OUTDIR/PORT"
TMPDIR="$OUTDIR/tmp"
MVDIR="$OUTDIR/scans"
UNIFY=0 # 0 to skip unification, any other value = unify nmap output
# Determine if we automatically run MSF on nmap results
RUN_MSF=0 # 0 to skip, any other value = run
OUTDIR2="$OUTDIR/msf_scan"
VULN="$OUTDIR/nmap.tsv"
THREADS=4 # Used to run msfcli instances concurrently for auxillary modules
mkdir "$OUTDIR" "$PORTDIR" "$OSDIR" "$TMPDIR" "$MVDIR" $OUTDIR2 2>/dev/null

TSV=$OUTDIR/nmap.tsv
SIN=$OUTDIR/nmap_single.tsv

# Update to correct location of Metasploit
MSFCONSOLE=$(realpath `which msfconsole` 2>/dev/null)
MSFDIR=$(dirname $MSFCONSOLE)
if [ -z "$MSFDIR" ]; then 
	MSFDIR="/pentest/exploits/framework" # Kali's Metasploit framework directory
	echo "# Cannot find Metasploit directory in path, assuming Kali: $MSFDIR"
fi

# Use xmlstarlet present in script directory if it exists. Local copy isn't as reliable (we may not be in our script directory)
if [ -e $SCRIPTPATH/xmlstarlet ]; then 
	PATH=$SCRIPTPATH:$PATH; 
	echo "# Using local xmlstarlet version present in $SCRIPTPATH"
	#which xmlstarlet; xmlstarlet --version
	fi
#if [ -e ./xmlstarlet ]; then PATH=.:$PATH; fi

# Single dependency is xmlstarlet
if ! which 'xmlstarlet' >/dev/null; then 
	echo "# Run apt-get install xmlstarlet or GUI equivalent."
	exit 1 
#else
	# Later verions of xmlstarlet no longer accept XML encoded entities, making certain things very difficult
	#echo "# Since 1.0.3, xmlstarlet -o takes its argument literally (to address a bug)"
	# This means we have to pass character like tab and newline literally, which requires bash variables which requires double quote encapsulation
	#xmlstarlet --version
	#xml --version
fi

FILECOUNT=$(ls -1 *.xml 2>/dev/null | wc -l)
if [[ $FILECOUNT == 0 ]]
then 
  echo "Process NMAP xml files"
  echo "Usage: $0 {outdir='out'} : Place any number of NMAP *.xml files in the directory and rerun"
  exit 1
fi 

echo "# Processing all NMAP xml files in current directory into '$OUTDIR':"
# Disable failed to load external entity "https://svn.nmap.org/nmap/docs/nmap.dtd" of newer xmlstarlet versions
ls *.xml
# Move invalid XML files to another directory
for i in *.xml; do
	if ! xmlstarlet val "$i" >/dev/null; then
		echo "# "$i" is not a valid XML file, moving to invalid directory"
		mkdir "invalid" 2>/dev/null
		mv $i "invalid"
	fi
done
# Fix xmlstarlet being a bitch
for i in *.xml; do
	sed -i 's#https://svn.nmap.org/nmap/docs/nmap.dtd#nmap.dtd#g' "$i"
done

#xmlstarlet sel -T -t -m "//state[@state='open']" -m ../../.. -v address/@addr -o "&#09;" -v hostnames/hostname/@name -o "&#09;" -v os/osmatch/@name -o "&#09;" -b -m .. -v @portid -o '/' -v @protocol -o "&#09;" -m service -i  "@tunnel" -v @tunnel -o "|" -b -v @name -o "&#09;" -v @product -o ' ' -v @version -v @extrainfo -o "&#09;" -m ../script  -v @id -o "=&quot;" -v "translate(@output,'&#xA;&quot;&#xD;','&#x20;&#x20;&#x20;')" -o "&quot; " -b -n -b -b -n -b -b *.xml | grep -v '^$' | sed 's/ *$//' | tr '"' "'" | awk -F'\t' '{ sub(/[,;][^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | awk -F'\t' '{ sub(/ or [^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | sed 's# See http://nmap.org/nsedoc/scripts/http-methods.html##;s/\tssl|\([^\t]*\)/\t\1s/;s/\thttpss\t/\thttps\t/' | sort -uV | sed "1i\\#IP\tHostname\tOS\tPort\tService\t\tVersion\tDetail" > $OUTDIR/nmap.tsv
#xmlstarlet sel -T -t -m "//state[@state='open']" -m ../../.. -v address/@addr -o "$TAB" -v hostnames/hostname[1]/@name -o "$TAB" -v os/osmatch[1]/@name -o "$TAB" -b -m .. -v @portid -o '/' -v @protocol -o "$TAB" -m service -i  "@tunnel" -v @tunnel -o "|" -b -v @name -o "$TAB" -v @product -o ' ' -v @version -v @extrainfo -o "$TAB" -m ../script  -v @id -o "='" -v "translate(@output,'${NEWLINE}\"${CR}','   ')" -o "' " -b -n -b -b -n -b -b *.xml | grep -v '^$' | sed 's/ *$//' | tr '"' "'" | sed "s/' */'/g" | awk -F'\t' '{ sub(/[,;][^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | awk -F'\t' '{ sub(/ or [^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | sed 's# See http://nmap.org/nsedoc/scripts/http-methods.html##;s/\tssl|\([^\t]*\)/\t\1s/;s/\thttpss\t/\thttps\t/' | sort -uV > $OUTDIR/nmap.tsv
# TODO: address/@addr is giving me MAC addresses, use "address[@addrtype='ipv4']/@addr" instead

# TODO: Consider pulling out script id and just putting @id names in instead. That way, our tsv output is managable and script info can be referenced below instead
#xmlstarlet sel --net -T -t -m "//state[@state='open']" -m ../../.. -v "address[@addrtype='ipv4']/@addr" -o "$TAB" -v hostnames/hostname[1]/@name -o "$TAB" -v os/osmatch[1]/@name -o "$TAB" -b -m .. -v @portid -o '/' -v @protocol -o "$TAB" -m service -i  "@tunnel" -v @tunnel -o "|" -b -v @name -o "$TAB" -v @product -o ' ' -v @version -v @extrainfo -o "$TAB" -m ../script  -v @id -o "='" -v "translate(@output,'${NEWLINE}\"${CR}','   ')" -o "' " -b -n -b -b -n -b -b *.xml | grep -v '^$' | sed 's/ *$//' | sed "s/' */'/g" | awk -F'\t' '{ sub(/[,;][^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | awk -F'\t' '{ sub(/ or [^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | sed "s# See http://nmap.org/nsedoc/scripts/http-methods.html##;s/\tssl|\([^\t]*\)/\t\1s/;s/\thttpss\t/\thttps\t/;s/doesn't/does not/g" | sort -uV > $OUTDIR/nmap.tsv
# TODO: This will need a lot of cleanup to address NOT having to clean up script output, so removing all the post processing
xmlstarlet sel --net -T -t -m "//state[@state='open']" -m ../../.. -v "address[@addrtype='ipv4']/@addr" -o "$TAB" -v hostnames/hostname[1]/@name -o "$TAB" -v os/osmatch[1]/@name -o "$TAB" -b -m .. -v @portid -o '/' -v @protocol -o "$TAB" -m service -i  "@tunnel" -v @tunnel -o "|" -b -v @name -o "$TAB" -v @product -o ' ' -v @version -v @extrainfo -o "$TAB" -m ../script  -v @id -o ',' -b -n -b -b -n -b -b *.xml | grep -v '^$' | sed 's/ *$//;s/,*$//' | sed "s/' */'/g" | awk -F'\t' '{ sub(/[,;][^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | awk -F'\t' '{ sub(/ or [^()]*/,"",$3);for (i=1; i<NF; i++){printf "%s%s",$i,FS};printf "%s\n",$i}' | sed "s/\tssl|\([^\t]*\)/\t\1s/;s/\thttpss\t/\thttps\t/" | sort -uV > $OUTDIR/nmap.tsv

# | sed "1s~\(.*\)~#IP\tHostname\tOS\tPort\tService\t\tVersion\tDetail\n\1~"

# TODO: Handle ERROR: Script execution failed (use -d to debug)
# Handle script output in another fashion than CSV format. 
# There are 3 types of script: global (pre/postscript), host-based, post-based
# This handles them all first into TSV to sort -uV, then into a text format sorted by both IP and by script name
# tsv files are being cat somewhere below to deal with hostname stuff I believe
xmlstarlet sel --net -T -t -m "nmaprun/postscript/script" -o "network " -v @id -o "$TAB" -v "translate(@output,'${NEWLINE}','${TAB}')" -n -b *.xml | cat -s > "$OUTDIR/nmap_scripts.out"
xmlstarlet sel --net -T -t -m "nmaprun/host/hostscript/script" -i "../../address[@addrtype='ipv4']" -v "../../address[@addrtype='ipv4']/@addr" -o " " -v @id -o "$TAB" -v "translate(@output,'${NEWLINE}','${TAB}')" -n -b *.xml | cat -s >> "$OUTDIR/nmap_scripts.out"
xmlstarlet sel --net -T -t -m "nmaprun/host/ports/port/script" -v "../../../address[@addrtype='ipv4']/@addr" -o ':' -v ../@portid -o " " -v @id -o "$TAB" -v "translate(@output,'${NEWLINE}','${TAB}')" -n -b *.xml | cat -s >> "$OUTDIR/nmap_scripts.out"
grep $'\t' "$OUTDIR/nmap_scripts.out" | cut -f1 | cut -d' ' -f2 | sort | uniq -c | sort -nr | sed 's/^ *//;s/ /\t/' > "$OUTDIR/nmap_scripts.list"
#sort -uV "$OUTDIR/nmap_scripts.out" | sed 's#$#\n#;s#\t\+#\n#g' | cat -s > "$OUTDIR/nmap_ip_scripts.txt"
sort -uV "$OUTDIR/nmap_scripts.out" | sort -t' ' -k2,2 | sed 's#$#\n#;s#\t\+#\n#g' | cat -s > "$OUTDIR/nmap_scripts.txt"
grep -i conficker "$OUTDIR/nmap_scripts.out" | grep -v '0/4' > "$OUTDIR/conflicker_status.txt"

# Grab Hostnames
xmlstarlet sel -T -t -m nmaprun/host -v "address[@addrtype='ipv4']/@addr" -o "$TAB" -m hostnames/hostname/@name -v . -o ',' -b -n *.xml | sed 's/,$//' | sort -uV > $OUTDIR/dns.tsv
#xmlstarlet sel -T -t -m nmaprun/host -v address/@addr -o "$TAB" -v ".//table[@key='subject']/elem[@key='commonName']" -n hostnames.xml | sort -uV > $OUTDIR/ssl.tsv
# TODO: Address bad CN values in ssl.tsv by requring a period in the hostname (this will eliminate some internal hostnames values)
xmlstarlet sel -T -t -m "//script[@id='ssl-cert']" -v "../../../address[@addrtype='ipv4']/@addr" -o "$TAB" -v ".//table[@key='subject']/elem[@key='commonName']" -n *.xml | awk '$2 ~ /\./ {print}' | sort -uV > $OUTDIR/ssl.tsv

# Need to split and then parse certs.txt for altNames
# Of course, could be multiple ports per host
#xmlstarlet sel -T -t -m nmaprun/host -i ".//script[@id='ssl-cert']" -v address/@addr -o "$NEWLINE" -v ".//elem[@key='pem']" -n -b *.xml > $OUTDIR/sslcerts.txt
xmlstarlet sel -T -t -m "//script[@id='ssl-cert']" -v "../../../address[@addrtype='ipv4']/@addr" -o "$NEWLINE" -v "./elem[@key='pem']" -n *.xml > $OUTDIR/sslcerts.txt
csplit -f "$TMPDIR/cert" -s "$OUTDIR/sslcerts.txt" "/^$/" '{*}'
for i in $TMPDIR/cert*; do
	sed -i '/^$/d' "$i"
	IP=$(head -n1 "$i")
	if [ -z "$IP" ]; then break; fi
	#echo "# Processing SSL Alternative names for $IP in $i"
	#CN=$(openssl x509 -in "$i" -noout -subject | grep -o "CN=[^ /]*" | tr -d ' ' | cut -d'=' -f2)
	#echo -ne "$IP\t$CN\n" >> cn.tsv
	ALT=$(openssl x509 -in "$i" -noout -text -certopt no_subject,no_header,no_version,no_serial,no_signame,no_validity,no_issuer,no_pubkey,no_sigdump,no_aux -nameopt oneline,-esc_msb | grep -o "DNS:[^, ]*" | cut -d":" -f2 | sort -uV | awk 'NR==1{x=$0;next}NF{x=x","$0}END{print x}') # | sed 's#\t\*\.#\t#'
	echo -ne "$IP\t$ALT\n" >> "$OUTDIR/altname.tsv"
done
rm -rf $TMPDIR

# Combine all tsv files for hostnames (removing blank lines and wildchard names, as these are not really hostnames per say)
# TODO: Taking all tsv files is a bad idea. SSL alt/names while potentially valid should not appear in the hostnames file unless verified
cat "$OUTDIR/dns.tsv" | cut -f1-2 | awk -F'\t' '{n=split($2,array,",");for (i=1;i<=n;i++) {printf "%s\t%s\n",$1,array[i];}}' | sort -uV | grep -v -e '^ *$' -e '\*' | awk -F "\t" '{ a[$1] = a[$1] "\t" $2 } END { for (item in a ) printf "%s%s\n",item,a[item] }' | sed 's#\t#,#g;s#,#\t#' | sort -uV > "$OUTDIR/hostnames.tsv"
#cat $OUTDIR/*.tsv | cut -f1-2 | awk -F'\t' '{n=split($2,array,",");for (i=1;i<=n;i++) {printf "%s\t%s\n",$1,array[i];}}' | sort -uV | grep -v -e '^ *$' -e '\*' | awk -F "\t" '{ a[$1] = a[$1] "\t" $2 } END { for (item in a ) printf "%s%s\n",item,a[item] }' | sed 's#\t#,#g;s#,#\t#' | sort -uV > "$OUTDIR/hostnames.tsv"

# XXX : For now, I'm assuming non-wildcard SSL names are hostnames for purposes of a test.
# TODO: Dealing with wildcard/common SSL certnames: If name resolves to another IP, remove it from the list. If name doesn't resolve, keep it in the list
# cat hostnames.tsv | cut -f2 | tr ',' '\n' | sort -uV | nmap -sL -R -iL - -T4 -oX reverse_lookup.xml
# xmlstarlet sel -T -t -m nmaprun/host -v address/@addr -o "$TAB" -m hostnames/hostname/@name -v . -o ',' -b -n reverse_lookup.xml | sed 's/,$//' | sort -uV | awk -F'\t' '{n=split($2,array,",");for (i=1;i<=n;i++) {printf "%s\t%s\n",$1,array[i];}}' | sort -uV | grep -v -e '^ *$' -e '\*' | awk -F "\t" '{ a[$1] = a[$1] "\t" $2 } END { for (item in a ) printf "%s%s\n",item,a[item] }' | sed 's#\t#,#g;s#,#\t#' | sort -uV > rdns.tsv
# Not sure how to resolve hostname.tsv and rdns.tsv differences
# It is possible for a single hostname to have multiple IP addresses (ie google.com)
# Logic may be more relevant up when dealing with SSL stuff. Extract all SSL Cert info (globally), do a reverse lookup, and only add if relevant
#cat rdns.tsv hostnames.tsv | awk -F'\t' '{n=split($2,array,",");for (i=1;i<=n;i++) {printf "%s\t%s\n",$1,array[i];}}' | awk -F'\t' '{printf "%s\t%s\n",$2,$1}'

cp $OUTDIR/nmap.tsv $OUTDIR/nmap.bak
grep -v '[0-9]*/ip' $OUTDIR/nmap.bak | sed 's#ssl/http\(s\)\?#https#;s#/UDP#/udp#;s#/TCP#/tcp#' > $OUTDIR/nmap.tsv
cut -f1 $OUTDIR/nmap.tsv | grep -v '^#' | sort -uV > $OUTDIR/ips.txt

# TODO: This could be a long long while...
# Unify IP,HOSTNAME,OS INFO,PORT SERVICE/VERSION INFO
if [[ $UNIFY -ne 0 ]]; then
	echo "# Unifying Output, may take a while"
	# TODO: Parallelize this
	while read IP
	do
		# Update all Hostnames and OS for each IP
		HOSTNAMES=$(cat "$OUTDIR/nmap.tsv" "$OUTDIR/hostnames.tsv" | grep "$IP" | cut -f2 | tr ',' '\n' | sort -uV | grep -v '^$' | tr '\n' ',' | sed 's/,$/\n/')
		OS=$(grep "$IP" $OUTDIR/nmap.tsv | cut -f3 | tr ',' '\n' | sort -uV | grep -v '^$' | tr '\n' ',' | sed 's/,$/\n/')
		awk -F '\t' -v "IP=$IP" -v "H=$HOSTNAMES" -v "OS=$OS" '{if ($1==IP){$2=H;$3=OS}}1' OFS='\t' $OUTDIR/nmap.tsv > $OUTDIR/nmap_new.tsv
		sort -uV $OUTDIR/nmap_new.tsv > $OUTDIR/nmap.tsv

		# Update service, version and script information to match the port for each IP
		grep "$IP" $OUTDIR/nmap.tsv | grep -v '/ip' | cut -f4 | sort -uV > $OUTDIR/tmpports.txt
		while read PORT
		do
			SERVICE=$(grep "$IP" $OUTDIR/nmap.tsv | grep "$PORT" | cut -f5 | sort -uV | grep -v -e '^ *$' -e '?' -e 'tcpwrapped' | tr '\n' ',' | sed 's/ *,$/\n/')
			VERSION=$(grep "$IP" $OUTDIR/nmap.tsv | grep "$PORT" | cut -f6 | sort -uV | grep -v -e '^ *$' | tr '\n' ',' | sed 's/ *,$/\n/')
		
			# Take the time to remove some details that would otherwise clog up TSV output, and cause errors below. This issue is mostly due to snmp based scripts
			# snmp-netstat=
			DETAILS=$(grep "$IP" $OUTDIR/nmap.tsv | grep "$PORT" | cut -f7 | sed "s#\([^=]\)'#\1'\n#g" | sort -uV | grep -v '^ *$' | tr -s ' ' | grep -iv -e 'ERROR: Script execution failed' -e 'does not' -e 'Did not follow redirect' -e 'No Allow or Public' -e 'ssl-cert=' -e 'ssl-date=' -e 'SSLv2 supported ciphers' -e 'http-enum=' -e 'http-robots.txt=' -e 'http-methods=' -e 'ssh-hostkey=' -e 'http-server-header.skip' -e 'snmp-[^=]*=' -e 'ftp-anon=' -e 'rpcinfo=' -e 'ntp-info=' -e 'smtp-commands=' | tr '\n' ',' | sed 's/ *,$/\n/')
		
			#Fix: /usr/bin/awk: Argument list too long
			DSIZE=${#DETAILS} 
			# Arguments must be less than MAX_ARG_STRLEN (131072)
			if [ $DSIZE -gt 2000 ]; then
				echo "IP='$IP' PORT='$PORT' SERVICE='$SERVICE' VERSION='$VERSION' DETAILS='$DETAILS'"
				DETAILS=''
			fi
		
			# Update if service is not empty
			if [ ! -z "$SERVICE" ]; then
				awk -F '\t' -v "IP=$IP" -v "PORT=$PORT" -v "SERVICE=$SERVICE" -v "VERSION=$VERSION" -v "DETAILS=$DETAILS" '{if ($1==IP && $4==PORT){$5=SERVICE;$6=VERSION;$7=DETAILS}}1' OFS='\t' $OUTDIR/nmap.tsv | sed 's/\t$//' > $OUTDIR/nmap_new.tsv
				sort -uV $OUTDIR/nmap_new.tsv > $OUTDIR/nmap.tsv
			fi
		done < $OUTDIR/tmpports.txt

	done < $OUTDIR/ips.txt
	rm $OUTDIR/tmpports.txt

	# Final Unification to eliminate lines without extra info if it exists somewhere else
	awk -F'\t' '{x=$1"\t"$2"\t"$3"\t"$4"\t"$5"\t"$6;if (length(a[x])<length($0)){a[x]=$0}} END {for(item in a) print a[item]}' $OUTDIR/nmap.tsv > $OUTDIR/nmap_new.tsv
	sort -uV $OUTDIR/nmap_new.tsv > $OUTDIR/nmap.tsv
	rm $OUTDIR/nmap_new.tsv
fi

# Single Format TSV
cat $OUTDIR/nmap.tsv | grep -v '^#' | cut -f1-5 | sort -uV | sed 's/ *\t/\t/g;s/\t */\t/g' | awk -F '\t' '{ a[$1"\t"$2"\t"$3] = a[$1"\t"$2"\t"$3] "\t" $4 " " $5 } END { for (item in a ) print item, a[item] }' | sort -uV > $OUTDIR/nmap_single.tsv

# Web Services Unified
#xmlstarlet sel -T -t -m "//state[@state='open']" -m "../service[@name='http']" -v @name -i "@tunnel='ssl'" -o 's' -b -o '://' -v ../../../address/@addr -o ':' -v ../@portid -o "&#09;" -v @product -o ' ' -v @version -o ' ' -v @extrainfo -m "../script[@id='http-title']" -o '&#09;&quot;' -v "translate(@output,'&#xA;','&#x20;')" -o '&quot;' -b -n *.xml | sort -uV | awk '{if (length(a[$1])<length($0)){a[$1]=$0}} END {for(item in a) print a[item]}' | sort -uV > $PORTDIR/nmap_web.tsv
xmlstarlet sel -T -t -m "//state[@state='open']" -m "../service[@name='http']" -v @name -i "@tunnel='ssl'" -o 's' -b -o '://' -v "../../../address[@addrtype='ipv4']/@addr" -o ':' -v ../@portid -o "$TAB" -v @product -o ' ' -v @version -o ' ' -v @extrainfo -m "../script[@id='http-title']" -o "$TAB'" -v "translate(@output,'$NEWLINE','&#x20;')" -o "'" -b -n *.xml | sort -uV | awk '{if (length(a[$1])<length($0)){a[$1]=$0}} END {for(item in a) print a[item]}' | sort -uV > $PORTDIR/nmap_web.tsv

# TODO: Replace below with something similar to ports.sh

echo "# Saving statistics"
CSUBNETS=$(cat $TSV | cut -d'.' -f1-3 | sort -uV | wc -l)
POTENTIALHOSTS=$(($CSUBNETS * 253))
NUMBERHOSTS=$(cat $SIN | wc -l)
NUTILIZATION=$(echo "scale=2; $NUMBERHOSTS/$POTENTIALHOSTS*100" | bc -q 2>/dev/null)

echo -e "# Network Statistics" > $OUTPUT
echo -e "Class C Networks:\t$CSUBNETS" >> $OUTPUT
echo -e "Potential IP:\t$(( $CSUBNETS * 253 ))" >> $OUTPUT
echo -e "Actual IP:\t$NUMBERHOSTS" >> $OUTPUT
echo -e "Network Utilization:\t%$NUTILIZATION" >> $OUTPUT
echo -e "Hostname Count:\t$(cut -f2 $TSV | sort -u | wc -l)" >> $OUTPUT
echo -e "OS Count:\t$(cut -f3 $TSV | sort -u | wc -l)" >> $OUTPUT
echo -e "Port Count:\t$(cut -f4 $TSV | sort -u | wc -l)" >> $OUTPUT
echo -e "Service Count:\t$(cut -f5 $TSV | sort -u | wc -l)" >> $OUTPUT
echo -e "Banner Count:\t$(cut -f6 $TSV | sort -u | wc -l)" >> $OUTPUT
echo -e "Total Ports:\t$(cat $TSV | wc -l)" >> $OUTPUT
echo -e "Web Server Count:\t$(grep -i 'http' $SIN | wc -l)" >> $OUTPUT
echo -e "FTP Server Count:\t$(grep -i 'ftp' $SIN | wc -l)" >> $OUTPUT
echo -e "Telnet Server Count:\t$(grep -i 'telnet' $SIN | wc -l)" >> $OUTPUT
echo -e "SSH Server Count:\t$(grep -i 'ssh' $SIN | wc -l)" >> $OUTPUT
echo -e "SMTP Server Count:\t$(grep -i 'smtp' $SIN | wc -l)" >> $OUTPUT
echo -e "SNMP Server Count:\t$(grep -i 'snmp' $SIN | wc -l)" >> $OUTPUT
echo -e "SQL Server Count:\t$(grep -i -e 'sql' -e 'oracle' $SIN | wc -l)" >> $OUTPUT
echo -e "Terminal Servers Count:\t$(grep -i 'ms-term' $SIN | wc -l)" >> $OUTPUT
echo -e "Windows OS Count:\t$(cut -f3 $SIN | grep -i 'Windows' | wc -l)" >> $OUTPUT
echo -e "Linux OS Count:\t$(cut -f3 $SIN | grep -i 'Linux' | wc -l)" >> $OUTPUT
echo -e "Solaris OS Count:\t$(cut -f3 $SIN | grep -i 'Solaris' | wc -l)" >> $OUTPUT
echo -e "BSD OS Count:\t$(cut -f3 $SIN | grep -i 'BSD' | wc -l)" >> $OUTPUT
echo -e "Cisco OS Count:\t$(cut -f3 $SIN | grep -i 'Solaris' | wc -l)" >> $OUTPUT
echo -e "IPs with a single port:\t$(cut -f1 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' | grep -i '^1[[:space:]]' | cut -f1 --complement | sort | wc -l)" >> $OUTPUT
echo -e "Unique OS:\t$(cut -f3 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' | grep -i '^1[[:space:]]' | wc -l)" >> $OUTPUT
echo -e "Unique Ports:\t$(cut -f4 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' | grep -i '^1[[:space:]]' | wc -l)" >> $OUTPUT
echo -e "Unique Services:\t$(cut -f5 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' | grep -i '^1[[:space:]]' | wc -l)" >> $OUTPUT
echo -e "# Vulnerabilities" >> $OUTPUT
echo -e "Unnecessary Services:\t$(cut -f4 $TSV | grep -i -P '^1?[0-9]/' | wc -l)" >> $OUTPUT
echo -e "Cleartext Services:\t$(grep -i 'telnet\|ftp' $SIN | wc -l)" >> $OUTPUT
echo -e "SSLv2 Enabled Webservers:\t$(cat $TSV | grep -i 'SSLv2' | wc -l)" >> $OUTPUT
echo -e "Trace Enabled Webservers:\t$(cat $TSV | grep -i 'Trace' | wc -l)" >> $OUTPUT
echo -e "Top 10 OS: $(cut -f3 $SIN | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /:/;s/: *$/:[UNKNOWN]/;s/ $//' | head | awk 'NR==1{x=$0;next}NF{x=x", "$0}END{print x}')" >> $OUTPUT
echo -e "Top 10 Ports: $(cut -f4 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /:/' | head | awk 'NR==1{x=$0;next}NF{x=x", "$0}END{print x}')" >> $OUTPUT
echo -e "Top 10 Services: $(cut -f5 $TSV| sort | uniq -c | sort -rn | sed 's/^ *//;s/ /:/' | head | awk 'NR==1{x=$0;next}NF{x=x", "$0}END{print x}')" >> $OUTPUT
echo -e "Top 10 IP with most ports:\t$(cut -f1 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /:/' | head | cut -f2 | sed 's/:$/:[Unknown]/' | awk 'NR==1{x=$0;next}NF{x=x", "$0}END{print x}')" >> $OUTPUT
echo -e "Top 10 Networks with most hosts:\t$(cut -f1 $SIN | cut -d'.' -f1-3 | sort -V | uniq -c | sort -rn | head | sed 's/^ *//;s/$/.0\/24/' | awk 'NR==1{x=$0;next}NF{x=x", "$0}END{print x}')" >> $OUTPUT
echo -e "Top 10 Domain Names:\t$(cut -f2 $TSV | grep -i "\." | cut -d '.' -f 1 --complement | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /:/' | awk 'NR==1{x=$0;next}NF{x=x", "$0}END{print x}')" >> $OUTPUT
cat "$OUTPUT"
echo "# Results are in out directory in txt and Tab Separated Format (tsv), import tsv files into Excel"
echo ""

# Additional OS and POST statistics
cut -f3 $SIN | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/;s/\t $/\t[UNKNOWN]/' | head -n 100 > $OSDIR/top_os.txt
cut -f4 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' | head -n 100 > $PORTDIR/top_ports.txt
cut -f5 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' | head -n 100 > $PORTDIR/top_services.txt
cut -f1 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' | head -n 100 > $PORTDIR/IP_highest_port_count.txt
cut -f1 $SIN | cut -d'.' -f1-3 | sort -V | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/;s/$/.X/' | head -n 100 > $PORTDIR/network_highest_host_count.txt
cut -f2 $TSV | grep "\." | cut -d '.' -f 1 --complement | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' > $OSDIR/highest_hostname_count.txt
cut -f1 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' | grep '^1[[:space:]]' | cut -f1 --complement | sort -uV | sed 's/$/\t/' | grep -F -f - $TSV > $PORTDIR/IP_single_port.txt
cut -f3 $TSV | sort | uniq -c | sort -rn | sed 's/^ *//;s/ /\t/' | grep '^1[[:space:]]' | cut -f2 | sed 's/$/\t/' | grep -F -f - $TSV > $OSDIR/unique_os.txt

# Grab OS systems
cut -f1,3 $SIN | grep -i Windows > $OSDIR/windows.txt
cut -f1,3 $SIN | grep -i -e Apple -e "OS X" -e Mac > $OSDIR/apple.txt
cut -f1,3 $SIN | grep -i -e Linux -e Unix > $OSDIR/linux.txt
cut -f1,3 $SIN | grep -i BSD > $OSDIR/bsd.txt
cut -f1,3 $SIN | grep -i Solaris > $OSDIR/solaris.txt
cut -f1,3 $SIN | grep -i Cisco > $OSDIR/cisco.txt
cut -f1,3 $SIN | grep -i SonicWall > $OSDIR/sonic.txt
cut -f1,3 $SIN | grep -i Nokia  > $OSDIR/nokia.txt
cut -f1,3 $SIN | grep -i Print > $OSDIR/printer.txt
cut -f1,3 $SIN | grep -i VM > $OSDIR/vmware.txt
cut -f1,3 $SIN | grep -i Check > $OSDIR/checkpoint.txt
cut -f1,3 $SIN | grep -i HP > $OSDIR/hp.txt
cut -f1,3 $SIN | grep -i IBM > $OSDIR/ibm.txt
cut -f1,3 $SIN | grep -i Juniper > $OSDIR/juniper.txt
cut -f1,3 $SIN | grep -i -e Camera -e Video -e Tandberg > $OSDIR/camera.txt
cut -f1,3 $SIN | grep -i Phone > $OSDIR/phone.txt

# Ports
cut -f1,4,5 $TSV | grep -i http | sed 's#/tcp##;s#/udp##' | awk '{print $3"://"$1":"$2}' | sed 's/^.*http/http/;s/^\(http\(s\)\?\)[^:]*/\1/' | sort -uV > $PORTDIR/http.txt
cut -f1,4,5 $TSV | grep -i ssh | sed 's#/tcp##;s#/udp##' | awk '{print $3"://"$1":"$2}' | sed 's/^.*ssh/ssh/;s/^\(ssh\?\)[^:]*/\1/' | sort -uV > $PORTDIR/ssh.txt
cut -f1,4,5 $TSV | grep -i telnet | sed 's#/tcp##;s#/udp##' | awk '{print $3"://"$1":"$2}' | sed 's/^.*telnet/telnet/;s/^\(telnet\?\)[^:]*/\1/' | sort -uV > $PORTDIR/telnet.txt
cut -f1,4,5 $TSV | grep -i ftp | sed 's#/tcp##;s#/udp##' | awk '{print $3"://"$1":"$2}' | sed 's/^.*ftp/ftp\(s\)/;s/^\(ftp\?\)[^:]*/\1/' | sort -uV > $PORTDIR/ftp.txt
cut -f1,4,5 $TSV | grep -i sql | sed 's#/tcp##;s#/udp##' | awk '{print $3"://"$1":"$2}' > $PORTDIR/sql.txt

# TODO: Replicate ports.sh here

# Extract http-enum output in a meaningful format
xmlstarlet sel -T -t -m "//script[@id='http-enum']" -v ../service/@name -i "@tunnel='ssl'" -o 's' -b -o '://' -v ../../../address/@addr -o ":" -v ../@portid -v "translate(@output,'$NL','$TAB')" -n *.xml | sed 's/^ \+/\t/g' | awk -F'\t' '{if ($1!=""){url=$1}if ($2!=""){print url$2}}' | sed 's/: /\t/' | sort -uV > $PORTDIR/http-enum.tsv

echo "# Making some Metasploit Magic"
# Get list of ports used by Metasploit's auxiliary scanning modules
grep -or "RPORT([0-9]*)" "$MSFDIR/modules/auxiliary/scanner" | grep -v '.svn' > $OUTDIR2/msf2port.txt
echo "workspace -a auxiliary" > $OUTDIR/nmap_auxiliary.rc
echo "" >> $OUTDIR/nmap_auxiliary.rc
OFS=$IFS
IFS=$'\n'
# Match Metasploit ports to corresponding ports discovered by NMAP
for i in $(grep -v '^#' "$VULN" | cut -f4 | cut -f1 -d'/' | sort -uV | sed 's/\(.*\)/(\1)/' | grep -r -f - $OUTDIR2/msf2port.txt)
do 
  MSF=$(echo "$i" | cut -d':' -f1);
  MSF_MODULE=$(echo $MSF | sed 's#^.*/auxiliary#auxiliary#;s#\.rb$##')
  MSF_HOST_FILE=$(echo "$MSF" | awk -F'/' '{print $(NF-1)"_"$NF}' | sed "s#\([^.]*\).*#$OUTDIR2/\1.hosts#")
  RPORT=$(echo "$i" | cut -d':' -f2 | grep -o "[0-9]*" | sed 's/\(.*\)/\t\1\//' );
  HOSTS=$(cat "$VULN" | grep "$RPORT" | cut -f1 | sort -uV) # Unique please
  echo "$HOSTS" > "$MSF_HOST_FILE" # File with list of hosts for a particular metasploit module
  # Allow all modules to run in the background concurrently
  echo "$MSFDIR/msfcli \"$MSF_MODULE\" RHOSTS=\"file:/$(readlink -f $MSF_HOST_FILE)\" E" >> $OUTDIR/msf_aux_scan.sh # Script file used to run all modules against corresponding hosts
  # Create and append to a metasploit script file
  echo "use $MSF_MODULE" >> $OUTDIR/nmap_auxiliary.rc
  echo "set RHOSTS file:/$(readlink -f $MSF_HOST_FILE)" >> $OUTDIR/nmap_auxiliary.rc
  echo "run" >> $OUTDIR/nmap_auxiliary.rc
  echo "" >> $OUTDIR/nmap_auxiliary.rc
done
IFS=$OFS

if [[ $RUN_MSF -ne 0 ]]; then
	echo "# Running Metasploit against all matched auxiliary modules available in $OUTDIR/msf_aux_scan.sh $OUTDIR/nmap_auxiliary.rc with $OUTDIR2 using $THREADS threads"
	#$MSFDIR/msfconsole -q -r $(readlink -f $OUTDIR/nmap_auxiliary.rc) -o $(readlink -f $OUTDIR/nmap_auxiliary.log)
	#chmod +x $OUTDIR/msf_aux_scan.sh; $OUTDIR/msf_aux_scan.sh | tee $OUTDIR/nmap_auxiliary.log
	# Run with xargs so we can scan concurrently (much faster) based upon provided threads
	cat $OUTDIR/msf_aux_scan.sh | sort -R | xargs -P $THREADS -I{} bash -c "echo {}; {} | tee -a $OUTDIR/nmap_auxiliary.log"

	# Remove color stuff from nmap_auxiliary.log and filter on [*] and [+]
	cat $OUTDIR/nmap_auxiliary.log | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" | grep -e '^\[\+\]' -e '^\[\*\]' | grep -vi -e 'Scanned' -e 'completed' -e 'initializing' -e 'attempting' -e 'trying' -e 'connecting' -e 'sending' -e 'error' -e "doesn't" | cut -d' ' -f1 --complement | sed 's/ /\t/;s/\t- /\t/' > $OUTDIR/msf_aux_results.txt
	echo "# Sorted Metasploit results are in $OUTDIR/msf_aux_results.txt"
else
	echo "# Metasploit ready to be run against all matched auxiliary modules using $OUTDIR/msf_aux_scan.sh or $OUTDIR/nmap_auxiliary.rc with $OUTDIR2"
	echo "# cat $OUTDIR/msf_aux_scan.sh | sort -R | xargs -P $THREADS -I{} bash -c \"echo {}; {} | tee -a $OUTDIR/nmap_auxiliary.log\""
fi

# Create Recon.csv format output
echo "# Converting Output to recon.csv format"
./nmap_tsv_to_recon.sh "$OUTDIR"

# Move our processed xml files to the scan directory
mv *.xml "$MVDIR"
echo "# xml files moved to $MVDIR, please move them back if you need to rerun"

# Remove empty files
find "$OUTDIR" -size 0 -delete; find "$OUTDIR" -type d -empty -delete



