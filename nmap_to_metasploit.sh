#!/bin/bash
# nmap ports to Metasploit modules mapper

# Determine if we automatically run MSF on nmap results
RUN_MSF=0 # 0 to skip, any other value = run
THREADS=10 # Used to run msfcli instances concurrently using xargs for auxillary modules, and for modules which accept a thread parameter

OUTDIR=${1-'out'}
OUTDIR2="$OUTDIR/msf_scan"
VULN="$OUTDIR/nmap.tsv"
mkdir "$OUTDIR" "$OUTDIR2" 2>/dev/null

# Update to correct location of Metasploit
MSFCONSOLE=$(realpath `which msfconsole` 2>/dev/null)
MSFDIR=$(dirname $MSFCONSOLE)
if [ -z "$MSFDIR" ]; then 
	MSFDIR="/pentest/exploits/framework" # Kali's Metasploit framework directory
	echo "# Cannot find Metasploit directory in path, assuming Kali: $MSFDIR"
fi

echo "# Making some Metasploit Magic"
# Get list of ports used by Metasploit's auxiliary scanning modules
grep -or "RPORT([0-9]*)" "$MSFDIR/modules/auxiliary/scanner" | grep -v '.svn' > $OUTDIR2/msf2port.txt
echo "workspace -a auxiliary" > $OUTDIR/nmap_auxiliary.rc
echo "setg THREADS $THREADS" >> $OUTDIR/nmap_auxiliary.rc
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
  echo "$MSFDIR/msfcli \"$MSF_MODULE\" RHOSTS=\"file:/$(readlink -f $MSF_HOST_FILE)\" THREADS=\"$THREADS\" E" >> $OUTDIR/msf_aux_scan.sh # Script file used to run all modules against corresponding hosts
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

