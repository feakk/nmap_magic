#!/bin/bash
#Convert NMAP TSV input to SpiderLabs recon.csv equivalent output

# IP Address	Port/Protocol	Domains	Operating System	OS Version	Notes
OUTDIR=${1-'out'}
while read IP
do
	PORTS=$(grep "$IP" $OUTDIR/nmap.tsv | grep -v -e '^#' -e '/ip' | cut -f4 | sort -uV | tr '\n' ',' | sed 's/ *,$/\n/')
	DOMAINS=$(grep "$IP" $OUTDIR/nmap.tsv | cut -f2 | sort -uV | tr '\n' ',' | sed 's/ *,$/\n/')
	# We only care about the first OS present (head -n1)
	O=$(grep "$IP" $OUTDIR/nmap.tsv | cut -f3 | sort -uV | cut -d',' -f1 | head -n1)
	OS=$(echo "$O" | sed 's/\([^\[(0-9]*\).*/\1/' | sed 's/ *$//' )
	OV=$(echo "$O" | sed 's/[^(0-9]*//' )
	NOTES=$(grep "$IP" $OUTDIR/nmap.tsv | grep -v -e '^#' -e '/ip' | sort -uV | awk -F'\t' '{if (length($6)>0){printf "%s/%s=\"%s\"\n",$4,$5,$6}else{printf "%s/%s\n",$4,$5}}' | sort -uV | tr '\n' ',' | sed 's/ *,$/\n/')
	
	echo -ne "$IP\t$PORTS\t$DOMAINS\t$OS\t$OV\t$NOTES\n"
done < $OUTDIR/ips.txt | python ./tsv2csv.py > $OUTDIR/recon.csv

