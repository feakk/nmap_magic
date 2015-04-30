#!/usr/bin/env python
'''Convert tab separated input to fully quoted comma separated output'''
import sys
import csv

tabin = csv.reader(sys.stdin, dialect=csv.excel_tab)
commaout = csv.writer(sys.stdout, dialect=csv.excel,quoting=csv.QUOTE_ALL)
for row in tabin:
  commaout.writerow(row)
