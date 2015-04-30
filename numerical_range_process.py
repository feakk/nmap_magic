#!/usr/bin/env python
# Paul Haas <Paul dot J dot Haas at gmail dot com> : Free License
'''Methods to expand and concatenate numerical ranges:

expand_ranges : Expands a integer string in a,b,c,d-e,f,...x-y,z notation. Called when a single argument is provided.
compress_ranges : Compresses a list of numbers into a,b,c,d-e,f,...x-y,z notation. Reads from stdin when no arguments are provided.

Bad input causes a rejection of processing.'''

def expand_ranges(num_string):
	'''Expands a integer string in a,b,c,d-e,f,...x-y,z notation'''
	if not all((c in set('0123456789,- ')) for c in num_string): return None # Verify we only have valid characters
	num_string = num_string.translate(None, ' ') # Remove spaces (may allow slightly bad input to be accepted)
	
	lst = num_string.split(',')
	numbers = []
	for l in lst:
		if '-' in l:
			r = l.split('-')
			if len(r) != 2: return None # Should only be 2 elements in range
			if len(r[0]) == 0 or len(r[1]) == 0: return None # Neither should be blank
			if not (int(r[0]) < int(r[1])): return None # The second should be greater than the first
			numbers += range(int(r[0]),int(r[1])+1)
		else:
			numbers.append(int(l))
	# Set and sort our number list
	nums = sorted(set(numbers))
	if not all((item>=0) for item in nums): return None
	return nums

def compress_ranges(numbers,fuzz=0):
	'''Compresses a list of numbers into a,b,c,d-e,f,...x-y,z notation. Fuzz may be use to over-extend ranges.'''
	lst=sorted(set(numbers)) # Set and sort our number list
	if not all(isinstance(item, int) for item in lst): return None # Verify we have all numbers
	if not all((item>=0) for item in lst): return None # Verify all numbers are positive
	
	string = ''
	i = 0
	length = len(lst)-1
	while i < length:
		j = i
		while j < length and lst[j]+1+fuzz >= lst[j+1]: j += 1
		string += "%i" % lst[i]
		if i != j: string += "-%i" % lst[j]
		if j != length: string += ","
		i = j
		i += 1
	if i <= length: string += "%i" % lst[i] # Print out final element if it was not part of a prior range
	return string

if __name__ == "__main__":
	import sys
	v = 1 # Verbosity 0=Disabled, >=Enabled
	
	'''
	# Tests:
	import random
	numbers = []
	for x in range(1,20):
		numbers.append(random.randint(1,100))
		r = random.randint(1,100)
		numbers += range(r,r+random.randint(1,10))
	random.shuffle(numbers)
	# There and back again
	str = compress_ranges(numbers)
	lst = expand_ranges(str)
	print "Testing:\n\tprovided: %s\n\tcompressed: %s\n\texpanded: %s" % (numbers,str,lst)
	exit(0)
	'''

	if len(sys.argv) == 1:
		if v > 0: print "# Reading list of numbers from stdin one per line:"
		lst = []
		for line in sys.stdin.readlines():
			try: num = int(line.strip())
			except ValueError as error: exit(2) # Catch and exit on non-number input
			lst.append(num)
		print compress_ranges(lst)
	elif len(sys.argv) == 2:
		if v > 0: print "# Processing argument as number_string:"
		lst = expand_ranges(sys.argv[1])
		if lst is not None: print ",".join(str(i) for i in lst) 
		else: exit(3) # Bad return on bad input
	else:
		if v > 0: print __doc__
		print "Usage:"
		print "\t%s = Read characters from stdin" % (sys.argv[0])
		print "\t%s 'numerical string to expand'" % (sys.argv[0])
		exit(1)

