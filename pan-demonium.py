#!/usr/bin/env python
"""Script to search filesystem for Primary Account Numbers(PANs)"""

# Import modules
import argparse
import subprocess
import logging
import branch_regexpes

# Set global variables
search_dirs = "/tmp /home /opt"
log_file = "pan-demonium.log"
pan_all = []

pandemonium_description =  """
pan-demonium.py - Payment Card Number Search Tool
=================================================
Pan-Demonium Searches filesystem for Payment Card Numbers(PANs) using find and
grep/egrep unix command-line tools. The found PANs are displayed in a report.

Recommended usage: Run Pan-Demonium regularly from cron to find PANs on the
system and report to system-administrators and/or PCI-DSS compliance officers.

Author: Kim Halavakoski <kim.halavakoski@crosskey.fi>
Date: 3.4.2013

"""

# Parse arguments
parser = argparse.ArgumentParser(description=pandemonium_description)
parser.add_argument('-d','--dir', help='Search directory',
                    required=False, action='store',dest='search_dirs')
parser.add_argument('-r', '--report', help='Show PAN report',
                    required=False,action='store_true')
parser.add_argument('-v','--verbose', help='Show verbose debugging information',
                    required=False, action="store_true")
parser.add_argument('-l','--log', help='Enable logging',
                    required=False, action='store_true')
parser.add_argument('--log-file', help='Set logfile',
                   required=False, action='store', dest='log_file')

args = parser.parse_args()

# Override the default global variables if set via arguments
if args.search_dirs:
    search_dirs = args.search_dirs

if args.log_file:
    log_file = args.log_file


# Functions

def logPAN(message):

    if args.verbose:
        print "Logging PAN: %s" % message

    filename, pan, branch = message
    logmessage = "file=%s PAN=%s branch=%s" %(filename, pan, branch)
    log.warning(logmessage)


def findPAN():

    if args.verbose:
        print "Searching PANs in %s" % search_dirs

    for pan in findAmexPAN():
        pan_all.append(pan)

    for pan in findDiscover6011xPAN():
        pan_all.append(pan)

    for pan in findDiscover65xPAN():
        pan_all.append(pan)

    for pan in findMastercardPAN():
        pan_all.append(pan)

    for pan in findVisa13PAN():
        pan_all.append(pan)

    for pan in findVisa16PAN():
        pan_all.append(pan)


def findAmexPAN():

    description = "AMEX card numbers"
    info = "The detected files contain possible American Express credit card numbers - start with the numbers 34 or 37."
    cmd = "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(3(4[0-9]{2}|7[0-9]{2})( |-|)[0-9]{6}( |-|)[0-9]{5})([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs

    pan_amex = []
    pan_amex_raw = subprocess.check_output(cmd, shell=True)

    if pan_amex_raw.strip() != "0":
        for item in pan_amex_raw.splitlines():
            pan = item.split(':')
            pan.append("amex")
            pan_amex.append(pan)

        if args.verbose:
            print  "\n" + description + ":"
            print pan_amex
    
    return pan_amex

def findDiscover6011xPAN():

    description = "Discover credit card numbers (6011x)"
    info = "The detected files contain possible Discover credit card numbers -  start with 6011 and contain 16 digits."
    cmd =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(6011( |-|)[0-9]{4}( |-|)[0-9]{4}( |-|)[0-9]{4})([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
 
    pan_discover6011x = []
    pan_discover6011x_raw = subprocess.check_output(cmd, shell=True)

    if pan_discover6011x_raw.strip() != "0":
        for item in pan_discover6011x_raw.splitlines():
            pan = item.split(':')
            pan.append("discover")
            pan_discover6011x.append(pan)

        if args.verbose:
            print  "\n" + description + ":" 
            print pan_discover6011x

    return pan_discover6011x


def findDiscover65xPAN():

    description = "Discover credit card numbers (65x)"
    info = "Modify the /usr/bin/find directory to search the desired location"
    info = "The detected files contain possible Discover credit card numbers -  start with 65 and contain 16 digits."
    cmd =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(65([0-9]{2}|-|)[0-9]{4}( |-|)[0-9]{4}( |-|)[0-9]{4})([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
 
    pan_discover65x = []
    pan_discover65x_raw = subprocess.check_output(cmd, shell=True)

    if pan_discover65x_raw.strip() != "0":
        for item in pan_discover65x_raw.splitlines():
            pan = item.split(':')
            pan.append("discover")
            pan_discover65x.append(pan)

        if args.verbose:
            print  "\n" + description + ":"                         
            print pan_discover65x

    return pan_discover65x


def findMastercardPAN():

    description = "Mastercard card numbers"
    info = "Modify the /usr/bin/find directory to search the desired location"
    info = "The detected files contain possible MasterCard credit card numbers - start with the numbers 51 through 55 and contain 15 digits."
    cmd  =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(5[1-5][0-9]{2}( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
 
    pan_mastercard = []
    pan_mastercard_raw = subprocess.check_output(cmd, shell=True)

    if pan_mastercard_raw.strip() != "0":
        for item in pan_mastercard_raw.splitlines():
            pan = item.split(':')
            pan.append("mastercard")
            pan_mastercard.append(pan)

        if args.verbose:
            print  "\n" + description + ":"                         
            print pan_mastercard

    return pan_mastercard


def findVisa13PAN():

    description = "Visa 13-digit card numbers"
    info = "Modify the /usr/bin/find directory to search the desired location"
    info = "The detected files contain possible Visa credit card numbers - start with the number four and contain 13 digits."
    cmd =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(4( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
 
    pan_visa13 = []
    pan_visa13_raw = subprocess.check_output(cmd, shell=True)

    if pan_visa13_raw.strip() != "0":
        for item in pan_visa13_raw.splitlines():
            pan = item.split(':')
            pan.append("visa")
            pan_visa13.append(pan)

        if args.verbose:
            print  "\n" + description + ":"                         
            print pan_visa13

    return pan_visa13



def findVisa16PAN():

    description = "Visa 16-digit card numbers"
    info = "Modify the /usr/bin/find directory to search the desired location"
    info = "The detected files contain possible Visa credit card numbers - start with the number four and contain 16 digits."
    cmd =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(4[0-9]{3}( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
 

    pan_visa16 = []
    pan_visa16_raw = subprocess.check_output(cmd, shell=True)

    if pan_visa16_raw.strip() != "0":
        for item in pan_visa16_raw.splitlines():
            pan = item.split(':')
            pan.append("visa")
            pan_visa16.append(pan)

        if args.verbose:
            print  "\n" + description + ":"                         
            print pan_visa16

    return pan_visa16



def luhn_checksum(card_number):
    def digits_of(n):
        return [int(d) for d in str(n)]
    digits = digits_of(card_number)
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = 0
    checksum += sum(odd_digits)

    for d in even_digits:
        checksum += sum(digits_of(d*2))

    if checksum % 10 == 0:
        return True
    else:
        return False



def is_luhn_valid(card_number):
    return  luhn_checksum(card_number) == 0



def luhn(pan):
    r = [int(ch) for ch in str(pan)][::-1]
    return (sum(r[0::2]) + sum(sum(divmod(d*2,10)) for d in r[1::2])) % 10 == 0

def reportPAN():

    pan_count = len(pan_all)

    print ""
    print "PAN Search Report"
    print "================="
    print "A total of %s credit card numbers where found on this system:" % \
    pan_count
    print ""
    for item in pan_all:
        filename, pan, branch = item
        print "file=%s PAN=%s branch=%s" % (filename, pan,branch)

    print ""
    print "Make sure that these PANs are handled according to PCI-DSS and your \
company Data Retention policies."
    print ""

#
# Main
#

# Override the default global variables if set in arguments
if args.search_dirs:
    search_dirs = args.search_dirs

if args.log_file:
    log_file = args.log_file


# Parse arguments and do stuff


if args.verbose:
    print pandemonium_description

findPAN()
reportPAN()

if args.log:

    log = logging.getLogger('pan-demonium')
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter('[%(levelname)s] %(message)s')
    formatter = logging.Formatter("%(asctime)s pan-demonium[%(process)d] [%(levelname)s]: %(message)s")
    handler_stream = logging.StreamHandler()
    handler_stream.setFormatter(formatter)
    handler_stream.setLevel(logging.ERROR)
                                                     
    log.addHandler(handler_stream)
    handler_file = logging.FileHandler(log_file)
    handler_file.setFormatter(formatter)

    log.addHandler(handler_file)

    for pan in pan_all:
        logPAN(pan)

