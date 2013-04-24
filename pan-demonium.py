#!/usr/bin/env python
"""Script to search filesystem for Primary Account Numbers(PANs)"""

#
# Import modules
#

import re
import argparse
import subprocess
import logging
import branch_regexpes

#
# Set global variables
#

search_dirs = "/tmp /home /opt"
log_file = "pan-demonium.log"
pan_all = []
pan_record = {"file":u"filename","PAN":1234567890,"branch":u"branchname","luhn":u"luhncheck"}



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
#
# Parse arguments
#

parser = argparse.ArgumentParser(description=pandemonium_description)
parser.add_argument('-d','--dir', help='Search directory',
                    required=False, action='store',dest='search_dirs')
parser.add_argument('-v','--verbose', help='Show verbose debugging information',
                    required=False, action="store_true")
parser.add_argument('-l','--log', help='Enable logging to logfile',
                    required=False, action='store_true')
parser.add_argument('--log-file', help='Set logfile',
                   required=False, action='store', dest='log_file')
parser.add_argument('-u', '--luhn', help='Show Luhn check output',
                    required=False, action='store_true')
args = parser.parse_args()


#
# Functions
#

def iterateBranch():
    """ Search filesystem for PANs from Cardbranch ranges """

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


def findPAN(branch):
    """ Find PANs for branch. Use class CardBranch from branch_regexps.py to get branch information. """

    branch = CardBranch.branch
    branch_description = CardBranch.description
    branch_info = CardBranch.info
    branch_cmd = CardBranch.cmd
    branch_regexp = CardBranch.regexp

    pan_temp_raw = subprocess.check_output(cmd, shell=True)
    
    if pan_temp_raw.strip() != "0":
        for item in pan_temp_raw.splitlines():

            # Get the filename from the egrep output
            filename_raw = item.split(':')[0]

            # Put the rest in content_raw
            rest_raw = item.split(':')[1:]
            content_raw = ''.join(rest_raw)
 
            # Get the PANs from the content_raw variable using regexp 
            pan_raw=branch_regexp.findall(content_raw)
    
            for item in pan_raw:

                # Calculate Luhn for the PAN
                luhncheck=checkLUHN(item)
    
                # Store the file, PAN, branch and luhn-check results in a dictionary
                pan_record = {"file":filename_raw,"PAN":pan_raw,"branch":branch,"luhncheck":luhncheck}
    
                # Append the extracted record to a temporary list pan_temp
                pan_temp.append(pan_record)
    
        if args.verbose:
            print  "\n" + description + "(%d):" % len(pan_temp)
            for item in pan_temp:
                print item
   
    # Return the temporary list pan_temp
    return pan_temp


def findAmexPAN():
    """ Find Amex PANs using regexps """

    description = "AMEX card numbers"
    branch = "amex"
    info = "The detected files contain possible American Express credit card numbers - start with the numbers 34 or 37."
    cmd = "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(3(4[0-9]{2}|7[0-9]{2})( |-|)[0-9]{6}( |-|)[0-9]{5})([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
    branch_regexp = re.compile("(34[0-9]{2}|7[0-9]{2}[\s-]{0,1}[0-9]{6}[\s-]{0,1}[0-9]{5})")

    pan_temp = []
    pan_raw = []
    content_raw = ""
    filename_raw = ""
    pan_temp_raw = subprocess.check_output(cmd, shell=True)
    
    if pan_temp_raw.strip() != "0":
        for item in pan_temp_raw.splitlines():

            # Get the filename from the egrep output
            filename_raw = item.split(':')[0]

            # Put the rest in content_raw
            rest_raw = item.split(':')[1:]
            content_raw = ''.join(rest_raw)
 
            # Get the PANs from the content_raw variable using regexp 
            pan_raw=branch_regexp.findall(content_raw)
                        
            for item in pan_raw:

                # Calculate Luhn for the PAN
                luhncheck=checkLUHN(item)
            
                # Store the file, PAN, branch and luhn-check results in a dictionary
                pan_record = {"file":filename_raw,"PAN":pan_raw,"branch":branch,"luhncheck":luhncheck}
           
                # Append the extracted record to a temporary list pan_temp
                pan_temp.append(pan_record)
                
        if args.verbose:
            print  "\n" + description + "(%d):" % len(pan_temp)
            for item in pan_temp:
                print item
   
    # Return the temporary list pan_temp
    return pan_temp

7
def findDiscover6011xPAN():
    """ Find Discover PANs using regexps """

    description = "Discover credit card numbers (6011x)"
    branch = "discover"
    info = "The detected files contain possible Discover credit card numbers -  start with 6011 and contain 16 digits."
    cmd =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(6011( |-|)[0-9]{4}( |-|)[0-9]{4}( |-|)[0-9]{4})([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
    branch_regexp = re.compile("(6011[\s-]{0,1}[0-9]{4}[\s-]{0,1}[0-9]{4}[\s-]{0,1}[0-9]{4})")

    pan_temp = []
    pan_raw = []
    content_raw = ""
    filename_raw = ""
    pan_temp_raw = subprocess.check_output(cmd, shell=True)
    
    if pan_temp_raw.strip() != "0":
        for item in pan_temp_raw.splitlines():

            # Get the filename from the egrep output
            filename_raw = item.split(':')[0]

            # Put the rest in content_raw
            rest_raw = item.split(':')[1:]
            content_raw = ''.join(rest_raw)
 
            # Get the PANs from the content_raw variable using regexp 
            pan_raw=branch_regexp.findall(content_raw)

            for item in pan_raw:

                # Calculate Luhn for the PAN
                luhncheck=checkLUHN(item)
                    
                # Store the file, PAN, branch and luhn-check results in a dictionary
                pan_record = {"file":filename_raw,"PAN":pan_raw,"branch":branch,"luhncheck":luhncheck}
                    
                # Append the extracted record to a temporary list pan_temp
                pan_temp.append(pan_record)

        if args.verbose:
            print  "\n" + description + "(%d):" % len(pan_temp)
            for item in pan_temp:
                print item

    # Return the temporary list pan_temp
    return pan_temp


def findDiscover65xPAN():
    """ Find Discover PANs using regexps """

    description = "Discover credit card numbers (65x)"
    branch = "discover"
    info = "Modify the /usr/bin/find directory to search the desired location"
    info = "The detected files contain possible Discover credit card numbers -  start with 65 and contain 16 digits."
    cmd =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(65([0-9]{2}|-|)[0-9]{4}( |-|)[0-9]{4}( |-|)[0-9]{4})([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
    branch_regexp = re.compile("(65([0-9]{2}|-|)[0-9]{4}( |-|)[0-9]{4}( |-|)[0-9]{4})")

    pan_temp = []
    pan_raw = []
    content_raw = ""
    filename_raw = ""
    pan_temp_raw = subprocess.check_output(cmd, shell=True)
    
    if pan_temp_raw.strip() != "0":
        for item in pan_temp_raw.splitlines():

            # Get the filename from the egrep output
            filename_raw = item.split(':')[0]

            # Put the rest in content_raw
            rest_raw = item.split(':')[1:]
            content_raw = ''.join(rest_raw)
 
            # Get the PANs from the content_raw variable using regexp 
            pan_raw=branch_regexp.findall(content_raw)

            for item in pan_raw:

                # Calculate Luhn for the PAN
                luhncheck=checkLUHN(item)
                    
                # Store the file, PAN, branch and luhn-check results in a dictionary
                pan_record = {"file":filename_raw,"PAN":pan_raw,"branch":branch,"luhncheck":luhncheck}
                    
                # Append the extracted record to a temporary list pan_temp
                pan_temp.append(pan_record)

        if args.verbose:
            print  "\n" + description + "(%d):" % len(pan_temp)
            for item in pan_temp:
                print item

    # Return the temporary list pan_temp
    return pan_temp


def findMastercardPAN():
    """ Find Mastercard PANs using regexps """

    description = "Mastercard card numbers"
    branch = "mastercard"
    info = "Modify the /usr/bin/find directory to search the desired location"
    info = "The detected files contain possible MasterCard credit card numbers - start with the numbers 51 through 55 and contain 15 digits."
    cmd  =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(5[1-5][0-9]{2}( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
    branch_regexp = re.compile("(5[1-5][0-9]{2}[\s-]{0,1}[0-9]{4}[\s-]{0,1}[0-9]{4}[\s-]{0,1}[0-9]{4})")

    pan_temp = []
    pan_raw = []
    content_raw = ""
    filename_raw = ""
    pan_temp_raw = subprocess.check_output(cmd, shell=True)

    if pan_temp_raw.strip() != "0":
        for item in pan_temp_raw.splitlines():

            # Get the filename from the egrep output
            filename_raw = item.split(':')[0]

            # Put the rest in content_raw
            rest_raw = item.split(':')[1:]
            content_raw = ''.join(rest_raw)

            # Get the PANs from the content_raw variable using regexp 
            pan_raw=branch_regexp.findall(content_raw)

            for item in pan_raw:

                # Calculate Luhn for the PAN
                luhncheck=checkLUHN(item)
                        
                # Store the file, PAN, branch and luhn-check results in a dictionary
                pan_record = {"file":filename_raw,"PAN":pan_raw,"branch":branch,"luhncheck":luhncheck}
                        
                # Append the extracted record to a temporary list pan_temp
                pan_temp.append(pan_record)

        if args.verbose:
            print  "\n" + description + "(%d):" % len(pan_temp)
            for item in pan_temp:
                print item

    # Return the temporary list pan_temp
    return pan_temp


def findVisa13PAN():
    """ Find Visa PANs using regexps """

    description = "Visa 13-digit card numbers"
    branch = "visa"
    info = "Modify the /usr/bin/find directory to search the desired location"
    info = "The detected files contain possible Visa credit card numbers - start with the number four and contain 13 digits."
    cmd =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(4( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
    branch_regexp = re.compile("(4[\s-]{0,1}[0-9]{4}[\s-]{0,1}[0-9]{4}[\s-]{0,1}[0-9]{4})")
    pan_temp = []
    pan_raw = []
    content_raw = ""
    filename_raw = ""
    pan_temp_raw = subprocess.check_output(cmd, shell=True)
    
    if pan_temp_raw.strip() != "0":
        for item in pan_temp_raw.splitlines():

            # Get the filename from the egrep output
            filename_raw = item.split(':')[0]

            # Put the rest in content_raw
            rest_raw = item.split(':')[1:]
            content_raw = ''.join(rest_raw)
 
            # Get the PANs from the content_raw variable using regexp 
            pan_raw=branch_regexp.findall(content_raw)

            for item in pan_raw:

                # Calculate Luhn for the PAN
                luhncheck=checkLUHN(item)
                    
                # Store the file, PAN, branch and luhn-check results in a dictionary
                pan_record = {"file":filename_raw,"PAN":pan_raw,"branch":branch,"luhncheck":luhncheck}
                    
                # Append the extracted record to a temporary list pan_temp
                pan_temp.append(pan_record)

        if args.verbose:
            print  "\n" + description + "(%d):" % len(pan_temp)
            for item in pan_temp:
                print item
   
    # Return the temporary list pan_temp
    return pan_temp


def findVisa16PAN():
    """ Find Visa PANs using regexps """

    description = "Visa 16-digit card numbers"
    branch = "visa"
    info = "Modify the /usr/bin/find directory to search the desired location"
    info = "The detected files contain possible Visa credit card numbers - start with the number four and contain 16 digits."
    cmd =  "/usr/bin/find %s -type f -print0 |/usr/bin/xargs -0 /bin/egrep -H -s '([^0-9a-zA-Z_-]|^)(4[0-9]{3}( |-|)([0-9]{4})( |-|)([0-9]{4})( |-|)([0-9]{4}))([^0-9a-zA-Z_-]|$)'| /bin/egrep '\:[^0]' || /bin/echo '0'" % search_dirs
    branch_regexp = re.compile("(4[0-9]{3}[\s-]{0,1}[0-9]{4}[\s-]{0,1}[0-9]{4}[\s-]{0,1}[0-9]{4})")

    pan_temp = []
    pan_raw = []
    content_raw = ""
    filename_raw = ""
    pan_temp_raw = subprocess.check_output(cmd, shell=True)
    
    if pan_temp_raw.strip() != "0":
        for item in pan_temp_raw.splitlines():

            # Get the filename from the egrep output
            filename_raw = item.split(':')[0]

            # Put the rest in content_raw
            rest_raw = item.split(':')[1:]
            content_raw = ''.join(rest_raw)
 
            # Get the PANs from the content_raw variable using regexp 
            pan_raw=branch_regexp.findall(content_raw)

            for item in pan_raw:

                # Calculate Luhn for the PAN
                luhncheck=checkLUHN(item)
                    
                # Store the file, PAN, branch and luhn-check results in a dictionary
                pan_record = {"file":filename_raw,"PAN":pan_raw,"branch":branch,"luhncheck":luhncheck}
                    
                # Append the extracted record to a temporary list pan_temp
                pan_temp.append(pan_record)

        if args.verbose:
            print  "\n" + description + "(%d):" % len(pan_temp)
            for item in pan_temp:
                print item

    # Return the temporary list pan_temp
    return pan_temp


def checkLUHN(pan):
    """ Check PAN with the Luhn-algorithm """

    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(pan)
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


def reportPAN():
    """ Make report of the found PANs """

    # Count the found PANs
    pan_count = len(pan_all)

    # Print a pretty report
    print ""
    print "PAN Search Report"
    print "================="
    print "A total of %s credit card numbers where found on this system:" % \
    pan_count
    print ""
    for record in pan_all:

        # Go through list of PAN records(dictionaries) and print information
        print "file=%s PAN=%s branch=%s luhn=%s" % (record["file"], record["PAN"], record["branch"], record["luhncheck"])

    if args.luhn:

        print ""
        print "The following PANs passed the Luhn-check:"
        print ""

        for record in pan_all:
            if record["luhn"] == True:
                print "file=%s PAN=%s branch=%s luhn=%s" % (record["file"], record["PAN"], record["branch"], record["luhncheck"])

    print ""
    print "Make sure that these PANs are handled according to PCI-DSS and your company Data Retention policies."
    print ""


def logPAN(record):
    """ Log PANs to logfile """

    if args.verbose:
        print "Logging PAN: %s" % record

    
    logmessage = "file=%s PAN=%s branch=%s luhncheck=%s " % (record["file"], record["PAN"], record["branch"], record["luhncheck"])
    log.warning(logmessage)


#
# Main
#

# Override the default global variables if set in arguments
if args.search_dirs:
    search_dirs = args.search_dirs

if args.log_file:
    log_file = args.log_file


# Do stuff

if args.verbose:
    print pandemonium_description

# Find the PANs
iterateBranch()

# Print pretty report for the found PANs
reportPAN()

# Log actions to logfile 
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
    log.info("Starting pan-demonium")
    log.info("Checking directories %s" % search_dirs)

    for record in pan_all:
        logPAN(record)

    log.info("Stopping pan-demonium")

