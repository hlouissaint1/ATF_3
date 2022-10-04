#!/usr/bin/python
#
# May 08, 2017 - dwharton@ - 
# Simple script that reads the passed in ruleset diff file,
#  looks in the recent alerts file for alerts from those rules,
#  and returns "FalsePositive: PASSED" or "FalsPositive: FAILED".
#
#  Replaces (old) FalsePositive.pl
#

import logging
import os
import sys
import re
import time
from datetime import datetime
import subprocess
import shutil

DEBUG = False

failed_msg = "FalsePositive: FAILED"
passed_msg = "FalsePositive: PASSED"

store_dir = "/mnt6/log"
if not os.path.isdir(store_dir):
    store_dir = "/tmp"

###################
##### Logging #####
###################

# log error
def error(msg=''):
    print "ERROR: %s" % str(msg)
    msg = "%s\n" % str(msg)
    sys.stderr.write(msg)
    print(failed_msg)
    sys.exit(1)

def fail(msg=None):
    if msg:
        print "%s" % str(msg)
    print "%s" % failed_msg
    sys.exit(0)

# warn logging function
def warn(msg=''):
    print "WARN: %s" % str(msg)

# Debug logging function
def debug(msg=''):
    if DEBUG:
        print "DEBUG: %s" % str(msg)

# logging function
def log(msg=''):
    print "%s" % str(msg)

def usage(msg=None):
    usage_msg = "Usage: python FalsePositive.py <ruleset_diffs_file>"
    log("%s" % usage_msg)


###################
##### Helpers #####
###################

def get_uptime():
    # get the seconds the ips service has been up
    # assumes svstat is in PATH !
    cmd = "svstat /service/ips"
    regex = re.compile("\s(?P<SECONDS>\d+)\sseconds")
    uptime = 4 * 60 * 60 # default 4 hours
    try:
        output = os.popen(cmd).read()
        result = regex.search(output)
        if result:
            uptime = result.group("SECONDS")
        else:
            warn("Could not extract seconds from '%s' command." % cmd)
    except Exception, e:
        warn("Problem getting uptime: %s" % e)
        pass

    uptime = int(uptime)
    debug("Returning uptime: %d" % uptime)
    return uptime

###################
#####   main  #####
###################

def main():
    log("%s UTC: FalsePositive.py starting" % datetime.utcnow())

    rules = []
    rule_regex = re.compile("(?P<SWIDVID>\d+\s+VID\d+)")
    alerts_found = False

    if len(sys.argv) < 2:
        usage()
        error("Cannot continue script: not enough arguments provided.")
    diffs_file = os.path.abspath(sys.argv[1])
    if not os.path.isfile(diffs_file):
        error("diffs file '%s' does not exist" % diffs_file)
    try:
        # read diffs file and get all SWID + VID entries
        df = open(diffs_file, 'rb')
        for line in df.readlines():
            result = rule_regex.search(line)
            if result:
                swidvid = result.group("SWIDVID")
                rules.append(swidvid)
        df.close()
        if len(rules) > 0:
            log("Checking for the following rules:")
            for rule in rules:
                log("\t%s" % rule)
        else:
            # not sure if we want to error out here or just print warning msg
            #error("No rules found in diff file!")
            warn("No rules found in diff file!")
            # exit here otherwise the grep will be for '' which will match everything
            log(passed_msg)
            sys.exit(0)

    except Exception, e:
        error("Error reading diffs file '%s'. Error: %s" % (diffs_file, e))

    # now find the latest alert files and look for alerts from the extracted rules

    # see how long the IPS has been running and only read alerts since it started
    uptime = get_uptime()

    # get alert files
    alert_dir = "/secureworks/msg/compound"
    if not os.path.isdir(alert_dir): error("alerts directory '%s' does not exist!" % alert_dir)
    all_alert_files = [f for f in os.listdir(alert_dir) if f.startswith("alerts2")]
    alert_files_to_check = []
    for alert_file in all_alert_files:
        # find files that have modification time since uptime
        mseconds = int(time.time()) - int(os.path.getmtime("%s/%s" % (alert_dir, alert_file)))
        #debug("File: %s, mtime: %d seconds ago" % (alert_file, mseconds))
        if mseconds <= uptime:
            alert_files_to_check.append(alert_file)
    debug("alert_files_to_check: %s" % alert_files_to_check)
    if len(alert_files_to_check) == 0:
        log("No alert files found")

    # use xpdfoo to read unified2 files and grep results; assumes xpdfoo in path!
    for alert_file in alert_files_to_check:
        log("Checking alert file '%s/%s'..." % (alert_dir, alert_file))
        find_cmd = "/secureworks/bin/xpdfoo \"%s/%s\" | grep -P -B6 \"%s\"" % (alert_dir, alert_file, '|'.join(rules))
        debug("find_cmd: %s" % find_cmd)
        sp = subprocess.Popen(find_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, err = sp.communicate()
        if err:
            error("%s" % err)
        if not output or output == '':
            log("\t--> no alerts")
        else:
            log("%s" % output)
            alerts_found = True
            # store unified2 file so we can go back and look at pcap record if necessary 
            shutil.copy2("%s/%s" % (alert_dir, alert_file), "%s/%s" % (store_dir, alert_file))
            log("unified2 file '%s' copied to '%s'\n-----" % (alert_file, store_dir)) 

    if alerts_found:
        fail("Alerts found where none expected.")
    else:
        log(passed_msg)

    sys.exit(0)

if '__main__' == __name__:
    main()
