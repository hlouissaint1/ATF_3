#! /usr/bin/python

import os
from glob import glob
import sys
import re
from pprint import pprint


def get_groups(diffs):
    group = re.compile('\[\+\]\s(Added|Removed|Changed)\s\(\d+\)')
    vid = re.compile('\d+\sVID\d+\s')
    groups = {'Added': [], 'Removed': [], 'Changed': []}
    found_diffs = 0
    expected_diffs = 0
    action = ''
    for diff in diffs:
        line_action = re.match(group, diff)
        if line_action != None:
            if found_diffs != expected_diffs:
                bail('ERROR: mismatched diff count %d vs. %d' % (expected_diffs, found_diffs))
            action = re.findall('(Added|Removed|Changed)', line_action.group())[0]
            expected_diffs = int(re.findall('\d+', line_action.group())[0])
            found_diffs = 0
        else:
            try:
                groups[action].append(re.findall(vid, diff)[0])
                found_diffs += 1
            except IndexError:
                pass
    return (groups)


def is_disabled(rset, vid):
    start_of_line = rset.rfind('\n', 0, vid)
    comment_hash = re.match('$\W*#', rset[start_of_line:vid])
    if comment_hash != None:
        return True
    else:
        return False


def bail(msg=''):
    print 'ERROR:%s\n\nUsage: check.py <revision> <category> <snort-version> <diff-xml-file>\n' % msg
    sys.exit(1)


def check_ruleset_installation(rules_file_list, groups):
    found_added = []
    found_changed = []
    found_removed = []
    error = False
    rval = ''
    for rulefile in rules_file_list:
        rulef = open(rulefile, 'r')
        rulesets = rulef.read()
        for diff in groups['Added']:
            found = rulesets.find(diff)
            if is_disabled(rulesets, found):
                rval += '%s is disabled'
            if found > 0:
                if not diff in found_added:
                    found_added.append(diff)
        for diff in groups['Changed']:
            found = rulesets.find(diff)
            if found > 0:
                if is_disabled(rulesets, found):
                    rval += '%s is disabled'
                if not diff in found_changed:
                    found_changed.append(diff)
        for diff in groups['Removed']:
            if rulesets.find(diff) > 0:
                if not diff in found_removed:
                    found_changed.append(diff)
    ecount = 0
    if len(found_added) != groups['Added']:
        for diff in groups['Added']:
            if not diff in found_added:
                rval += '%s was added but is missing from rules files\n' % diff
                error = True
                ecount += 1
    if len(groups['Added']) > 0:
        if error == False:
            rval += 'All rules that were added were found on the iSensor\n'
    else:
        rval += 'No rules were added\n'
    error = False
    if len(found_changed) != groups['Changed']:
        for diff in groups['Changed']:
            if not diff in found_changed:
                rval += '%s was changed but is missing from rules files\n' % diff
                error = True
                ecount += 1
    if len(groups['Changed']) > 0:
        if error == False:
            rval += 'All rules that were changed were found on the iSensor\n'
    else:
        rval += 'No rules were changed\n'
    error = False
    if len(found_removed) > 0:
        for diff in found_removed:
            rval += '%s was removed but is in the rules files\n' % diff
            error = True
            ecount += 1
    if len(groups['Removed']) > 0:
        if error == False:
            rval += 'The rules that were removed do not exist on the iSensor\n'
    else:
        rval += 'No rules were removed\n'
    return (ecount, rval)


if __name__ == '__main__':
    if len(sys.argv) < 5:
        bail('Insufficient number of arguments')
    try:
        diffs = open(sys.argv[4], 'r')
        diff_text = diffs.read()
        diff_list = diff_text.split('\n')
    except IOError:
        diff_list = None
        diff_text = ''
        bail('Unable to parse input file "%s"' % (sys.argv[4]))
    groups = get_groups(diff_list)
    rules_file_list = glob('/secureworks/baserules7/%s/%s.%s/*/*.rules' % (sys.argv[2], sys.argv[3], sys.argv[1]))
    if len(rules_file_list) == 0:
        bail('ruleset files for %s.%s.%s were not found' % (sys.argv[2], sys.argv[3], sys.argv[1]))

    error, rval = check_ruleset_installation(rules_file_list, groups)
    if error == False:
        errstr = 'PASSED'
    else:
        errstr = 'FAILED'
    print '\n%s\nRuleset check %s' % (diff_text + "\n" + rval, errstr)
    sys.exit(error)


				
	

		
