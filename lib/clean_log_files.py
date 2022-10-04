#! /usr/bin/python

import sys
from os.path import dirname, basename, isdir, isfile, getmtime, getsize, splitext
from os import unlink
from lxml import etree
from pprint import pprint
from glob import glob
from stat import *
from time import time
import logging

DOCROOT = '/var/www/html/atfweb'

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p',
                    filename='%s/cleanup.log' % DOCROOT,
                    level=logging.DEBUG)


def inspect(contents):
    dirs = []
    files = {}
    for content in contents:
        if isdir(content):
            dirs.append(content)
        elif isfile(content):
            age = (time() - getmtime(content)) / (3600 * 24)
            files[content] = {'size': getsize(content), 'age': int(age)}
    for dirpath in dirs:
        subdir_contents = glob('%s/*' % dirpath)
        subfiles, subdirs = inspect(subdir_contents)
        dirs.extend(subdirs)
        files.update(subfiles)
    return files, dirs


def main(suites):
    freed_bytes = 0
    for suite in suites:
        for doctype in ['logs', 'reports', 'outputs']:
            docpath = '%s/%s/%s/%s' % (
            DOCROOT, suite.getparent().attrib['name'].replace(' ', '_'), suite.attrib['name'], doctype)
            contents = glob('%s/*' % docpath)
            files, dirs = inspect(contents)
            for doc in files:
                if splitext(doc)[1] == '.html' and files[doc]['age'] > 512:
                    logging.info('%s, age=%d, size=%d' % (doc, files[doc]['age'], files[doc]['size']))
                    unlink(doc)
                    freed_bytes += files[doc]['size']
                elif splitext(doc)[1] == '.xml' and files[doc]['age'] > 30:
                    logging.info('%s, age=%d, size=%d' % (doc, files[doc]['age'], files[doc]['size']))
                    unlink(doc)
                    freed_bytes += files[doc]['size']
    contents = []
    for files in ['/tmp/atf.*', '/tmp/*.err', '/tmp/*.out', '/tmp/*.diff', '/tmp/*.all', '/tmp/*.tcl', '/tmp/bps',
                  '/tmp/*release*.txt']:
        contents.extend(glob(files))
    logging.info('Cleaning out %d temporary files' % len(contents))
    files, dirs = inspect(contents)
    deleted = 0
    for tfile in files:
        # print tfile, files[tfile]['age']
        if files[tfile]['age'] < 2:  # tests running overnight might get upset if their temp files disappeared
            #logging.info('skipped deletion of tmp file "%s" due to young age' % tfile)
            #print 'skipped deletion of tmp file "%s" due to young age' % tfile
            continue
        try:
            logging.info('deleted %s' % tfile)
            unlink(tfile)
            deleted += 1
        except Exception as error:
            logging.info('Unable to delete temp file %s\n (%s)' % (tfile, str(error)))
    logging.info('%d temporary files deleted' % deleted)
    logging.info('ATF file ageout complete - Total freed bytes = %s' % freed_bytes)


if __name__ == '__main__':
    logging.info('Starting ATF file ageout')
    master_list = etree.parse('%s/tests.xml.master' % DOCROOT)
    suite_list = master_list.xpath('//suite')
    result = main(suite_list)

