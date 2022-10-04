#! /usr/bin/python
import os
from lxml import etree
from lxml.builder import E
import logging
import fcntl


DOCROOT = '/var/www/html/htdocs'
PARSER = etree.XMLParser(remove_blank_text=True)
LOGPATH = '/var/www/cgi-bin/logs'
LOG = 'locks.log'
logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)

class Locker:
        def __enter__(self):
                self.fp = open('.lockfile.lck')
                fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX)
		logging.debug('lock file locked')


        def __exit__(self, _type, value, tb):
                fcntl.flock(self.fp.fileno(), fcntl.LOCK_UN)
		logging.debug('lock file unlocked')
                self.fp.close


def atf_lock(user, action, reset_lock=False, **tvars):
        count = 0
        BPS = 'bps'
        IONE = 'ione'
        FTD = 'ftd'
        FMC = 'fmc'
        PAN = 'pan'
        ISENSOR = 'isensor'
	if reset_lock ==False:
        	logging.debug('starting to %s resources for user %s' % (action, user))
        ignore_resource = lambda r: False if 'address' in r.attrib and r.attrib['address'] != "" else True
        is_locked = lambda l, s, a: True if l.attrib[a] == s.attrib[a] else False
        lockable_resources = {
                BPS     : ['Firstport', 'Secondport', 'bpgroup', 'address'],
                IONE    : ['ports', 'address'],
                FTD     : ['address'],
                FMC     : ['address'],
                PAN     : ['address'],
                ISENSOR : ['address'],
                }
	if not os.path.exists('.lockfile.lck'):
		with open('.lockfile.lck','w') as lf:
			lf.write('\n')
        lockfile = '%s/locks.xml' % DOCROOT
        if not os.path.exists(lockfile):
                with open(lockfile, 'w') as lf:
                        lf.write(etree.tostring(E.locks(), pretty_print=True))
	if reset_lock == True:
		fp = open('.lockfile.lck')
		logging.debug( 'Lock Reset')
		fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
		return
        if not os.path.exists('%s/%s/sessions.xml' % (DOCROOT, user)):
                logging.error('ERROR: missing sessions.xml file for user %s...unable to lock resources' % user)
                return(False)
        with Locker():
		logging.debug('lock file locked for user %s' % user)
                lockxml = etree.parse(lockfile, PARSER)
                lroot = lockxml.getroot()
                sessionxml = etree.parse('%s/%s/sessions.xml' % (DOCROOT, user))
                logging.debug('read %s/%s/sessions.xml to pull needed resources' % (DOCROOT, user))
                # check if there are existing locks on the resources this user needs
                if action == 'unlock':
                        for lock in lockxml.xpath('//*[@user="%s"]' % user):
                                lroot.remove(lock)
                locked = True
                resources_needed = []
                topo = sessionxml.find('session/topo')
                logging.debug('checking for bps and ione resources needed for user %s' % user)
                for resource in [BPS, IONE]:
                        session_resource = topo.find(resource)
                        if session_resource == None:
                                continue
                        if ignore_resource(session_resource):
                                continue
                        resources_needed.append(session_resource)
                logging.debug('checking for DUT resources needed for user %s' % user)
                for resource in [ISENSOR, FTD, FMC, PAN]:
                        session_resource = sessionxml.find('session/%s' % resource)
                        if session_resource == None:
                                continue
                        if ignore_resource(session_resource):
                                continue
                        resources_needed.append(session_resource)
                logging.debug('resources needed: %s' % ''.join('%s ' % r.tag for r in resources_needed))
                for resource in resources_needed:
                        logging.debug('checking for resources %s in lockfile allocated for other users: %s' % (resource.tag, user))
                        in_use_resources = lockxml.xpath('%s[@user!="%s"]' % (resource.tag, user))
                        if len(in_use_resources) == 0:
                                logging.debug('resource %s is free for %s to use' % (resource.tag, user))
                                continue
                        logging.debug('in use resources are...%s' % ''.join('%s ' % r.tag for r in in_use_resources))
                        for in_use in in_use_resources:
                                for att in lockable_resources[resource.tag]:
					logging.debug('inuse: %s\nresources needed:%s\nlockable:%s' % (
						str(in_use.items()), str(resource.items()), str(lockable_resources[resource.tag])))
                                        if in_use.attrib[att] == "" or resource.attrib[att] == "":
                                                continue
                                        locked = is_locked(in_use, resource, att)
					if resource.tag == BPS and resource.attrib['address'] != in_use.attrib['address']:
							locked = False
							continue
                                        if locked and att == 'address': # we don't care about the address as longs as the ports anf group don't match
                                                if resource.tag == BPS or resource.tag == IONE:
                                                        locked = False
                                                        continue
                                        if locked:
                                                msg = 'ERROR: Unable to lock resource for %s due to conflict. %s has %s %s locked' % (
                                                        user, in_use.attrib['user'], in_use.tag.upper(), att.upper())
                                                logging.error(msg)
                                                return(msg)

                if action == 'lock':
                        logging.debug('attempting to %s resources for user %s' % (action, user))
                        for lock in lockxml.xpath('//*[@user="%s"]' % user):
                                lroot.remove(lock)
                        topo = sessionxml.find('session/topo')
                        for resource in [BPS, IONE]:
                                session_resource = topo.find(resource)
                                if session_resource == None:
                                        continue
                                if ignore_resource(session_resource):
                                        continue
                                resource_node = E(resource, user=user)
                                resource_node.attrib.update(session_resource.attrib)
                                lroot.append(resource_node)
                        for resource in [ISENSOR, FTD, FMC, PAN]:
                                session_resource = sessionxml.find('session/%s' % resource)
                                if session_resource == None:
                                        continue
                                if ignore_resource(session_resource):
                                        continue
                                resource_node = E(resource, user=user)
                                resource_node.attrib.update(session_resource.attrib)
                                lroot.append(resource_node)
                with open('%s/locks.xml' % DOCROOT, 'w') as lfile:
                        lfile.write(etree.tostring(lockxml, pretty_print=True))
                msg = 'SUCCESS: Resources %sed for %s' % (action, user)
                logging.info(msg)
                return(msg)

if __name__ == '__main__':
	from optparse import OptionParser
	import sys
	optprsr = OptionParser(usage="Usage %s <options> <user>" % sys.argv[0])
	optprsr.add_option('-l', '--lock', action='store_true', dest='lock', default=False)
	optprsr.add_option('-u', '--unlock', action='store_true', dest='unlock', default=False)
	
	options, cliargs = optprsr.parse_args()
	if len(cliargs) == 0:
		print ('\nUser was not specified\n\n')
		exit(1)
	user = cliargs[0]
	if options.lock == True:
		result =atf_lock(user, 'lock')
	elif options.unlock == True:
		result = atf_lock(user, 'unlock')
	print(result)

