#! /usr/bin/python
import os
import re
from glob import glob
import signal
from lxml import etree
from lxml.builder import E
from time import time, strftime, gmtime

DOCROOT = '/var/www/html/atfweb'
PARSER = etree.XMLParser(remove_blank_text=True)


class KILL_TID:
	
	def __init__(self, **opts):
		self.PIDS= re.compile('^\d{3,5}$', re.MULTILINE)
		self.USER = re.compile('atf\.\d{8}\S+\.\S+\.vars')
		pids = ''.join('%s\n' % s.replace('/proc/','') for s in glob('/proc/*'))
		self.pid = None
		self.user = None
		self.tid = None

		self.pidlist = re.findall(self.PIDS, pids)
		if 'tid' in opts:
			self.tid = opts['tid'] 
			found = -1
			for pid in self.pidlist:
				with open('/proc/%s/cmdline' % pid.rstrip('\n'), 'r') as pidfile:
					cmd = pidfile.read()
				found = cmd.find(opts['tid'])
				if found >= 0:
					self.pid = int(pid)
					parsed_tid = self.tid.split('.')
					parsed_tid.reverse()
					self.user = parsed_tid[0]
					break
		elif 'user' in opts:
			self.user = opts['user']
			found = -1
			for pid in self.pidlist:
				with open('/proc/%s/cmdline' % pid.rstrip('\n'), 'r') as pidfile:
					cmd = pidfile.read()
				pids = re.findall('atf\.\d{8}_\d{6}\.%s\.\S+\.vars' % opts['user'], cmd)
				if len(pids) > 0:
					self.pid = int(pid)
					tids = pids[0].replace('atf.','').split('.')
					self.tid = tids[0] + '.' + self.user 
					break
		assert self.pid != None, 'user name or testrun ID must be specified to kill test run'

	def killTestNow(self, signal=signal.SIGKILL):
		try:
			sessionXML = etree.parse('%s/%s/sessions.xml' % (DOCROOT, self.user), PARSER)
			session = sessionXML.find('session')
			assert session != None, 'the session file for %s is missing or corrupted' % self.user
			session.set('running','no')
			session.set('refresh','300')
			testrun = session.find('testrun')
			tests_in_progress = testrun.findall('test')

			if len(tests_in_progress) > 0:
				try:
					touched = False
					test_statusXML = etree.parse('%s/%s/tests.xml' % (DOCROOT, self.user), PARSER)
					for test in tests_in_progress:
						testnodes = test_statusXML.xpath('//test[@name="%s"]' % test.attrib['name'])
						if len(testnodes) > 0:
							testnode = testnodes[0]
							testnode.set('lastresult','Aborted')
							testnode.set('status','Error')
							testnode.set('lastran',strftime('%4Y-%3m-%2d %2H:%2M:%2S', gmtime()))
							touched = True
					if touched == True:
						with open('%s/%s/tests.xml' % (DOCROOT, self.user), 'w') as status_file:
							status_file.write(etree.tostring(test_statusXML, pretty_print=True))
				except Exception as estr:
					raise AssertionError, 'unable to update test status file: %s' % str(estr)
				session.remove(testrun)
			session.append(E.testrun(timestamp=str(int(time()))))
		except Exception as estr:
			raise AssertionError, 'unable to reset test run session: %s' % str(estr)

		try:
			os.kill(self.pid, signal)
		except:
			raise  AssertionError, 'testrun process died before kill attempt'
		with open('%s/%s/sessions.xml' % (DOCROOT, self.user), 'w') as session_file:
			session_file.write(etree.tostring(sessionXML, pretty_print=True))
		try:
			locks = etree.parse('%s/locks.xml' % DOCROOT, PARSER)
			lock = locks.find('lock[@user="%s"]' % self.user)
			if lock != None:
				locks.remove(lock)
				with open('%s/locks.xml' % DOCROOT, 'w') as lockfile:
					lockfile.write(etree.tostring(locks, pretty_print=True))
		except Exception as estr:
			raise AssertionError, 'unable to clear test run locks: %s' % str(estr)
		


		
		
			
		
		





					
				
			

		
