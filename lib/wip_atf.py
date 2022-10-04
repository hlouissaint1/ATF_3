#! /usr/bin/python
import sys
import os
import time
from lxml import etree
from lxml.builder import E
import subprocess
import logging
import re
import signal
from axsess import Password
from atfvars import varImport
from tempfile import mkstemp
from glob import glob
from copy import deepcopy
from optparse import OptionParser
import inspect
import traceback

global options
DOCROOT = '/var/www/html/htdocs'
CGIPATH = '/var/www/cgi-bin'
PARSER = etree.XMLParser(remove_blank_text=True)
NOW = lambda: time.time()
ELAPSED = lambda t: NOW() - t
LOGPATH = '/var/www/cgi-bin/logs'
LOG = 'atf_engine.log'
LOGPATH = '/var/www/cgi-bin'
LOG = 'ATF.log'
global ABORT_REQUEST
global TEST_IN_PROGRESS
ABORT_REQUEST = 0
TEST_IN_PROGRESS = 0

logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)

TEST_ID = lambda u, n: time.strftime('%Y%m%d_%H%M%S') + '.' + u + '.' + n + '.'
logging.debug('Initialized log')


def abort_request_handler(signum, frame):
    """
    Handles SIGTERMs to gracefully stop all or a specific test-run.
    Abort requests can come in from the REST service or it can be killed from a bash prompt.
    ABORT_REQUEST = 0 Initial state of running session
    ABORT_REQUEST = 1 Received Abort signal (SIGUSR2) attempt to shutdown gracefully
    ABORT_REQUEST = 2 Received second Abort signal (SIGUSR2) force 
    
    """
    global ABORT_REQUEST
    global TEST_IN_PROGRESS
    logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
    logging.info('SIGUSR2 signal raised')
    if ABORT_REQUEST == 0:
    	ABORT_REQUEST = 1
	if TEST_IN_PROGRESS != 0:
		os.kill(TEST_IN_PROGRESS, signal.SIGTERM)
    elif ABORT_REQUEST == 1:
	ABORT_REQUEST = 2
	if TEST_IN_PROGRESS != 0:
		os.kill(TEST_IN_PROGRESS, signal.SIGTERM)
		os.kill(TEST_IN_PROGRESS, signal.SIGKILL)
	

signal.signal(signal.SIGUSR2, abort_request_handler)


def test_generator(user, xml):
    logging.debug('generating tests')
    order_by_name = lambda t1, t2: -1 if t1.attrib['name'] <= t2.attrib['name'] else 1
    scheduled_tests = xml.xpath('//test[@status="Scheduled"]')
    sorted_tests = sorted(scheduled_tests, order_by_name)
    for test in sorted_tests:
        yield test


def get_fqdn():
    import re
    try:
        with open('/etc/hosts', 'r') as hosts:
            fqdn_parse = re.findall('(a|p|r)(-atf.*net)', hosts.read(), re.MULTILINE)[0]
            fqdn = fqdn_parse[0] + fqdn_parse[1]
            logging.info('FQDN is %s' % fqdn)
            return (fqdn)
    except Exception as estr:
        logging.debug('failed to determine FQDN "%s"...exiting' % str(estr))
    return ('')


class Session:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
	self.handle_error = self.error_handler
        self.evars = evars
	logging.debug('session initializing')
        self.logfile = None
        self.reportfile = None
	self.pid = 0
	self.ppid = 0
	self.ruleset_version = options.version
	if not 'ID' in self.__dict__:
        	self.testrun_ID = time.strftime('%Y%m%d_%H%M%S') + '.' + self.ATF_User + '.'
	else:
		self.testrun_ID = self.ID
        self.sessionfile = '%s/%s/sessions.xml' % (DOCROOT, self.ATF_User)
	self.testID = ''
        if not os.path.exists(self.sessionfile):
            self.create_session_file()
        self.sessionsxml = etree.parse(self.sessionfile, PARSER)
        self.session = self.sessionsxml.find('session')
        self.test_queue = test_generator(self.ATF_User, self.sessionsxml)
	self.suite = None
        self.result = ''
	self.running='yes'
        #self.session.set('running', 'yes')
        self.session.set('user', self.ATF_User)
        self.tests = self.session.find('tests')
        self.test = None
        self.outfile = None
        self.errfile = None
        self.error = ''
        if options.test != None:
            self.session = self.sessionsxml.find('session')
            self.tests = self.session.find('tests')

        total_tests = len(self.tests.findall('test'))
	if total_tests <= 0:
		estr = 'This testrun was launched with no tests defined in session file'
		logging.error(estr)
		raise AssertionError, estr

        # print etree.tostring(self.test_queue.next(), pretty_print=True)A
        self.test_in_progress = None
        self.last_test = None
        self.varfile = None
        self.start_time = 0
        self.Process = None
	if 'ATF_STATS' in os.environ:
		print os.environ['ATF_STATS']
		self.stats = eval(os.environ['ATF_STATS'])
	else:
        	self.stats = {
            	'total-passed': 0,
            	'total-failed': 0,
            	'total-blocked': 0,
            	'total-aborted': 0,
            	'total-tests': 0,
            	'start-time': NOW(),
            	'id': self.testrun_ID,
        	}
        self.testrunfile = '%s/%s/testrun_summary.xml' % (DOCROOT, self.ATF_User)
        self.update_session_file(True)
        self.summary = self.create_testrun_summary(self.stats)
	logging.debug('session initialized')

    def error_handler(self, request, client_address):
	import traceback
	exstr = traceback.format_exception_only(sys.exc_type, sys.exc_value)
	estr = 'An error occurred during session...\n%s\n' % (exstr)
	logging.error(estr)
	logging.error('trap: %s' % traceback.format_exc(30))

    def create_testrun_summary(self, stats):
        summary = E('testrun-summary')
        testrun = E.testrun()
        for stat in stats:
            testrun.set(stat, str(stats[stat]))
        tests = test_generator(self.ATF_User, self.sessionsxml)
        for test in tests:
            add_test = E.test()
            add_test.attrib.update(test.attrib)
            testrun.append(add_test)
        summary.append(testrun)
        xmlstr = etree.tostring(summary, pretty_print=True)
        with open(self.testrunfile, 'w') as f:
            f.write(etree.tostring(summary, pretty_print=True))
	return(etree.parse(self.testrunfile, PARSER))

    

    def update_testrun_summary(self, test, stats, loglink=None, reportlink=None):
        testrun = self.summary.find('testrun')
        counters = {}
        for stat in stats.keys():
            if stat.startswith('total'):
                counters[stat] = str(stats[stat])
        testrun.attrib.update(counters)
        oldtest = testrun.find('test[@name="%s"]' % test.attrib['name'])
	uptest = E.test()
        uptest.attrib.update(test.attrib)
        uptest.set('run-time', str(ELAPSED(self.start_time)))
        uptest.set('heartbeat', str(NOW()))
	if loglink != None:
		uptest.insert(0,E.loglink('https://%s' % loglink.replace(DOCROOT,get_fqdn())))
	if reportlink != None:
		uptest.insert(0,E.reportlink('https://%s' % reportlink.replace(DOCROOT,get_fqdn())))
	parent = oldtest.getparent()
	parent.remove(oldtest)
	parent.insert(0,uptest)
        with open(self.testrunfile, 'w') as f:
            f.write(etree.tostring(self.summary, pretty_print=True))
	self.summary = etree.parse(self.testrunfile, PARSER)
	return(self.summary)

    def write_var_file(self, ID, docs):
        script, report, log, debugf, outputf = docs
        fd, varfile = mkstemp(prefix='atf.%s' % ID, suffix='.vars')
        with open(varfile, 'w') as v:
            v.write('--variable VarFile:%s' % varfile)
            for var in self.evars:
                if var == 'VarFile':
                    continue
                if var.find('_Password') > 0:
                    continue
		if var in os.environ:
			v.write('--variable %s:%s\n' % (var, os.environ[var]))
                else:
			v.write('--variable %s:%s\n' % (var, self.evars[var]))
            if 'LOGFILE' not in self.evars:
                v.write('--variable %s:%s\n' % ('LOGFILE',log))
            if 'REPORTFILE' not in self.evars:
                v.write('--variable %s:%s\n' % ('REPORTFILE',report))
	    if options.version != '':
		v.write('--variable %s:%s\n' % ('targetRuleset', options.version))
        return (varfile)

    def update_session_file(self, rerun=False, remove=None):
        sessionsxml = etree.parse(self.sessionfile, PARSER)
        session = sessionsxml.find('session')
	session.set('pid', str(self.ppid))
	session.set('running', self.running)
        tests = session.find('tests')
        if rerun == True:
            stale = self.sessionsxml.xpath('//test[@status!="Scheduled"]')
            for test in stale:
                test.set('status', 'Scheduled')
        if remove != None:
            tnode = tests.xpath('//test[@name="%s"]' % remove)
            if len(tnode) > 0:
                logging.debug('removing test "%s" from session file' % remove)
                test = tnode[0]
                test.getparent().remove(test)
                with open(self.sessionfile, 'w') as w:
                    w.write(etree.tostring(sessionsxml, pretty_print=True))
                    logging.debug(
                        'new session file written successfully\n%s' % etree.tostring(sessionsxml, pretty_print=True))
            return (sessionsxml)
	if self.test_in_progress != None:
		tnode = tests.find('test[@name="%s"]' % self.test_in_progress)
		tnode.set('status',self.test.attrib['status'])
		tnode.set('result',self.test.attrib['result'])
        try:
            logging.debug('writing new session file')
	    parent = session.getparent()
	    parent.remove(session)
	    parent.insert(0,session)
            with open(self.sessionfile, 'w') as w:
                w.write(etree.tostring(sessionsxml, pretty_print=True))
	    return (sessionsxml)

        except Exception as estr:
	    error =  'ERROR: unable to update session file:%s ' % str(estr)
	    logging.error(error)
            raise AssertionError, error

    def get_robot_filenames(self, test):
        logpath = os.path.dirname(
            test.find('logs').text) + '/' + self.TestEnv.capitalize() + '/' + self.testID + '.html'
        reportpath = logpath.replace('logs', 'reports')
        debugpath = logpath.replace('logs', 'debugfiles')
	outputpath = logpath.replace('logs', 'output')
        rf_script = test.find('path').text
        return (rf_script, reportpath, logpath, debugpath, outputpath)

    def monitor_testrun(self):
	global ABORT_REQUEST
	global TEST_IN_PROGRESS 
	logging.debug('monitor started user= %s' % os.environ['ATF_User'])
	suite_in_progress = None
	abort_serviced = False
	
        while True:
	    log = None,
	    report = None
	    if ABORT_REQUEST == 1:
		if abort_serviced == False and self.pid != 0:
			print 'sent sigterm to process %s' % self.pid
			os.kill(self.pid, signal.SIGTERM)
			abort_serviced = True
		
            if self.test_in_progress == None:
                try:
                    self.test = self.test_queue.next()
                    logging.debug('Running: %s' % self.test.attrib['name'])
		    self.sessionsxml = self.update_session_file()
		    self.session = self.sessionsxml.find('session')
		    self.tests = self.session.find('tests')

                except StopIteration:
                    logging.debug('no more tests in queue...testrun ended')
		    self.pid = self.ppid = 0
		    self.running = 'no'
		    self.sessionsxml = self.update_session_file()
		    self.session = self.sessionsxml.find('session')
		    self.tests = self.session.find('tests')
                    break

    		if options.rest_session == True:
        		rest_var_overrides()

                self.test_in_progress = self.test.attrib['name']
		self.suite = self.test.attrib['suite']
                self.testID = self.testrun_ID + '.' + self.test_in_progress
                self.test.set('status', 'Running')
                self.varfile = self.write_var_file(self.testrun_ID, self.get_robot_filenames(self.test))
                self.start_time = NOW()
                #self.summary = self.update_testrun_summary(self.test, self.stats, log, report)
		if ABORT_REQUEST == 0:
                	logging.debug('launching pybot...')
                	self.Process, self.pid, self.outfile, out_fd, self.errfile, err_fd = self.launch_test(
                    		self.get_robot_filenames(self.test))
			logging.debug('user: %s, PID= %d' % (os.environ['ATF_User'],self.pid))
			self.ppid = os.getppid()
			TEST_IN_PROGRESS = self.pid
			self.session.set('pid',str(self.ppid))
                	self.session.set('timestamp', str(self.start_time))
			self.sessionsxml = self.update_session_file()
			self.session = self.sessionsxml.find('session')
			self.tests = self.session.find('tests')
			suite_in_progress = self.suite
			TEST_IN_PROGRESS = self.ppid

		else:
			self.last_test = self.test_in_progress
			self.test_in_progress = None
			continue


            self.test_elapsed_time = ELAPSED(self.start_time)
            rcode = self.Process.poll()
            if rcode != None: # pybot has exited
		logging.debug('User %s, RCODE: %d' % (os.environ['ATF_User'],rcode))
		if suite_in_progress != None and self.suite != suite_in_progress:
			x = S.mail_testrun_update(testrun_ID)
                logging.debug('Test Ended "%s" with rcode %d' % (self.test_in_progress, rcode))
                self.test.set('status', 'Completed')
                self.test.set('result', 'Unknown')
                log, report, errstr, results = self.analyze_rf_result(out_fd, self.outfile, err_fd, self.errfile)
                count, passed, failed = results
                self.rf_test_errors = errstr
                self.test.set('status', 'Completed')
		if abort_serviced == True:
			TEST_IN_PROGRESS = self.pid = 0
			self.result = 'Aborted'
			self.test.set('result','Aborted')
			self.stats['total-aborted'] += 1

                elif int(failed) > 0:
                    self.result = 'Failed'
                    self.test.set('result', 'Failed')
                    self.stats['total-failed'] += 1
                    logging.info('Test %s FAILED:\n%s' % (self.test.attrib['name'], errstr))
                elif int(passed) > 0:
                    self.result = 'Passed'
                    self.test.set('result', 'Passed')
                    self.stats['total-passed'] += 1
                    logging.info('Test %s PASSED' % (self.test.attrib['name']))
		self.stats['total-tests'] += 1
                self.summary = self.update_testrun_summary(self.test, self.stats, log, report)
		
                self.sessionsxml = self.update_session_file(False, self.test_in_progress)
                self.session = self.sessionsxml.find('session')
                self.tests = self.session.find('tests')
		suite_in_progress = self.suite
		TEST_IN_PROGRESS = self.pid = 0	
                self.test_in_progress = None
		if abort_serviced == True:
			self.session.attrib['running'] = 'no'
			self.session.attrib['pid'] = '0'
			self.sessionsxml = self.update_session_file()
		
	    """
            else:
            	if self.test != None:
                	self.summary = self.update_testrun_summary(self.test, self.stats)
		
	    """
            time.sleep(3)


    def process_rf_output(self,outf):
	causes = ''
	if not os.path.exists(outf):
		causes = 'Unknown app error...check the "/tmp/*.err" logs'
		return(causes)

	with open(outf,'r') as rf:
		contents = rf.read()
		lines = contents.split('\n')
		x = 0
		for line in range(0, len(lines)):
			failure = re.findall('^.*(?=\|\sFAIL)', lines[line])
			if len(failure) == 0:
				x += 1
				continue
			keyword = failure[0].rstrip()
			n = 1
			cause = lines[line + 1]
			if cause.startswith('--'):
				cause = 'unknown error'
				continue
			if cause.startswith('Test execution stopped due to a fatal error'):
				continue
			if lines[line + 2].startswith('===='):
				causes += '\t %s Test Keyword Result Summary (including benign failures): \t\t%s' % (keyword,cause)
			else:
				causes += '\tIn keyword "%s"...\t\t%s\n' % (keyword, cause)
	return(causes)	

    def analyze_rf_result(self, fo, outfile, fe, errfile, remove_file=False):
        result_re = re.compile('^(\d+)\s+test.*(\d+)\s+passed.*(\d+)\s+failed', re.MULTILINE)
        errstr = ''
        nt = np = nf = 0
        errors = {}
	loglink = ''
	reportlink= ''
        try:
            # fo.close()
            # fe.close()
            with open(outfile, 'r') as fd:
                output = fd.read()
                print('STDOUT:\n%s' % output)
            nt, np, nf = re.findall(result_re, output, )[0]
	    loglink = re.findall('(?<=Log:)\s+(\S+)', output, re.MULTILINE )[0]
	    reportlink = re.findall('(?<=Report:)\s+(\S+)', output, re.MULTILINE )[0]
            case = None
            for line in output.split('\n'):
                if case != None:
                    errors[case] = line.rstrip('  ')
                    case = None
                if line.find('| FAIL |') > 0:
                    case = line.replace('| FAIL |', '').replace('  ', '')
                    continue
	    logging.debug('parsing error file %s' % errfile)
            with open(errfile, 'r') as fd:
                err_content = fd.read()
		test_errors = '%s/%s/%s.test_errors.txt' % (DOCROOT, os.environ['ATF_User'], self.testrun_ID)
                logging.debug('STDERR:\n%s\n%s' % (test_errors,err_content))
		if len(err_content) > 0:
                	with open(test_errors, 'a') as rf:
                        	rf.write('Test Name: %s\n' % self.testID)
                        	rf.write(err_content)
		else:
			with open(test_errors, 'a') as rf:
				rf.write('Test Name: %s\n' % self.testID)
				failures = self.process_rf_output(outfile)	
				if len(failures) == 0:
					rf.write('No errors indicated\n')
				else:
					rf.write(failures)

        except IOError as estr:
            errstr = 'ERROR...unable to read output file "%s"\n%s' % (outfile, str(estr))
        except ValueError as estr:
            errstr = 'ERROR...output file "%s" is corrupted\n%s' % (outfile, str(estr))
        except Exception as estr:
            errstr = 'ERROR: unknown error %s' % str(estr)
        if len(errstr) > 0:
            logging.error(errstr)
        else:
            logging.debug('successfully parsed RF output file')
            if remove_file == True:
                os.unlink(fo)
                os.unlink(fe)
        if len(errors) > 0:
            errstr = ''.join('%s - %s\n' % (e, errors[e]) for e in errors)
            with open(errfile, 'r') as err:
                errstr += 'errorfile contents...\n%s' % err.read()
        return (loglink, reportlink, errstr, (nt, np, nf))

    def launch_test(self, docs):
        script, report, log, debug, outputf = docs
        logging.debug('launching test: \n%s\n%s\n%s\n%s' % (script, report, log, debug))
        err_fd, errfile = mkstemp(prefix='atf.%s' % self.testID, suffix='.err')
        out_fd, outfile = mkstemp(prefix='atf.%s' % self.testID, suffix='.out')
        fqdn = get_fqdn()
        logging.debug('FQDN=%s' % fqdn)
        os.environ['LOGFILE'] = log
        os.environ['REPORTFILE'] = report
        libpath = '--pythonpath /var/www/htdocs'
        Pcmd = 'pybot --outputdir /var/www/html/htdocs -L DEBUG --RemoveKeywords WUKS -A %s --log %s --output %s --report %s --debugfile %s %s' % (
            self.varfile,
            log,
	    outputf,
            report,
            debug,
            # libpath,
            script,
        )
        logging.debug(Pcmd)
        P = subprocess.Popen(Pcmd, shell=True, stderr=err_fd, stdout=out_fd)
        pid = os.fork()
        if pid == 0:
            rcode = P.wait()
            exit(rcode)

        else:
            return (P, P.pid, outfile, out_fd, errfile, err_fd)

    def add_new_test(self, ):
        if options.test == None or options.group == None:
            logging.debug('missing test or test group definition')
            exit(1)

        seekpath = '/%s/%s' % (DOCROOT, options.group)
	if options.suite != None and options.group != options.suite:
	    seekpath += '/%s' % options.suite 
        for newtest in options.test.split(','):
            seektest = '%s.txt' % newtest
            tree = [f for f in os.walk(seekpath)]
            tpath = None
            for d in tree:
                try:
                    found = d[2].index(seektest)
		    if options.suite == None or options.suite == options.group:
                    	tpath = '%s/%s/%s' % (DOCROOT, options.group, d[2][found])
		    else:
			tpath = '%s/%s/%s/%s' % (DOCROOT, options.group, options.suite, d[2][found])
                    break
                except ValueError:
                    continue
	    if tpath == None:
		estr = 'Test named "%s.txt" cannot be found in %s group' % (newtest, options.group)
		logging.error(estr)
		raise AssertionError, estr

            if options.suite == None:
                options.suite = options.group
            for bottomdir in ['debugfiles', 'logs', 'reports']:
                path = '%s/%s/%s/%s/%s' % (DOCROOT, options.group, options.suite, newtest, bottomdir)
                if not os.path.exists(path):
                    os.makedirs(path)
            addtest = E.tests(
                E.test(
                    E.path(tpath),
                    E.logs('%s/%s/logs/%s/%s' % (options.group, options.suite, newtest, self.TestEnv)),
                    E.output('%s/%s/output/%s/%s' % (options.group, options.suite, newtest, self.TestEnv)),
                    E.reports('%s/%s/reports/%s/%s' % (options.group, options.suite, newtest, self.TestEnv)),
                    E.debugfiles('%s/%s/debug/%s/%s' % (options.group, options.suite, newtest, self.TestEnv)),
                    name=newtest,
                    group=options.group,
                    suite=options.suite,
                    status='Scheduled',
                    result='Pending',
                )
            )
            self.session.append(addtest)
        with open(self.sessionfile, 'w') as f:
            f.write(etree.tostring(self.sessionsxml, pretty_print=True))
        return (etree.parse(self.sessionfile, PARSER))


    def create_session_file(self):
	logging.debug('creating session file for user %s' % self.TestEnv)
        var_exists = lambda v: self.evars[v] if v in self.evars else ''
        session = E.session(
            E.topo(
                E.bps(
                    topo=var_exists('bps_Topology'),
                    address=var_exists('bps_IP'),
                    bpgroup=var_exists('bps_Group'),
                    Firstport=var_exists('bps_Firstport'),
                    Secondport=var_exists('bps_Secondport'),
                ),
                E.ione(
                    topo=var_exists('ione_Topology'),
                    address=var_exists('ione_IP'),
                    ports=var_exists('ione_Ports'),
                ),
                address=var_exists('dcim_IP'),
                name=var_exists('dcim_Name'),
                dut=var_exists('device_type')
            ),
            running="yes",
	    pid=str(self.ppid),
            user=self.ATF_User,
            env=self.TestEnv
        )
        if options.email != None:
            session.append(E.email(options.email))
        if 'device_type' in self.evars:
            dev = self.device_type
            session.append(E(dev,
				E('target-ruleset', version=self.ruleset_version),
				address=var_exists('%s_IP' % dev), name=var_exists('%s_Name' % dev)))
        if 'device_console' in self.evars:
            dev = self.device_console
            session.append(E(dev, address=var_exists('%s_IP' % dev), name=var_exists('%s_Name' % dev)))
        if 'device_peer' in self.evars and self.evars['device_peer'] != "None":
            dev = self.device_peer
            session.append(E(dev, address=var_exists('%s_IP' % dev), name=var_exists('%s_Name' % dev)))

        sessions = E.sessions(session)
        with open(self.sessionfile, 'w') as f:
            f.write(etree.tostring(sessions, pretty_print=True))


    def mail_testrun_update(self, testID, run_status='Update', subject=None):
	M = Mail(environment, user,)
	testrun = self.summary.find('testrun')
	tstatus = ''.join(' %s: %s,' % (key.capitalize(), testrun.attrib[key]) for key in ['total-tests', 'total-passed', 'total-failed', 'total-aborted'])
	content = 'TESTRUN SUMMARY: %s\n\n' % tstatus 
	test_run_passing = True
	testrun_results = 'Passed'	
	for test in self.summary.xpath('//test'):
		name, status, result = ['%s' % test.attrib[att] for att in ['name', 'status', 'result']]
		if result == 'Failed':
			test_run_passing = False
		if status == 'Completed':
			content += '\n\nTest Name: %s, Suite: %s, Status: %s, Result: %s' % (name.upper(), self.suite, status, result.upper())
			for linknode in ['reportlink','loglink']:
				link = test.find(linknode)
				if link != None:
					content += '\n\t%s\n\t\t%s' % (linknode,link.text)
				else:
					content += '\n\tNo link available'
					content += '\n\t%s' % etree.tostring(test, pretty_print=True)
			if result == 'Failed':
				testrun_results = 'Failed'
				err_file = '%s/%s/%s.test_errors.txt' % (DOCROOT, os.environ['ATF_User'], self.testrun_ID)
				if os.path.exists(err_file):
					with open(err_file, 'r') as ef:
						content += '\n\tErrors during test:'
						for line in ef.read().split('\n'):
							content += '\n\t\t%s' % line
		else:
			content += '\n\nTest Name: %s, Suite: %s, Status: %s, Result: %s' % (name, self.suite, status, result)
			if test_run_passing == True:
				testrun_results = 'Passing so far'
			else:
				testrun_results = 'FAILURES in testrun'
	if run_status == 'Completed':
		runstatus = 'Testrun %s: ID=%s' %  (testrun_results, testID)
	else:
		runstatus = 'Testrun %s: %s ID=%s' %  (run_status, testrun_results, testID)
	if subject != None:
		runstatus = runstatus.replace('Testrun',subject)
	logging.debug('Mail Subject: %s, Mail Contents:\n%s' % (runstatus, content))
	M.Set_Mail_Subject(runstatus)
	M.Log_To_Mail(content)
	resp = M.Mail_Report(runstatus)	
	logging.debug(str(resp))

def gen_tests_from_csv_file(csvfile=None):
	suites = [] 
	with open(csvfile, 'r') as csv:
		csvlines = csv.read().split('\n')
	for line in csvlines:
		if line.startswith('#') or len(line) < 1:
			continue
		tokens = line.rstrip('\n').split(',')
		suite = tokens[0]
		tests = ''.join('%s,' % t for t in tokens[1:])
		suites.append({suite : tests.rstrip(',')})
	return(suites)

class Mail:
    @varImport()
    def __init__(self, **evars):
	from time import strftime
        self.__dict__.update(evars)

        # self.default_to_addresses = self.to_addresses = ['gowen@secureworks.com,pmankoo@secureworks.com,hlouissaint@secureworks.com']
        self.default_to_addresses = self.to_addresses = ['gowen@secureworks.com']

        self.mailing_list = {}
        self.summary = ''
        self.reports = ''
        #self.report_link = self.REPORTFILE if 'REPORTFILE' in self.__dict__ else ''
        self.log = ''
        #self.log_link = self.LOGFILE if 'LOGFILE' in self.__dict__ else ''
        self.content = ''
        self.test_config = ''
        self.test_status = 'started up'
        self.fqdn = get_fqdn()
        if options.rest_session == True:
        	rest_var_overrides()

        if 'LOGFILE' in self.__dict__:
            self.testID = '.%s' % os.path.basename(self.LOGFILE.strip('html'))
            self.log_link = 'https://%s/%s' % (self.fqdn, os.environ['LOGFILE'])
        if 'REPORTFILE' in self.__dict__:
            self.testID = '.%s' % os.path.basename(self.REPORTFILE.strip('html'))
            self.report_link = 'https://%s/%s' % (self.fqdn, os.environ['REPORTFILE'])
        if not 'TestID' in self.__dict__:
            self.TestID = strftime('%04Y%02m%02d.%02H%02M%02S')
        self.subject = ''
	if options.email != None:
		self.__dict__['email'] = self.email = options.email
        if 'email' not in self.__dict__ or self.email == 'User' or self.email == 'UNDEFINED':
            logging.debug('using default email distro for %s' % self.ATF_User)
            self.email = self.ATF_User
        for resource in ['isensor_IP', 'pan_IP', 'TestEnvironment', 'bpIP', 'bps_Firstport', 'bps_Secondport', 'bpGroup',
                         'bps_TOPOLOGY', 'ione_IP',
                         'ione_Ports', 'ione_Topology', 'targetRuleset', 'TestEnv', 'bps_IP', 'isensor_Hardware',
                         'idrac_IP','ione_Topology',
                         'session_user', 'email', 'VarFile']:
	    if resource in os.environ:
		self.test_config += '\t%s: %s\n' % (resource.replace('_', ' ').upper(), os.environ[resource])
		continue
            if resource in self.__dict__:
                if self.__dict__[resource] == 'UNASSIGNED':
                    continue
                self.test_config += '\t%s: %s\n' % (resource.replace('_', ' ').upper(), self.__dict__[resource])
            else:
                continue
        try:
            sxml = etree.parse('%s/admin/%s_servers.xml' % (DOCROOT, self.TestEnv.lower()))
        except:
            logging.error('servers configuration missing')
            raise AssertionError, 'Mail module was imported with missing servers config'
        try:
            logging.error('email distribution is: %s' % self.email)
        except AttributeError:
            logging.error('email distribution is undefined')
            raise AssertionError, 'Mail module was imported without the email distribution defined\n%s' % str(evars)
        try:
            exml = etree.parse('%s/admin/email.xml' % (DOCROOT))
        except Exception as estr:
	    error = 'Email file unreadable: %s' % str(estr)
	    logging.error(error)
            raise AssertionError, error
        mailserver = sxml.find('atf/mail-server')
        if mailserver != None and 'url' in mailserver.attrib:
            self.smtp_server = mailserver.attrib['url']
        else:
            self.smtp_server = 'r-atl1mxhost04.corp-dmz.secureworks.net'

        mailclient = sxml.find('atf/mail-client')
        if mailclient != None and 'url' in mailclient.attrib:
            self.from_address = mailclient.attrib['url']
        else:
            self.from_address = 'p-atf.atf-pilot.aws.secureworks.net'

        logging.debug('email server URL is: %s, email client is %s' % (self.smtp_server, self.from_address))
        if self.email != 'UNDEFINED':
            if len(self.to_addresses) > 0:
                user = self.to_addresses.pop(0)  # remove the default user (me)
            else:
                user = None
            group = exml.find('group[@name="%s"]' % self.email)
	    if group == None:
		estr = "Can't find email distro group %s" % self.email
		logging.error(estr)
		raise AssertionError, estr
            recipients = group.findall('recipient')
            logging.debug('found %s recipients in distribution list: %s' % (
                len(recipients), self.email))
            for recipient in recipients:
                self.to_addresses.append('%s@%s' % (recipient.attrib['name'], group.attrib['domain']))
            self.email = str(self.to_addresses)
            logging.debug('email distribution list is: %s' % self.to_addresses)

    def Mail_Report(self, subject=None, recipients=None, **options):
        import smtplib
	logging.debug('Subject: %s\nrecipients: %s' % (subject, recipients))
	if subject != None:
		self.subject = subject
        logging.debug('email distro is %s' % self.email)

        if recipients != None:
            for recipient in recipients.split(','):
                self.to_addresses.append('%s.secureworks.com' % recipient)
        logging.debug(
            'Processing Mail Report keyword...\n\tDistribution:%s\n\tsubject: %s\n\tTo: %s\n\tBody:%s' % (
                self.email, self.subject, self.to_addresses, self.content))
        content = self.content
        self.content = 'Test Configuration:\n%s\n' % self.test_config
        """
        if 'attach' in options:
                self.mailAttachemnts(self.subject, self.to_addresses, self.content, options['attach'])
                return('Message "%s" Sent' % self.subject)
        """
        self.content += content
        body = 'Subject:%s\n\n%s' % (self.subject, self.content)
        try:
            smtpObj = smtplib.SMTP(self.smtp_server)
            smtpObj.helo(self.from_address)
            smtpObj.sendmail(self.from_address, self.to_addresses, body)
            logging.info('Successfully sent mail with subject "%s" to %s' % (
                self.subject,
                ''.join('%s;' % recipient for recipient in self.to_addresses),
            ))
            return ('Message "%s" Sent' % self.subject)
        except Exception as merror:
            logging.error('ERROR in attempting to send mail with subject "%s" to %s: %s' % (
                self.subject,
                str(self.to_addresses),
                str(merror)
            ))
            return ('ERROR sending email to %s with subject %s\n%s\n' % (
                str(self.to_addresses), self.subject, str(merror)))

    def Log_To_Mail(self, content, link=None, **options):
        logging.debug('content: %s\nlink:%s\noptions:%s' % (content, link, str(options)))

        url = 'https://%s' % self.fqdn
        if 'convert_to_link' in options:
            if content.index(DOCROOT) < 0:
                logging.debug('content does not contain DOCROOT')
            else:
                content = content.replace(DOCROOT, url)
                logging.debug('converted content to %s' % content)
                link = None
        if link != None:
            if link == 'logfile':
                linker = self.log_link
            elif link == 'reportfile':
                linker = self.report_link
            else:
                linker = None
            if linker != None:
                logging.debug('LINKER: "%s"' % str(linker))
                try:
                    ext = linker.index('html')
                except ValueError:
                    logging.error('"html" file is missing from link %s (%s) ' % (link, str(linker)))
                s = linker[21:len(linker) - 5]
                linkstr = '%s' % (linker)
                content += '\n\t%s\n' % linkstr
                logging.debug('content w/link = %s' % content)
        if 'title' in options:
            indented = '----------'
            for line in content.split('\n'):
                indented += '\n     %s' % line
            self.content += '\n%s:\n%s\n----------\n\n' % (options['title'], indented)
        else:
            self.content += content

    def Set_Mail_Subject(self, subject, **options):
        self.subject = subject

    def Update_Config(self, key, value, **options):
        logging.debug('request to update mail configuration string replacing %s value with %s,\ncurrent config:\n%s' % (
            key, value, self.test_config))
        if self.test_config.index(key) >= 0:
            for line in self.test_config.split('\n'):
                if line.startswith(key):
                    self.test_config = self.test_config.replace(line, '%s:%s' % (key, value))
                    logging.debug(
                        'replaced "%s" with "%s:%s"..config now is:\n%s' % (line, key, value, self.test_config))
                    break

    def Append_Config(self, cfg_csv, **options):
        for cfg in cfg_csv.split(','):
            self.test_config += '\t%s\n' % cfg

class Make_CSV_Session:
    @varImport()
    def __init__(self, **evars):
	self.__dict__.update(evars)
	self.evars = evars
	self.sessionfile = '%s/%s/sessions.xml' % (DOCROOT, self.ATF_User)
	logging.debug('CSV session initializing')
        if options.rest_session == True:
        	rest_var_overrides()


    def build_session_from_csv(self, csvfile, group=None, email=None, version=None, s_reset=False):

	logging.debug('%s CSV file is:%s' % (os.environ['ATF_User'],csvfile))
	if os.path.exists(self.sessionfile) and s_reset == False:
		sessionxml = etree.parse(self.sessionfile, PARSER)
		session = sessionxml.find('session')
		assert session.attrib['running'] == 'no', 'A test is already in progress fot user %s' % self.ATF_User
	var_exists = lambda v: os.environ[v] if v in os.environ else self.evars[v] if v in self.evars else ''
	inputfile = '%s/%s/%s' % (DOCROOT, self.ATF_User, csvfile)
	session = E.session(
	    E.topo(
		E.bps(
		    topo=var_exists('bps_Topology'),
		    address=var_exists('bps_IP'),
		    bpgroup=var_exists('bps_Group'),
	     	    Firstport=var_exists('bps_Firstport'),
		    Secondport=var_exists('bps_Secondport'),
		),
                E.ione(
                    topo=var_exists('ione_Topology'),
                    address=var_exists('ione_IP'),
                    ports=var_exists('ione_Ports'),
                ),
                address=var_exists('dcim_IP'),
                name=var_exists('dcim_Name'),
                dut=var_exists('device_type')
            ),
            running="yes",
            pid='',
            user=self.ATF_User,
            env=self.TestEnv
        )
        if email != None:
            session.append(E.email(email))
        if 'device_type' in self.evars:
            dev = self.device_type
	    devnode = E(dev, address=var_exists('%s_IP' % dev), name=var_exists('%s_Name' % dev))
	    if version != None:
		devnode.insert(0, E('target-ruleset', version=version))
	    session.append(devnode)
        if 'device_console' in self.evars:
            dev = self.device_console
            session.append(E(dev, address=var_exists('%s_IP' % dev), name=var_exists('%s_Name' % dev)))
        if 'device_peer' in self.evars and self.evars['device_peer'] != "None":
            dev = self.device_peer
            session.append(E(dev, address=var_exists('%s_IP' % dev), name=var_exists('%s_Name' % dev)))

	testrun = gen_tests_from_csv_file(inputfile)
	if os.path.exists('%s/%s/sessions.xml' % (DOCROOT, self.ATF_User)):
		os.unlink('%s/%s/sessions.xml' % (DOCROOT, self.ATF_User))
	
	tests = E.tests()
	for suiteX in testrun:
		suite = suiteX.keys()[0]
		for token in suiteX[suite].split(','):
			if suite != group:
				tpath = '%s/%s/%s/%s.txt' % (DOCROOT, group, suite, token)
			else:
				tpath = '%s/%s/%s.txt' % (DOCROOT, group, token)
			if not os.path.exists(tpath):
				estr = 'There is not RF script at %s' % tpath
				logging.error(estr)
				assert os.path.exists(tpath),estr
			addtest = E.test(E.path(tpath),
					E.logs('%s/%s/logs/%s/%s' % (group, suite, token, self.TestEnv)),
					E.output('%s/%s/output/%s/%s' % (group, suite, token, self.TestEnv)),
					E.reports('%s/%s/reports/%s/%s' % (group, suite, token, self.TestEnv)),
					E.debugfiles('%s/%s/debug/%s/%s' % (group, suite, token, self.TestEnv)),
					E.output('%s/%s/output/%s/%s' % (group, suite, token, self.TestEnv)),
					name=token,
					group=group,
					suite=suite,
					status='Scheduled',
					result='Pending'
			

				)
			tests.append(addtest)
	session.append(tests)
        sessions = E.sessions(session)
	with open(self.sessionfile, 'w') as f:
		f.write(etree.tostring(sessions, pretty_print=True))
	return (etree.parse(self.sessionfile, PARSER))

def atf_lock(user, action, *tvars):
	count = 0
	BPS = 'bps'
	IONE = 'ione'
	FTD = 'ftd'
	FMC = 'fmc'
	PAN = 'pan'
	ISENSOR = 'isensor'
	logging.debug('starting to %s resources for user %s' % (action, user))
	ignore_resource = lambda r: False if 'address' in r.attrib and r.attrib['address'] != "" else True
	is_locked = lambda l, s, a: True if l.attrib[a] == s.attrib[a] else False
	lockable_resources = {
		BPS 	: ['Firstport', 'Secondport', 'bpgroup', 'address'],
		IONE	: ['ports', 'address'],
		FTD	: ['address'],
		FMC	: ['address'],
		PAN	: ['address'],
		ISENSOR	: ['address'],
		}
	lockfile = '%s/locks.xml' % DOCROOT
	if not os.path.exists(lockfile):
		with open(lockfile, 'w') as lf:
			lf.write(etree.tostring(E.locks(), pretty_print=True))
	if not os.path.exists('%s/%s/sessions.xml' % (DOCROOT, user)):
		logging.error('ERROR: missing sessiions.xml file for user %s...unable to lock resources' % user)
		return(False)
	while True: # collisions can occure so keep trying untill successfule
	    try:
		lockxml = etree.parse(lockfile, PARSER)
		break
	    except:
		logging.debug('possible collision on lockfile by user: %s' % user)
		sleep(3)
		count += 1
		assert count < 5, 'Lock file unreadable'
		continue
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
				if in_use.attrib[att] == "" or resource.attrib[att] == "":
					continue
				locked = is_locked(in_use, resource, att)
				if locked and att == 'address': # we don't care about the address as longs as the ports anf group don't match
					if resource.tag == BPS or resource.tag == IONE or resource.tag == PAN:
						locked = False
						continue
				if locked:
					msg = 'ERROR: Unable to lock resource for %s due to conflict. %s has %s locked' % (
						user, in_use.attrib['user'], att.upper())
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
	try:
       		with open('%s/locks.xml' % DOCROOT, 'w') as lfile:
       			lfile.write(etree.tostring(lockxml, pretty_print=True))
	except:
		time.sleep(3)
		count += 1
		assert count < 5, 'Lock file unwriteable'
	msg = 'SUCCESS: Resources %sed for %s' % (action, user)
	logging.info(msg)
	return(msg)

def rest_var_overrides():
    
    	tokens = {
		'bpGroup' 	: 'bps_Group',
		'bpIP'		: 'bps_IP',
		'bp_port2'	: 'bps_Firstport',
		'bp_port1'	: 'bps_Secondport',
		'bpTopo'	: 'bps_Topology',
		'ioneIP'	: 'ione_IP',
		'ionePorts'	: 'ione_Ports',
		'ioneTopo'	: 'ione_Topology',
		'dcim'		: 'dcim_Name',
		'dcimIP'	: 'dcim_IP',
		'ip'		: 'isensor_IP',
		'pan_ip'	: 'pan_IP',
		'ftd_ip'	: 'ftd_ip',
		}
    	for token in tokens.keys():
		if options.__dict__[token] != None:
			eng_var = token
			env_var = tokens[token]
			value = options.__dict__[eng_var]
			os.environ[env_var] = value
			logging.debug('export %s=%s' % (env_var, value))
	if options.ip != None:
		os.environ['isensor_Name'] = options.ip

def file_cleanup(user, **opts):
	udir = '%s/%s' % (DOCROOT, user)
	if not os.path.exists(udir):

		tmp_files = glob('/tmp/*.err')
		tmp_files.append(glob('/tmp/*.out'))
		print ('%d tmp files to delete\n' % len(tmp_files))
		for tfile in tmp_files:
			os.unlink(tfile)
		return
	err_files = glob('%s/*.test_errors.txt' % udir)
	print('%d files to delete\n' % len(err_files))
	for efile in err_files:
		os.unlink(efile)
		print('%s deleted' % efile)
	
	

if __name__ == "__main__":
    global options
    optprsr = OptionParser(usage="Usage %s <options> <user> <environment>" % sys.argv[0])
    optprsr.add_option('-t', '--addtest', action='store', dest='test', default=None)
    optprsr.add_option('-g', '--group', action='store', dest='group', default=None)
    optprsr.add_option('-s', '--suite', action='store', dest='suite', default=None)
    optprsr.add_option('-e', '--email', action='store', dest='email', default=None)
    optprsr.add_option('-r', '--reset', action='store_true', dest='reset', default=False)
    optprsr.add_option('-v', '--ruleset-version', action='store', dest='version', default='', help='Version of the target ruleset (e.g. 2.9.7.5.501)')
    optprsr.add_option('-G','--bp-group', action='store', dest='bpGroup', default=None, help="Specifies the Breaking Point group")
    optprsr.add_option('-k','--ione', action='store', dest='ioneIP', default=None, help='IOne IP address')
    optprsr.add_option('-M','--ione-topo', action='store', dest='ioneTopo', default=None, help='IOne topology')
    optprsr.add_option('-m','--ione-ports', action='store', dest='ionePorts', default=None, help='IOne port pair (e.g. "p1p2:p1p1"')
    optprsr.add_option('-T','--bp-topo', action='store', dest='bpTopo', default=None, help='Set up  Breaking Point topology: <BPTOPO>')
    optprsr.add_option('-f', '--testfile', action='store', dest='testfile', default=None)
    optprsr.add_option('-b','--breaking-point-ip', action='store', dest='bpIP', default=None, help='Use Breaking Point located @ ip-address: <bpIP>')
    optprsr.add_option('','--bp-port1', action='store', dest='bp_port1', default=None,
		help='Use Breaking Point port-pair <BPPORTS>, format is: "slot:port1" (e.g. "1,6"). Ports begin at zero')
    optprsr.add_option('','--bp-port2', action='store', dest='bp_port2', default=None,
		help='Use Breaking Point port-pair <BPPORTS>, format is: "slot:port2" (e.g. "1,7"). Ports begin at zero')
    optprsr.add_option('-I','--iSensor', action='store', dest='ip', default=None, help='IP address of the iSensor under test')
    optprsr.add_option('-P','--pan', action='store', dest='pan_ip', default=None, help='IP address of the PAN device under test')
    optprsr.add_option('-F','--ftd', action='store', dest='ftd_ip', default=None, help='IP address of the FTD device under test')
    optprsr.add_option('-D','--dcim', action='store', dest='dcim', default=None, help='The DCIM. (default=LabManager)')
    optprsr.add_option('-d','--dcim-address', action='store', dest='dcimIP', default=None, help='The DCIM IP address. (default="172.16.250.200")') 
    optprsr.add_option('-R','--rest_launch', action='store_true', dest='rest_session', default=False,
		help='Used by REST service only')
    optprsr.add_option('','--clean', action='store', dest='clean', default=None, help=('remove test errorfiles'))
    optprsr.add_option('','--title', action='store', dest='title', default=None, help=('insert <title> into mail subject'))

    options, cliargs = optprsr.parse_args()
    logging.info('ATF engine starting up with arguments %s' % str(sys.argv))
    logging.debug('options: %s' % str(options))
    logging.debug('cliargs: %s' % str(cliargs))
    try:
        nargs = len(cliargs)
        user = cliargs[0] if nargs > 0 else os.environ['ATF_User']
        environment = cliargs[1] if nargs > 1 else os.environ['TestEnv']
        testid = cliargs[2] if nargs > 2 else None
	varfile = cliargs[3] if nargs > 3 else None

    except Exception as estr:
        logging.error('ERROR: bad arguments...%s' % str(estr))
        print(str(estr))
        exit(1)

    if options.clean == True:
	file_cleanup(user)
	exit(0)
    try:
	if options.testfile == None:
		if options.suite == None:
			options.suite = options.group	
		with open('%s/%s/temp.csv' % (DOCROOT, user), 'w') as csv:
			csv.write('%s,%s\n' % (options.suite, options.test))
		options.testfile = 'temp.csv'

	if options.testfile != None:
		logging.debug('CSVFILE: %s' % options.testfile)
		csvfile = '%s/%s/%s' % (DOCROOT, user, options.testfile)
		if not os.path.exists(csvfile):
			errstr = 'ERROR: test CSV file "%s" does not exist' % options.testfile
			print(errstr)
			logging.error(errstr)
			exit(1)
    		CSV = Make_CSV_Session(environment, user)
		CSV.build_session_from_csv(options.testfile, options.group, options.email, options.version, options.reset)
		lock = atf_lock(user,'lock')
		logging.info(lock)
		if lock.startswith('ERROR'):
			print lock
			exit(1)
		if testid == None:	
			testid = user + '-' + time.strftime('%Y%m%d_%H%M%S')
		try:
			S = Session(environment, user, ID=testid)
			logging.debug('session created from csv file: %s: %s' % (options.suite, options.test))
			logging.debug('entering monitor session for user %s' % os.environ['ATF_User'])
			S.monitor_testrun()
			lock = atf_lock(user,'unlock')
			logging.info(lock)
			if ABORT_REQUEST != 0:
				x = S.mail_testrun_update(testid, 'Aborted', options.title)
				exit(1)
			x = S.mail_testrun_update(testid, 'Completed', options.title)
			del S
		except Exception as exstr:
			test_errors = '%s/%s/%s.test_errors.txt' % (DOCROOT, os.environ['ATF_User'], testid)
		        with open(test_errors, 'a') as ef:
                		ef.write('Testrun failed due to a catastrophic EXCEPTION:\n\t')
                		exc_type, exc_value, exc_traceback = sys.exc_info()
                		traceback.print_exception(exc_type, exc_value, exc_traceback,limit=2, file=ef)
			raise AssertionError, str(exstr)
    except Exception as estr:
	import smtplib
        logging.error('ERROR: %s' % str(estr))
	sfile = '%s/%s/sessions.xml' % (DOCROOT, user)
	if os.path.exists(sfile):
	
		xml = etree.parse(sfile)
		session = xml.find('session')
		if session.attrib['running'] == 'yes':
			session.attrib['running'] = 'no'
			session.attrib['pid'] = ''
			tests = session.xpath('//test')
			for test in tests:
				test.getparent().remove(test)
			with open(sfile, 'w') as ws:
				ws.write(etree.tostring(xml, pretty_print=True))
	test_errors = '%s/%s/%s.test_errors.txt' % (DOCROOT, os.environ['ATF_User'], testid)
	with open(test_errors, 'a') as ef:
		ef.write('Testrun failed due to a catastrophic EXCEPTION:\n\t')
		exc_type, exc_value, exc_traceback = sys.exc_info()
		traceback.print_exception(exc_type, exc_value, exc_traceback,limit=2, file=ef)
	with open(test_errors, 'r') as rf:
		fatal = rf.read()
		logging.error(fatal)
	exit(1)
	subject = 'ATF INTERNAL ERROR'
	content = '\nTest Run ID: %s encountered a FATAL catastrophic error...\n\n' % testid
	admin = etree.parse('%s/admin/%s_servers.xml' % (DOCROOT, environment.lower()))
	smtp_server = admin.find('atf/mail-server').attrib['url']
	from_address = admin.find('atf/mail-client').attrib['url']
	smtpObj = smtplib.SMTP(smtp_server)
	smtpObj.helo(from_address)
	email = etree.parse('%s/admin/email.xml' % DOCROOT)
	group = email.find('group[@name="ATF-Administrator"]')
	if group == None:
		trap
	domain = group.attrib['domain']
	recipients = group.findall('recipient')
	rlist = []
	for r in recipients:
		rlist.append(r.attrib['name'])
	body = subject + content + fatal
	print from_address
	print rlist
	print body
	k = smtpObj.sendmail(from_address,rlist, body)
	print k
	time.sleep(4)
        exit(1)
    exit(0)

