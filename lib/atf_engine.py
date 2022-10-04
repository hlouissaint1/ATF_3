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

global options
DOCROOT = '/var/www/html/htdocs'
CGIPATH = '/var/www/cgi-bin'
PARSER = etree.XMLParser(remove_blank_text=True)
global ABORT_REQUEST
ABORT_REQUESTS = {}
TEST_IN_PROGRESS = None
NOW = lambda: time.time()
ELAPSED = lambda t: NOW() - t
LOGPATH = '/var/www/cgi-bin/logs'
LOG = 'atf_engine.log'
LOGPATH = '/var/www/cgi-bin'
LOG = 'ATF.log'

logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)

TEST_ID = lambda u, n: time.strftime('%Y%m%d_%H%M%S') + '.' + u + '.' + n + '.'
logging.debug('Initialized log')


def test_generator(user, xml):
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
        self.evars = evars
	logging.debug('session initializing')
	self.pid = 0
	self.ruleset_version = options.version
        self.testrun_ID = time.strftime('%Y%m%d_%H%M%S') + '.' + self.ATF_User + '.'
        self.sessionfile = '%s/%s/sessions.xml' % (DOCROOT, self.ATF_User)
        if not os.path.exists(self.sessionfile):
            self.create_session_file()
        self.sessionsxml = etree.parse(self.sessionfile, PARSER)
        self.session = self.sessionsxml.find('session')
        if self.session.attrib['running'] == 'yes':
            raise AssertionError, 'Test is already in progress for session user: %s' % self.ATF_User
        self.test_queue = test_generator(self.ATF_User, self.sessionsxml)
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
            self.sessionsxml = self.add_new_test()
            self.session = self.sessionsxml.find('session')
            self.tests = self.session.find('tests')

        total_tests = len(self.tests.findall('test'))
        assert total_tests > 0, 'This testrun was launched with no tests defined in session file'

        # print etree.tostring(self.test_queue.next(), pretty_print=True)A
        self.test_in_progress = None
        self.varfile = None
        self.start_time = 0
        self.Process = None
        self.stats = {
            'total-passed': 0,
            'total-failed': 0,
            'total-blocked': 0,
            'total-aborted': 0,
            'total-tests': total_tests,
            'start-time': NOW(),
            'id': self.testrun_ID,
        }
        self.testrunfile = '%s/%s/testrun_summary.xml' % (DOCROOT, self.ATF_User)
        self.update_session_file(True)
        self.create_testrun_summary(self.stats)
	logging.debug('session initialized')

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

    def update_testrun_summary(self, test, stats):
        summary = etree.parse(self.testrunfile, PARSER)
        testrun = summary.find('testrun')
        counters = {}
        for stat in stats.keys():
            if stat.startswith('total'):
                counters[stat] = str(stats[stat])
        testrun.attrib.update(counters)
        uptest = testrun.find('test[@name="%s"]' % test.attrib['name'])
        uptest.attrib.update(test.attrib)
        uptest.set('run-time', str(ELAPSED(self.start_time)))
        uptest.set('heartbeat', str(NOW()))
        with open(self.testrunfile, 'w') as f:
            f.write(etree.tostring(summary, pretty_print=True))

    def write_var_file(self, ID):

        fd, varfile = mkstemp(prefix='atf.%s' % ID, suffix='.vars')
        with open(varfile, 'w') as v:
            v.write('--variable VarFile:%s' % varfile)
            for var in self.evars:
                if var.find('_Password') > 0:
                    continue
                v.write('--variable %s:%s\n' % (var, self.evars[var]))
        return (varfile)

    def update_session_file(self, rerun=False, remove=None):
        sessionsxml = etree.parse(self.sessionfile, PARSER)
        session = sessionsxml.find('session')
	session.set('pid', str(self.pid))
	session.set('running',self.running)
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
        while True:
            try:
                logging.debug('writing new session file')
                with open(self.sessionfile, 'w') as w:
                    w.write(etree.tostring(self.sessionsxml, pretty_print=True))
                break
            except IOError:
                time.sleep(1)
                continue
            except Exception as estr:
                raise AssertionError, 'ERROR: unable to update session file:%s ' % str(estr)

    def get_robot_filenames(self, test):
        logpath = os.path.dirname(
            test.find('logs').text) + '/' + self.TestEnv.capitalize() + '/' + self.testID + '.html'
        reportpath = logpath.replace('logs', 'reports')
        debugpath = logpath.replace('logs', 'debugfiles')
        rf_script = test.find('path').text
        return (rf_script, reportpath, logpath, debugpath)

    def monitor_testrun(self):
        while True:
            if self.test_in_progress == None:
                try:
                    self.test = self.test_queue.next()
                    logging.debug('Running: %s' % self.test)
                except StopIteration:
                    logging.info('no more tests in queue...testrun ended')
                    break
                self.test_in_progress = self.test.attrib['name']
                self.testID = self.testrun_ID + self.test_in_progress
                self.test.set('status', 'Running')
                self.varfile = self.write_var_file(self.testrun_ID)
                self.start_time = NOW()
                logging.debug('launching pybot...')
                self.Process, self.pid, self.outfile, out_fd, self.errfile, err_fd = self.launch_test(
                    self.get_robot_filenames(self.test))
		self.session.set('pid',str(self.pid))
                self.session.set('timestamp', str(self.start_time))
            self.test_elapsed_time = ELAPSED(self.start_time)
            rcode = self.Process.poll()
            if rcode != None:
                logging.debug('Test Ended "%s" with rcode %d' % (self.test_in_progress, rcode))
                self.test.set('status', 'Completed')
                self.test.set('result', 'Unknown')
                errstr, results = self.analyze_rf_result(out_fd, self.outfile, err_fd, self.errfile)
                count, passed, failed = results
                self.rf_test_errors = errstr
                self.test.set('status', 'Completed')
                if int(failed) > 0:
                    self.result = 'Failed'
                    self.test.set('result', 'Failed')
                    self.stats['total-failed'] += 1
                    logging.info('Test %s FAILED:\n%s' % (self.test.attrib['name'], errstr))
                elif int(passed) > 0:
                    self.result = 'Passed'
                    self.test.set('result', 'Passed')
                    self.stats['total-passed'] += 1
                    logging.info('Test %s PASSED' % (self.test.attrib['name']))
                self.update_testrun_summary(self.test, self.stats)
		self.running='no'
                self.sessionsxml = self.update_session_file(False, self.test_in_progress)
                self.session = self.sessionsxml.find('session')
                self.tests = self.session.find('tests')

                self.test_in_progress = None
            else:
		
                time.sleep(3)
            if self.test:
                self.update_testrun_summary(self.test, self.stats)
            time.sleep(1)

    def analyze_rf_result(self, fo, outfile, fe, errfile, remove_file=False):
        result_re = re.compile('^(\d+)\s+test.*(\d+)\s+passed.*(\d+)\s+failed', re.MULTILINE)
        errstr = ''
        nt = np = nf = 0
        errors = {}
        try:
            # fo.close()
            # fe.close()
            with open(outfile, 'r') as fd:
                output = fd.read()
                print('STDOUT:\n%s' % output)
            nt, np, nf = re.findall(result_re, output, )[0]
            case = None
            for line in output.split('\n'):
                if case:
                    errors[case] = line.rstrip('  ')
                    case = None
                if line.find('| FAIL |') > 0:
                    case = line.replace('| FAIL |', '').replace('  ', '')
                    continue
            with open(errfile, 'r') as fd:
                err_out = fd.read()
                print('STDERR:\n%s' % err_out)

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
        return (errstr, (nt, np, nf))

    def launch_test(self, docs):
        script, report, log, debug = docs
        print('launching test: \n%s\n%s\n%s\n%s' % (script, report, log, debug))
        err_fd, errfile = mkstemp(prefix='atf.%s' % self.testID + '.' + self.test_in_progress, suffix='.err')
        out_fd, outfile = mkstemp(prefix='atf.%s' % self.testID + '.' + self.test_in_progress, suffix='.out')
        fqdn = get_fqdn()
        print('FQDN=%s' % fqdn)
        os.environ['LOGFILE'] = log
        os.environ['REPORTFILE'] = report
        libpath = '--pythonpath /var/www/htdocs'
        Pcmd = 'pybot --outputdir /var/www/html/htdocs -L DEBUG -rpa --RemoveKeywords WUKS -A %s --log %s --report %s --debugfile %s %s' % (
            self.varfile,
            log,
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
            return (P, pid, outfile, out_fd, errfile, err_fd)

    def add_new_test(self, ):
        if options.test == None or options.group == None:
            print('missing test or test group definition')
            exit(1)

        seekpath = '/%s/%s' % (DOCROOT, options.group)
        for newtest in options.test.split(','):
            seektest = '%s.txt' % newtest
            tree = [f for f in os.walk(seekpath)]
            tpath = None
            for d in tree:
                try:
                    found = d[2].index(seektest)
                    tpath = '%s/%s/%s' % (DOCROOT, options.group, d[2][found])
                    break
                except ValueError:
                    continue
            assert tpath, 'Test named "%s.txt" cannot be found in %s/%s' % (newtest, DOCROOT, options.group)

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
                    E.reports('%s/%s/reports/%s/%s' % (options.group, options.suite, newtest, self.TestEnv)),
                    E.debugfiles('%s/%s/debug/%s/%s' % (options.group, options.suite, newtest, self.TestEnv)),
                    name=newtest,
                    group=options.group,
                    suite=options.suite,
                    status='Scheduled',
                    result='New',
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
            running="no",
	    pid=str(self.pid),
            user=self.ATF_User,
            env=self.TestEnv
        )
        if options.email:
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


if __name__ == "__main__":

    optprsr = OptionParser(usage="Usage %s <options> <user> <environment>" % sys.argv[0])
    optprsr.add_option('-t', '--addtest', action='store', dest='test', default=None)
    optprsr.add_option('-g', '--group', action='store', dest='group', default=None)
    optprsr.add_option('-s', '--suite', action='store', dest='suite', default=None)
    optprsr.add_option('-d', '--device', action='store', dest='suite', default=None)
    optprsr.add_option('-e', '--email', action='store', dest='email', default=None)
    optprsr.add_option('-r', '--reset', action='store_true', dest='reset', default=False)
    optprsr.add_option('-v', '--ruleset-version', action='store', dest='version', default='')

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
    if options.reset == True and os.path.exists('%s/%s/sessions.xml' % (DOCROOT, user)):
        os.unlink('%s/%s/sessions.xml' % (DOCROOT, user))

    try:
	logging.debug('creating session')
        S = Session(environment, user, ID=testid)
	logging.debug('session created')
    except Exception as estr:
        logging.error('ERROR: %s' % str(estr))
        print(str(estr))
        exit(1)

    S.testrun_ID
    S.monitor_testrun()
    print
    S.error

    """
    except ValueError:
        assert 'ATF_User' in os.environ and 'TestEnv' in  os.environ, 'session user or test environment undefined\n'
        user , environment = [os.environ['ATF_User'], os.environ['TestEnv']]
        varfile = None
    """
