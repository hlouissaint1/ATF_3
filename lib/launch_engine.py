#! /usr/bin/python

import sys
import os
import time
from lxml import etree
from lxml.builder import E
import random
import subprocess
import logging
import re
import signal
from axsess import Password
from atfvars import varImport
from Queue import Queue
from threading import Thread, Event, Lock
from tempfile import mkstemp
from glob import glob
import cgi
from shutil import move
from copy import deepcopy
import inspect

DOCROOT = '/var/www/html/htdocs'
CGIPATH = '/var/www/cgi-bin'
PARSER = etree.XMLParser(remove_blank_text=True)
UNASSIGNED = 'UNASSIGNED'
global ABORT_REQUEST
ABORT_REQUESTS = {}
TEST_IN_PROGRESS = None

NOW = lambda: time.time()
ELAPSED = lambda t: NOW() - t
LOCATION = lambda L: '@location="%s" or @location="%s" or @location="ANY"' % (L.capitalize(), L.lower())
LOGPATH = '/var/www/cgi-bin'
LOG = 'ATF.log'

logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)


def abort_request_handler(signum, frame):
    """
    Handles SIGTERMs to gracefully stop all or a specific test-run.
    Abort requests can come in from the REST service or it can be killed from a bash prompt.
    """
    global ABORT_REQUESTS
    global TEST_IN_PROGRESS
    logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
    logging.info('SIGUSR2 signal raised')
    userxml = etree.parse('%s/users.xml' % DOCROOT, PARSER)
    users = userxml.xpath('//user')
    unabort = None
    for user in users:
        trnode = user.find('testrun')
        if trnode != None and 'abort' in trnode.attrib:
            if user.attrib['name'] not in ABORT_REQUESTS:
                pid = TEST_IN_PROGRESS
                ABORT_REQUESTS[user.attrib['name']] = (pid, False)
                unabort = trnode.attrib.pop('abort')
                logging.info('An abort request was received from user %s to kill pid %s' % (user.attrib['name'], pid))
    if unabort != None:
        with open('%s/users.xml' % DOCROOT, 'w') as userfile:
            userfile.write(etree.tostring(userxml, pretty_print=True))
    logging.info('ABORT_REQUESTS array: %s' % str(ABORT_REQUESTS))
    if len(ABORT_REQUESTS) == 0:  # this SIGTERM probably came in from the bash prompt
        logging.info('ABORT_REQUESTS array is empty...launch_engine exiting')
        exit(-2)
    for user in ABORT_REQUESTS:
        pid, terminated = ABORT_REQUESTS[user]
        if terminated == False:  # don't send more then one SIGTERM else pybot will exit before it can shut down the test gracefully
            try:
                if TEST_IN_PROGRESS != None:
                    os.kill(int(pid), signal.SIGTERM)
                    logging.info('SIGTERM sent to pid %s' % pid)
                    TEST_IN_PROGRESS = None
            except:
                pass  # the test ended before it could be killed
            ABORT_REQUESTS[user] = (
                pid, True)  # thread monitor will stop the threads and remove the request from the list
    with open('%s/users.xml' % DOCROOT, 'w') as userfile:
        userfile.write(etree.tostring(userxml, pretty_print=True))
    return


signal.signal(signal.SIGUSR2, abort_request_handler)


def test_generator(user, xml):
    order_by_name = lambda t1, t2: -1 if t1.attrib['name'] <= t2.attrib['name'] else 1
    scheduled_tests = xml.xpath('//test[@status="Scheduled"]')
    sorted_tests = sorted(scheduled_tests, order_by_name)
    for test in sorted_tests:
        yield test


def missing_var(error, varname, **kwords):
    logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
    rvar = {}
    logging.debug('WARNING: session file is missing attribute %s in node %s' % (error, varname));
    for v in kwords:
        rvar[v] = 'UNASSIGNED'
    return (rvar)


class UIPresentation:
    def __init__(self, user, location):
        self.testsxml = etree.parse('%s/%s/tests.xml' % (DOCROOT, user), PARSER)
        # self.devicesxml = etree.parse('%s/%s/%s_servers.xml' % (DOCROOT, user, location.lower()), PARSER)
        self.group = None
        self.suite = None
        self.active_test = None
        self.test_queue = []

        def triggerUIError(UIError):
            if UIError == None:
                logging.info("No UI Error to trigger")
                return
            errstr, color = UIError
            estr = errstr.strip('\'')
            estr = estr.split('\r')[0]
            logging.info('DEBUG: %s ' % estr)
            session_file = '%s/%s/sessions.xml' % (DOCROOT, form['User'])
            try:
                sxml = etree.parse(session_file, PARSER)
                existing_error = sxml.find('error')
                root = sxml.getroot()
                if existing_error != None:
                    root.remove(existing_error)

                root.append(E.error(estr, color=color, timestamp=NOW()))
                logging.error('Session update with %s error %s' % (color, estr))
                with open(session_file, 'w') as f:
                    f.write(etree.tostring(sxml, pretty_print=True))
            except:
                logging.error('Failed session update with %s error %s' % (color, estr))


class Session:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        self.evars = evars
        if 'ID' in evars:
            ID = self.ID
        else:
            ID = self.ID = time.strftime('%Y%m%d_%H%M%S') + '.' + self.ATF_User
        self.sessionfile = '%s/%s/sessions.xml' % (DOCROOT, self.ATF_User)
        self.presentionfile = '%s/%s/tests.xml' % (DOCROOT, self.ATF_User)
        self.sessionsxml = etree.parse(self.sessionfile, PARSER)
        self.devicesfile = '%s/%s/%s_servers.xml' % (DOCROOT, self.ATF_User, self.TestEnv.lower())
        session = self.sessionsxml.find('session')
        self.devicesxml = etree.parse(self.devicesfile, PARSER)
        self.lock = Lock()
        self.threads = []
        scheduled_tests = test_generator(self.ATF_User, self.sessionsxml)
        presention_testxml = etree.parse(self.presentionfile, PARSER)
        self.testrunfile = '%s/%s/testrun_summary.xml' % (DOCROOT, self.ATF_User)
        try:
            self.testrunxml = etree.parse(self.testrunfile, PARSER)
        except:
            tr = E.testrun(E.tag('N/A'), id=str(ID))
            tr.set('start-time', str(time.time()))
            tr.set('total-passed', '0')
            tr.set('total-failed', '0')
            tr.set('total-blocked', '0')
            tr.set('total-aborted', '0')
            tr.set('total-tests', '0')
            testlist = test_generator(self.ATF_User, self.sessionsxml)
            for test in testlist:
                t = E.test()
                for att in test.attrib:
                    t.set(att, test.attrib[att])
                tr.append(t)
            self.testrunxml = E('testrun-summary', tr)
            with open(self.testrunfile, 'w') as f:
                f.write(etree.tostring(self.testrunxml, pretty_print=True))

        while True:
            try:
                test = scheduled_tests.next()
                try:
                    ptests = presention_testxml.xpath('//testsuites')[0].xpath(
                        '//test[@name="%s"]' % test.attrib['name'])
                except Exception as estr:
                    logging.debug(
                        'ERROR: locating scheduled test "%s" in presentation file:\n%s' % (test.attrib['name'], estr))
                    continue
                if len(ptests) > 0:
                    ptest = ptests[0]
                    ptest.set('lastresult', 'Scheduled')
                    ptest.set('pcnt', '0.0')
            except StopIteration:
                with open(self.presentionfile, 'w') as presentionfile:
                    presentionfile.write(etree.tostring(presention_testxml, pretty_print=True))
                break

        if session.attrib['running'] != 'yes':
            session.set('running', 'yes')
            queue = Queue()
            tests = test_generator(self.ATF_User, self.sessionsxml)
            threads = []
            while True:
                try:
                    test = tests.next()
                except StopIteration:
                    break
                if ID == None:
                    ID = time.strftime('%Y%m%d_%H%M%S') + '.' + self.ATF_User + '.' + test.attrib['name'] + '.'
                else:
                    try:
                        index = ID.index(self.ATF_User)
                        ID = ID[0:index + len(self.ATF_User)]
                    except ValueError:
                        pass
                    ID += '.%s.' % test.attrib['name']
                efd, efile = mkstemp(prefix='atf.%s' % ID, suffix='.err')
                ofd, ofile = mkstemp(prefix='atf.%s' % ID, suffix='.out')
                cancel_flag, start_flag, end_flag, result_flag, error_flag = self.get_event_flags()
                thread_parameters = (
                    ID, self.ATF_User, test, (efd, efile), (ofd, ofile), cancel_flag, start_flag, end_flag, result_flag,
                    error_flag)
                worker = Thread(target=self.launch_test, args=(thread_parameters, queue))
                threads.append({'parameters': thread_parameters, 'object': worker})
                worker.daemon = True
                worker.start()
            self.threads = threads
            self.queue = queue
            logging.info('Session started: found %d scheduled tests to run' % len(threads))
        else:
            session.set('update', 'yes')
            logging.info('Reentrant %s session' % self.ATF_User)
        self.update_session_file(self.sessionsxml)

    def start_test_run(self):
        logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.monitor_test(self.ATF_User, self.TestEnv, self.threads, self.queue)

    def get_event_flags(self):
        cancel_flag = Event()  # signal when user stops or cancel a test
        cancel_flag.clear()
        start_flag = Event()  # signal when launch_test has called pybot
        start_flag.clear()
        end_flag = Event()  # signal when the thread has ended
        end_flag.clear()
        result_flag = Event()  # signal the test result 0 = fail, 1 = pass
        result_flag.clear()
        error_flag = Event()  # there was some sort of error that terminated the pybot run prematurely
        error_flag.clear()
        return (cancel_flag, start_flag, end_flag, result_flag, error_flag)

    def monitor_test(self, user, location, T, Q):
        logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        global ABORT_REQUESTS
        global TEST_IN_PROGRESS
        running = None
        result = lambda r: 'Passed' if r.is_set() else 'Failed'
        nameof = lambda t: t.attrib['name']
        statusof = lambda t: t.attrib['status']
        starttime = NOW()
        while True:
            orphan = False
            self.lock.acquire()
            logging.debug('lock acquired')
            sessionxml = etree.parse(self.sessionfile, PARSER)
            self.lock.release()
            logging.debug('lock released')

            try:
                thread_spec = T[0]
                logging.info('test found in queue...starting thread')

            except IndexError:  # The queue is empty...all of the tests have been run
                logging.info('no more tests found in queue...checking for updates to session file')
                session = sessionxml.find('session')
                if 'update' in session.attrib and session.attrib['update'] == 'yes':
                    logging.info('session updates found')
                    session.set('update', 'no')
                    self.update_session_file(sessionxml)
                    tests = test_generator(user, self.sessionsxml)
                    while True:
                        try:
                            update_test = tests.next()
                        except StopIteration:
                            logging.info('all updates processed')
                            break
                        ID = time.strftime('%Y%m%d_%H%M%S') + '.' + user + '.' + test.attrib['name'] + '.'
                        efd, efile = mkstemp(prefix='atf.%s' % ID, suffix='.err')
                        ofd, ofile = mkstemp(prefix='atf.%s' % ID, suffix='.out')
                        cancel_flag, start_flag, end_flag, result_flag, error_flag = self.get_event_flags()
                        thread_parameters = (
                            ID, user, test, (efd, efile), (ofd, ofile), cancel_flag, start_flag, end_flag, result_flag,
                            error_flag)
                        worker = Thread(target=self.launch_test, args=(thread_parameters, Q))
                        T.append({'parameters': thread_parameters, 'object': worker})
                        worker.daemon = True
                        worker.start()
                    if len(T) > 0:
                        session.set('running', 'yes')
                    self.update_session_file(sessionxml)
                    continue
                else:
                    session.set('running', 'no')
                    session.set('refresh', '60000')

                self.update_session_file(sessionxml)
                break;
            ID, user, test, efile, ofile, cancel_flag, start_flag, end_flag, result_flag, error_flag = thread_spec[
                'parameters']
            thread = thread_spec['object']
            if user in ABORT_REQUESTS:
                cancel_flag.set()

            if not cancel_flag.is_set():  # start up the first test thread in queue unless it has already been cancelled
                starttime = NOW()
                start_flag.set()
                self.set_test_status(T[0], starttime, [])
            else:  # otherwise pop it from the stack, update the presentation file then go on to the next test
                start_flag.set()  # unblock the thread and let the cancel flag prevent the test from starting up.
                self.set_test_status(T.pop(0), starttime, [])
                continue

            # read the session file and check for updates (e.g., cancelled tests, new tests added, etc.)
            try:
                process = Q.get(True, 120)  # block until the thread starts up pybot and queues the pid
                if process != None:
                    TEST_IN_PROGRESS = pid = process.pid
                    logging.info('Received pid %d from launch thread running test %s' % (pid, test.attrib['name']))
                else:
                    logging.info('launch thread failed for test %s' % (test.attrib['name']))

            except:
                logging.info('Timed out waiting for process object to be sent from launch thread running test %s' % (
                    test.attrib['name']))
                # check for more tests here
                break
            log_event = True
            while not end_flag.is_set():
                # read session file again to see if this thread's test gets cancelled
                self.lock.acquire()
                sessionxml = etree.parse(self.sessionfile, PARSER)
                self.lock.release()
                updates = sessionxml.xpath('//test[@name="%s"]' % test.attrib['name'])
                if len(updates) == 0:
                    end_flag.set()
                    orphan = True
                    break
                update = updates[0]
                if statusof(update) == 'Cancelled' or statusof(update) == "Aborting":
                    cancel_flag.set()
                self.set_test_status(T[0], starttime, [], log_event)
                if log_event == True:
                    log_event = False
                time.sleep(1)
            if orphan is False:
                logging.debug('no orphans found...waiting for test documents')
                testfiles = Q.get(True,
                                  60)  # blocks until pybot exits, the thread it puts the list of test files in the queue to be picked up here
                logging.debug('test documents received:\n%s' % str(testfiles))
                self.set_test_status(T.pop(0), starttime, testfiles)
            else:
                testfiles = None
            continue

            try:
                update_test = tests.next()
            except StopIteration:
                logging.debug('no more tests in this test run')
                # tests = test_generator(user, self.sessionsxml) # the last read of the session file should have picked up any new tests added
                break
            time.sleep(1)
        logging.info("Monitor ended for %s session" % user)
        if user in ABORT_REQUESTS:
            discard = ABORT_REQUESTS.pop(user)
        return

    def update_session_file(self, xml):
        logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        self.lock.acquire()
        # logging.info('launch_engine:update_session_file - lock acquired')
        with open(self.sessionfile, 'w') as f:
            f.write(etree.tostring(xml, pretty_print=True))
        self.lock.release()
        # logging.info('launch_engine:update_session_file - lock released')
        return

    def set_test_status(self, thread_spec, stime, testfiles, log_event=True):
        logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        flag = lambda s: 'yes' if s.is_set() else 'no'
        ID, user, test, efile, ofile, cancel_flag, start_flag, end_flag, result_flag, error_flag = thread_spec[
            'parameters']
        try:
            location = test.attrib['location']
        except:
            location = 'undefined'
        logging.debug('\n\tID:%s, user:%s, test:%s, cancel:%s, start:%s, end:%s, result:%s, error:%s' % (
            ID, user, test.attrib['name'], flag(cancel_flag), flag(start_flag), flag(end_flag), flag(result_flag),
            flag(error_flag)))
        testname = test.attrib['name']
        group = test.attrib['group']
        suite = test.attrib['suite']
        logging.debug('test = \n%s\n' % str(test.attrib))
        self.lock.acquire()
        xml = etree.parse(self.sessionfile, PARSER)
        session = xml.find('session')
        self.lock.release()
        status = None
        if error_flag.is_set():
            status = 'Error' if not user in ABORT_REQUESTS else 'Aborted'
        elif cancel_flag.is_set():
            if start_flag.is_set():
                status = 'Aborted'
                logging.debug('test %s ABORTED' % testname)
            else:
                logging.debug('test %s CANCELLED' % testname)
                status = 'Cancelled'
        elif start_flag.is_set():
            if not end_flag.is_set():
                logging.debug('test %s RUNNING' % testname)
                status = 'Running'

            else:  # the test has ended, remove it from the session file
                """
                ancestors = test.iterancestors()
                ancestor = {}
                while True:
                    try:
                    anc = ancestors.next()
                    ancestor[anc.tag] = anc.attrib[['name']
                    except StopIteration:
                    break;
                """
                logging.info('test %s ENDED with status of %s' % (testname, str(status)))
                poptest = xml.xpath('//testrun/test[@name="%s"]' % test.attrib['name'])
                try:
                    poptest[0].getparent().remove(poptest[0])
                except IndexError:
                    pass
                testruns = xml.find('//testrun')
                txml = etree.tostring(testruns, pretty_print=True)
                self.update_session_file(xml)
                if status == None:
                    status = 'Passed' if result_flag.is_set() == True else 'Failed'
                # update the locations of the output files
                fx = 0
                """
                        for filetype in testfiles:
                    outfile = '%s/%s' % (DOCROOT,testfiles[filetype])
                            base = os.path.basename(outfile)
                            dirname = os.path.dirname(outfile)
                            newbase = base.replace(test.attrib['name'], '%s.%s' % (test.attrib['name'], status))
                    newname = '%s/%s' % (dirname, newbase)
                    try:
                    matches = re.findall('\.(Failed|Passed)',outfile)
                    for match in matches:
                        outfile = outfile.strip(match)
                    os.rename(outfile, newname)
                        testfiles[filetype] = newname
                    except OSError as errstr:
                    raise AssertionError, 'launch_engine:set_test_status: renamed %s->%s\n%s' % (outfile, newname, errstr)
                        """
        if status == None:  # test is scheduled but hasn't yet started up...no need to update presentation file
            logging.debug('test %s has no status update' % testname)
            return
        self.update_session_file(xml)

        logging.debug('updating test %s with status="%s"' % (testname, status))

        if testfiles:
            logging.info('updating locations for test output files in %s' % self.TestEnv)
            path = test.find('path').text
            dirname = os.path.dirname(path)
            logpath = '../%s/%s/logs/%s/%s' % (group, suite, testname, self.TestEnv)
            lognode = test.find('lastlog')
            if lognode != None:
                lognode.getparent().remove(lognode)
            test.insert(0, E.lastlog('%s/%s' % (logpath.replace(' ', '_'), os.path.basename(testfiles['logs']))))
            rptpath = '../%s/%s/reports/%s/%s' % (group, suite, testname, self.TestEnv)
            reportnode = test.find('last')
            if reportnode != None:
                reportnode.getparent().remove(reportnode)
            test.insert(0, E.last('%s/%s' % (rptpath.replace(' ', '_'), os.path.basename(testfiles['reports']))))
            archives = {'reports': rptpath.replace(' ', '_'), 'logs': logpath.replace(' ', '_')}
            for archivenode in archives:
                rnode = test.find(archivenode)
                if rnode is not None:
                    test.remove(rnode)
                else:
                    logging.debug('Unable to locate "%s" archive path' % archivenode)
                test.append(E(archivenode, archives[archivenode]))

        test.set('lastresult', status)
        test.set('lastran', time.strftime('%Y-%m-%d %H:%M:%S'))
        stats = test.find('stats')
        if stats == None:
            stats = E.stats()
            test.insert(0, stats)
        stats.set('runtime', '%8.2f' % ELAPSED(stime))
        logging.debug('test %s stats = %s' % (testname, str(stats.attrib)))

        if end_flag.is_set():
            logging.info('test %s end flag is set' % testname)
            stats.set('successful-runtime', '%8.2f' % ELAPSED(stime))
            stats.set('pcnt', '100.0')
            test.set('status', 'Completed')
        elif start_flag.is_set():
            logging.debug('test %s start flag is set, end_flag is not set' % testname)
            sruntime = float(stats.attrib['successful-runtime'])
            if sruntime != 0.0:
                pcnt = ((ELAPSED(stime) * 100) / sruntime)
            else:
                pcnt = 0.0
            stats.set('pcnt', '%8.2f' % pcnt)
            test.set('status', 'Running')
        try:
            trxml = etree.parse('%s/%s/testrun_summary.xml' % (DOCROOT, user), PARSER)
            testrun = trxml.find('testrun')
            trtest = testrun.find('test[@name="%s"]' % testname)
            if trtest == None:
                logging.error('testrun_summary does not contain a test name %s: \n%s' % (
                    testname, etree.tostring(testrun, pretty_print=True)))
            trtest.set('status', test.attrib['status'])
            if test.attrib['status'] == 'Completed':
                trtest.set('result', test.attrib['lastresult'])
                """
                if test.attrib['lastresult'] == 'Passed':
                    pegcount = int(testrun.attrib['total-passed'])
                    testrun.set('total-passed',str(pegcount + 1))
                elif test.attrib['lastresult'] == 'Failed':
                    pegcount = int(testrun.attrib['total-failed'])
                    testrun.set('total-failed',str(pegcount + 1))
                elif test.attrib['lastresult'] == 'Aborted':
                    pegcount = int(testrun.attrib['total-aborted'])
                    testrun.set('total-aborted',str(pegcount + 1))
                """
            else:
                trtest.set('result', 'Pending')
            trtest.set('group', group)
            trtest.set('suite', suite)
            starttime = testrun.attrib['start-time']
            trtest.set('run-time', str(int(ELAPSED(float(starttime)))))
            trtest.set('heartbeat', str(NOW()))
            total_tests, total_passed, total_failed, total_aborted, tests_queued = [0, 0, 0, 0, 0]
            for testnode in testrun.findall('test'):
                total_tests += 1
                if testnode.attrib['status'] != 'Completed':
                    tests_queued += 1
                    continue

                if testnode.attrib['result'] == 'Passed':
                    total_passed += 1
                elif testnode.attrib['result'] == 'Failed':
                    total_failed += 1
                elif testnode.attrib['result'] == 'Error':
                    total_aborted += 1
                elif testnode.attrib['result'] == 'Aborted':
                    total_aborted += 1

            testrun.set('total-passed', str(total_passed))
            testrun.set('total-failed', str(total_failed))
            testrun.set('total-aborted', str(total_aborted))
            testrun.set('total-tests', str(total_tests))
            if total_passed + total_failed + total_aborted + tests_queued != total_tests:
                logging.error('Bad Accounting!, total:%d, passed:%d, failed:%d, aborted:%d, queued:%d\n%s\n%s' % (
                    total_tests,
                    total_passed,
                    total_failed,
                    total_aborted,
                    tests_queued,
                    etree.tostring(testrun, pretty_print=True),
                    etree.tostring(test, pretty_print=True)
                )
                              )
            """
            logging.info('launch_engine:set_test_status - Updating test summary - total:%d, passed:%d, failed:%d, aborted:%d' % (
                    total_tests,
                    total_passed,
                    total_failed,
                    total_aborted)
                    )
            """
            with open('%s/%s/testrun_summary.xml' % (DOCROOT, user), 'w') as trfile:
                trfile.write(etree.tostring(trxml, pretty_print=True))
        except Exception as estr:
            logging.error('unhandled exception: %s' % str(estr))

        logging.debug('updating test %s in presentation file' % testname)
        # now update the presentation file
        xml = etree.parse(self.presentionfile, PARSER)
        xpath = '//group[@name="%s"]/suite[@name="%s"]/tests/test[@name="%s"]' % (group, suite, testname)
        tests = xml.xpath(xpath)
        if len(tests) == 0:
            logging.error('unable to locate test %s in presentation file %s using xpath:\n\t%s' % (
                testname, self.presentionfile, xpath))
            logging.error(etree.tostring(xml, pretty_print=True))
            logging.error(etree.tostring(test, pretty_print=True))
            return
        previous = tests[0]  # previous contents of presentation file
        parent = previous.getparent()
        position = parent.index(previous)
        parent.remove(previous)
        inserted_test = deepcopy(test)
        parent.insert(position, inserted_test)
        logging.debug(
            'updating presentation file with test updates: \n %s' % etree.tostring(inserted_test, pretty_print=True))
        with open(self.presentionfile, 'w') as f:
            f.write(etree.tostring(xml, pretty_print=True))
        return

    def launch_test(self, parameters, queue):
        logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        configuration_error = False
        ID, user, test, efile, ofile, cancel, start, end, result, error = parameters
        logging.info('waiting on start signal for test %s, group %s, suite %s' % (
            test.attrib['name'], test.attrib['group'], test.attrib['suite']))

        start.wait()  # wait until the test(s) queued before this one have finished or have been cancelled
        logging.info('received start signal for test %s, group %s, suite %s' % (
            test.attrib['name'], test.attrib['group'], test.attrib['suite']))

        testvars = {}
        clipars = {}
        if cancel.is_set():
            logging.info('Cancelling test %s, group %s, suite %s' % (
                test.attrib['name'], test.attrib['group'], test.attrib['suite']))
            return

        logging.info('configuring run parameters for test %s, group %s, suite %s' % (
            test.attrib['name'], test.attrib['group'], test.attrib['suite']))

        fd, varfile = mkstemp(prefix='atf.%s' % ID, suffix='.vars')
        f = open(varfile, 'w')
        # testID = time.strftime('%04Y%02m%02d.%02H%02M%02S',time.localtime(NOW()))
        testID = ID
        os.environ['TEST_TAG'] = testvars['TestID'] = testID
        testvars['VarFile'] = varfile
        outputformats = {'logs': 'html', 'reports': 'html', 'outputs': 'dbg'}
        testfiles = {}
        for outputfile in ['logs', 'reports', 'outputs']:
            fname = '%s/%s/%s/%s/%s/%s%s' % (
                test.attrib['group'].replace(' ', '_'),
                test.attrib['suite'],
                outputfile,
                test.attrib['name'],
                self.TestEnv,
                testID,  # 'TEST',
                outputformats[outputfile]
            )
            dirname = os.path.dirname(fname)
            try:
                os.makedirs(dirname)
            except OSError as e:
                pass
            testfiles[outputfile] = fname
            if outputfile == 'reports':
                os.environ['REPORTFILE'] = testvars['REPORTFILE'] = fname
            elif outputfile == 'logs':
                os.environ['LOGFILE'] = testvars['LOGFILE'] = fname
            elif outputfile == 'outputs':
                os.environ['OUTPUTFILE'] = testvars['OUTPUTFILE'] = fname

            clipars['--%s' % outputfile.rstrip('s')] = '%s/%s' % (DOCROOT, fname)
            testvars['%sFILE' % outputfile.rstrip('s').upper()] = '%s/%s' % (DOCROOT, fname)
        # define the variables input by the operator to be used by Robot Framework
        clipars['--pythonpath'] = '/var/www/html/htdocs/lib'
        testvars['PYTHONPATH'] = '/var/www/html/htdocs/lib'
        testvars['TestEnvironment'] = self.TestEnv
        testvars.update(self.evars)
        dut_this_run = None
        targetrs = []
        P = Password(self.TestEnv, self.ATF_User)
        dut_this_run = None

        for dut in ['isensor', 'pan', 'ftd']:
            logging.debug('checking if DUT is %s' % dut)
            dutnode = self.sessionsxml.xpath('//%s' % dut)
            if len(dutnode) == 0:
                logging.debug('DUT is not %s' % dut)
                continue
            logging.debug('DUT is %s' % dut)
            dut_this_run = dut
            try:
                testvars['%s_IP'] = dutnode[0].attrib['address']
            except KeyError:
                logging.error('device under test has not been configured in this ATF')
                raise AssertionError, 'invalid configuration'
            device, username, pword, creds = P.getCredentials(address=testvars['%s_IP'])
            if device != dut:
                logging.error('device does not match session configuration')
                raise AssertionError, 'invalid session configuration'
            testvars['%s_User' % dut_this_run] = username
            testvars['%s_Password' % dut_this_run] = pword
            logging.debug('credentials found for device % s' % dut_this_run)
            rs_node = dutnode[0].find('target-ruleset')
            if rs_node != None:
                testvars['targetRuleset'] = rs_node.attrib['version']
            else:
                logging.error('target ruleset is undefined')
            break

        dcim_node = self.sessionsxml.xpath('//topo')[0]
        for traffic_generator in ['bps', 'ione']:
            tgen = dcim_node.find(traffic_generator)
            if tgen != None:
                break
        if tgen == None:
            logging.info('no traffic generator exists in the configuration')
            unassigned = 'UNASSIGNED'
            testvars['dcim_Name'] = 'UNASSIGNED'

        else:
            testvars['dcim_IP'] = dcim_node.attrib['address']
            device, testvars['dcim_User'], testvars['dcim_Password'], certs = P.getCredentials(
                address=dcim_node.attrib['address'])
            unassigned = 'UNASSIGNED'
            testvars['dcim_Name'] = P.get_device(device, 'name')
            testvars['%s_IP' % tgen.tag] = tgen.attrib['address'] if 'address' in tgen.attrib else unassigned
            testvars['%s_Firstport' % tgen.tag] = tgen.attrib[
                'first-port'] if 'first-port' in tgen.attrib else unassigned
            testvars['%s_Secondport' % tgen.tag] = tgen.attrib[
                'second-port'] if 'second-port' in tgen.attrib else unassigned
            testvars['%s_Group' % tgen.tag] = tgen.attrib['bpgroup'] if 'bpgroup' in tgen.attrib else unassigned
            device, testvars['%s_User' % tgen.tag], testvars['%s_Password' % tgen.tag], certs = P.getCredentials(
                address=testvars['%s_IP' % tgen.tag])

        timer = NOW()
        logging.debug('importing presentation file %s' % self.presentionfile)
        while ELAPSED(timer) < 60:
            try:
                presentxml = etree.parse(self.presentionfile, PARSER)
                read_error = False
                logging.debug('import of presentation file successful')
                break
            except Exception as estr:
                read_error = True
                time.sleep(1)
                continue
        if read_error == True:
            logging.error('ERROR reading presentation file %s' % self.presentionfile)
            raise AssertionError, '%s\n%s' % (self.presentionfile, estr)
        suite_node = presentxml.xpath(
            '//group[@name="%s"]/suite[@name="%s"]' % (test.attrib['group'], test.attrib['suite']))

        email_node = self.sessionsxml.find('session/email')
        if email_node != None:
            testvars['email'] = email_node.text

        webvars = ''
        for tvar in testvars:
            if testvars[tvar] == '' or testvars[tvar] == None:
                testvars[tvar] = 'NULL'
            os.environ[tvar] = testvars[tvar]
            if not tvar.endswith('Password'):
                webvars += '%s,' % tvar
                f.write('--variable %s:%s\n' % (tvar, testvars[tvar]))

        os.environ['webvars'] = webvars.rstrip(',')
        f.write('--variable webvars:%s\n' % webvars.rstrip(','))
        f.close()
        logging.info('run parameters configured for test %s, group %s, suite %s' % (
            test.attrib['name'], test.attrib['group'], test.attrib['suite']))
        try:
            tpath = test.find('path').text.strip('../')
        except:
            raise AssertionError, str(test.getchildren())

        logging.info('Starting up Test %s' % tpath)

        cmdopts = ''.join(' %s %s' % (par, clipars[par]) for par in clipars)
        # define the cli args
        Pcmd = '/usr/bin/pybot -L DEBUG --RemoveKeywords WUKS -A %s %s %s/%s' % (varfile, cmdopts, DOCROOT, tpath)
        Pcmd = Pcmd.replace('--output', '--debugfile')
        logging.debug('PYBOT CMD: %s' % Pcmd)
        logging.info('launching test %s, group %s, suite %s\n\n%s\n' % (
            test.attrib['name'], test.attrib['group'], test.attrib['suite'], Pcmd))
        stderr = efile[0]
        stdout = ofile[0]
        logging.info('RF script starting up: %s' % Pcmd)
        os.putenv('varfile', varfile)

        # run pybot
        assert 'ATF_CIPHER' in os.environ, 'Missing CIPHER'
        # os.environ['ATF_CIPHER'] = '2ba29a7e2e4212cd899cca82c1c2c5ce'
        # os.environ['ATF_LIBPATH'] = '/var/www/cgi-bin/lib'
        P = subprocess.Popen(Pcmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        self.set_test_status({'parameters': parameters}, NOW(), [])
        logging.debug('Sending process object to monitor thread for pid %d' % P.pid)
        queue.put(P)
        out, err = P.communicate(None)
        os.write(stderr, err)
        os.write(stdout, out)
        if P.returncode != 0:
            error.set()
            os.write(stderr, "\nExit Code %d\nstderr:%s\nstdout:%s" % (P.returncode, err, out))
        else:
            os.write(stdout, "\nNormal Exit (child) \n")
            error.clear()
        os.close(stderr)
        with open(efile[1], 'r') as f:
            logging.debug('\nstderr:%s\n' % f.read())
        os.close(stdout)
        # print 'Child process "%s" ended with exit status %s' % (Pcmd, str(P.returncode))
        time.sleep(1)
        rerr = open(efile[1], 'r')
        rout = open(ofile[1], 'r')
        outstr = ''
        errstr = ''
        logging.info("pybot exited after running test: %s" % test.attrib['name'])
        rdstr = rout.read()
        if len(rdstr) > 0:
            outstr += rdstr
            # print '\nUpdate:\n%s\n' % rdstr
        errstr += rerr.read()
        outstr += rout.read()
        benign_errors = {
            # the 'Error' string is sometime imbedded into the output when there is no error from the test (I'm talking to you Breaking Point!)
            'MaliciousCodePassed': 'Malicious traffic was passed through the DUT',
            'TCLfubar': 'TCL commands'
        }
        for benign in benign_errors:
            regex = '(?<=(ERROR|Error)).*%s' % benign_errors[benign]
            ignore = re.findall(regex, outstr)
            if len(ignore) > 0:
                for string in ignore:
                    k = ''.join('%c' % string[x] for x in range(len(string) - 1, 0, -1))
                    outstr.replace(string, '==benign==%s==benign==' % k)
        k = outstr.find('ERROR')
        if k >= 0:
            error.set()
        k = outstr.find('Error')
        if k >= 0:
            # print 'Found Error:\n%s' % outstr[k:]
            error.set()
        regex = 'test.*total,\s+\d+\s+passed,\s+\d+\sfailed'
        match = re.findall(regex, outstr)
        try:
            failed = match[0].split(',')[2].split(' ')[1]
            passed = match[0].split(',')[1].split(' ')[1]
            if int(failed) != 0:
                result.clear()
            elif int(passed) != 0:
                result.set()
            error.clear()  # if we match the regex then there is a result...otherwise there was a lowel lever error forcing pybot to throw an exception
        except IndexError:
            print
            str(parameters)
            print
            'regex failed: %s\n%s' % (regex, outstr)
            result.clear()
            error.set()
        rerr.close()
        os.unlink(efile[1])
        rout.close()
        os.unlink(ofile[1])
        end.set()
        logging.debug('sending test docouments to monitor thread')
        queue.put(testfiles)
        logging.info('Test %s ended' % test.attrib['name'])
        print
        'Test %s ended' % test.attrib['name']
        # queue.task_done()

        logging.info(
            'test %s, group %s, suite %s ended' % (test.attrib['name'], test.attrib['group'], test.attrib['suite']))
        return

    def setTestVars(self, varfd, nodename, has_credentials=True,
                    **pars):  # setTestVars(xml, 'isensor', 'Agile', 'varfile', _IP='address',service=True)
        logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        tvars = {}
        location = self.location

        try:
            snode = self.sessionsxml.xpath('//%s' % nodename)[0]
        except IndexError:
            tvars['%s_error' % nodename] = 'node %s not found' % nodename
            for par in pars:
                tvars['%s_%s' % (nodename, par)] = UNASSIGNED
            logging.error(tvars['%serror' % nodename])
            return (tvars)
        try:
            nname = nodename
            dnode = self.sessionsxml.xpath('//%s[@name="%s"][@location="%s"]' % (nname, snode.attrib['name'], location))
            assert len(dnode) > 0, 'Test if the device is in the resource file'
        except AssertionError:
            for par in pars:
                tvars['%s_%s' % (nodename, par)] = UNASSIGNED
                logging.error('%s_%s:UNASSIGNED' % (nodename, par))
            return (tvars)
        # get the credentials of the host
        if has_credentials == True:
            # try:
            dname = nname if nname != 'topo' else 'dcim'
            logging.debug('TRAP:%s\n%s' % (dname, str(snode.attrib)))
            try:
                creds = getCredentials(dname, location=location, name=snode.attrib['name'])
                user, pword = creds[0].split(':')
                tvars['%s_User' % nodename] = user
                tvars['%s_Password' % nodename] = pword
                logging.debug('successfully retrieved credentials for %s (%s) from getCredenetials' % (
                    snode.attrib['name'], user))
            except AssertionError as estr:
                try:
                    user, pword, cert = self.getCreds(snode.attrib)
                    assert user != None and (pword != None or cert != None)
                    tvars['%s_User' % nodename] = user
                    tvars['%s_Password' % nodename] = pword
                    logging.debug('successfully retrieved credentials for %s from getCreds' % user)
                except Exception as error:
                    logging.error(str(estr) + '\n' + str(error))
                    tvars['%s_User' % nodename] = 'user undefined'
                    tvars['%s_Password' % nodename] = 'password undefined'
            except Exception as error:
                logging.error('Unknown exception %s' % str(error))
                # except:
                #    tvars['%s_error' % nodename] = 'Missing credentials for %s in %s environment' % (nodename, location)
        for par in pars:
            tvars['%s' % (par)] = snode.attrib['%s' % pars[par]]

        return (tvars)

    def getCreds(self, host):  # uses new portable credential functions
        trap
        os.environ['ATF_CIPHER'] = '0806f8ccf696515beb96daf54b677b99'
        os.environ['ATF_LIBPATH'] = '/var/www/cgi-bin/lib'
        from axsess import Password as PW

        env = self.TestEnv
        user = self.ATF_User
        logging.debug('accessing alternate credentials for host @ address: "%s", user= %s, environment= %s' % (
            host['address'], user, env))
        try:
            assert os.environ['ATF_CIPHER']
        except:
            logging.error('missing ATF cipher')
            return (None, None, None)
        try:
            P = PW(env, user)
        except Exception as error:
            logging.debug('unable to access credentials for user "%s" in environment "%s"' % (user, env))
            return (None, None, None)
        P.get_credentials(P.environment, P.user, address=host['address'])
        try:
            assert P.username != None and (P.password != None or P.certificate != None)
        except:
            logging.debug('credentials for "%s" device @ address %s not found, username="%s", environment="%s"' % (
                P.device, host['address'], user, env))
            return (None, None, None)
        logging.info('successfully retrieved credentials for device "%s"' % P.device)
        os.environ['%s_User' % P.device] = P.username
        os.environ['%s_Password' % P.device] = P.password
        return (P.username, P.password, P.certificate)


if __name__ == "__main__":
    from getpass import getuser

    print
    'USER IS:', getuser()
    try:
        user = sys.argv[1]
    except IndexError:
        logging.info('A user name was not specified')
        raise AssertionError, 'A user name was not specified %s' % str(sys.argv)
    try:
        test_environment = sys.argv[2]
    except IndexError:
        test_environment = 'Agile'
        logging.info('Test environement was not specified...using Agile as default')
    try:
        test_id = sys.argv[3]
        logging.info('webservice launched testrun ID %s' % test_id)
    except IndexError:
        test_id = None
    try:
        varfile = sys.argv[4]
        logging.info('webservice specified RF varfile %s' % varfile)
    except:
        varfile = None

    logging.info('session request from user %s to launch test run in %s' % (sys.argv[1], test_environment))
    session = Session(test_environment, user, varfile, ID=test_id)
    if len(session.threads) > 0:
        logging.info('starting test run...%d tests in queue' % len(session.threads))
        session.start_test_run()
    else:
        logging.error("No tests found in queue...something is amiss!")
    if test_id != None:  # this test run was launched by the service
        lockxml = etree.parse('%s/locks.xml' % DOCROOT, PARSER)
        lroot = lockxml.getroot()
        for lock in lockxml.xpath('//lock[@user="%s"]' % user):
            lroot.remove(lock)
        with open('%s/locks.xml' % DOCROOT, 'w') as lfile:
            lfile.write(etree.tostring(lockxml, pretty_print=True))
    logging.debug('test run ended')
