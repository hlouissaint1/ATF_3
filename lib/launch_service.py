#!/usr/bin/env python
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
from OpenSSL import SSL
from OpenSSL.SSL import Context, Connection, SSLv23_METHOD, TLSv1_METHOD
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT, VERIFY_CLIENT_ONCE
from json import JSONDecoder, JSONEncoder, dumps
import urlparse
import subprocess
import logging
from tempfile import mkstemp
from os import unlink, getpid, fork
from lxml import etree
from lxml.builder import E
from copy import deepcopy
import time
import os
import signal
from datetime import datetime as DATE
import socket
import inspect

DOCROOT = '/var/www/html/htdocs'
CGIPATH = '/var/www/cgi-bin'
LOGPATH = '/var/www/cgi-bin/lib/logs'
xml_header = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

logging.basicConfig(format='%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/launch_service.log' % LOGPATH,
                    level=logging.DEBUG)

LAUNCH_REQUEST_SCHEMA = '%s/testrun-launch-request-schema.json' % CGIPATH
PARSER = etree.XMLParser(remove_blank_text=True)
NOW = lambda: time.time()
get_element_value = lambda e, j: j[e] if e in j else 'N/A'
ENV = 'environment'
ATF_USER = 'user'
CONFIG_PROFILE = 'configuration-profile'
TEST_GROUP = 'test-group'
HTML_BAD_REQUEST = (400, 'Bad Request')
HTML_CONFLICT = (409, 'Conflict')
HTML_UNAUTHORIZED = (401, 'Unauthorized')
HTML_NOT_FOUND = (404, 'Not Found')
HTML_REQUEST_TIMEOUT = (408, 'Request Timeout')
HTML_TOO_MANY_REQUESTS = (429, 'Too Many Requests')
HTML_INTERNAL_SERVER_ERROR = (500, 'Internal Server Error')
HTML_OK = (200, 'OK')
ATF_RUNS = {}


def check_required_elements(schema_node, request_node):
    if 'required' in schema_node:
        for required in schema_node['required']:
            assert required in request_node, (
                HTML_BAD_REQUEST, 'Request does not contain required element: %s' % required)


def validate_request(schema_node, request_node, **pars):
    newpars = {}
    check_required_elements(schema_node, request_node)
    if 'parent' in pars:
        parent = pars['parent']
    else:
        parent = None
    if 'properties' in schema_node:
        for node in request_node:
            assert node in schema_node['properties'], (HTML_BAD_REQUEST, 'Schema violation: %s' % node)
            newpars.update(
                validate_request(schema_node['properties'], request_node[node], parent=node, value=request_node[node]))

    elif 'parent' in pars:
        newpars[pars['parent']] = pars['value']
    return (newpars)


def unschedule(session, test):
    # remove the test from the users test run list
    tnode = session.find('testrun/test/[@name="%s"]' % test.attrib['name'])
    if not tnode:
        return ('Cancelled')
    if 'status' in tnode.attrib and tnode.attrib['status'] == 'Running':
        tnode.set('status', 'Aborting')
        status = tnode.attrib['status']
    else:
        tnode.getparent().remove(tnode)
        status = 'Cancelled'
    return (status)


def cancelTestRun(user):
    sessionxml = etree.parse('%s/%s/sessions.xml' % (DOCROOT, user), PARSER)
    session = sessionxml.find('session')
    if session == None or session.attrib['running'] != 'yes':
        running = False
    else:
        running = True
    assert running == True, (HTML_NOT_FOUND, 'User %s has no test run in progress' % user)
    userxml = etree.parse('%s/admin/users.xml' % DOCROOT, PARSER)
    usernodelist = userxml.xpath('//user[@name="%s"]' % user)
    assert len(usernodelist) > 0, (HTML_UNAUTHORIZED, 'User %s is not provisioned to use the ATF' % user)
    node = usernodelist[0]
    trnode = node.find('testrun')
    if trnode != None:
        trnode.set('abort', 'yes')
        try:
            pid = trnode.attrib['pid']
            logging.info('sending SIGUSR2 to launch engine running with pid=%s' % pid)
            os.kill(int(pid), signal.SIGUSR2)
        except Exception as errstr:
            logging.error(
                'Error in sending  SIGUSR2 to launch engine running with pid=%s\n%s' % (
                    pid, errstr))
    with open('%s/admin/users.xml' % DOCROOT, 'w') as userfile:
        userfile.write(etree.tostring(userxml, pretty_print=True))
    logging.info('Testrun abort request from user %s process' % user)
    logging.debug('%s' % etree.tostring(userxml, pretty_print=True))


def get_test_failure_message(name, user, **opts):
    logging.debug('entering get_test_failure_message')
    if 'tid' in opts:
        tid = opts['tid']
        logging.debug('tid = %s' % tid)
    else:
        logging.error('No test ID in REST request')
        return 'No test ID in REST request'
    test_err_file = '%s/%s/%s.test_errors.txt' % (DOCROOT, user, tid,)
    logging.debug('error file = %s' % test_err_file)
    errors = []
    with open(test_err_file) as ef:
        err_content = ef.read()
	for err in err_content.split('\n'):
		errors.append(err)
    return (errors)

    txml = etree.parse('%s/%s/tests.xml' % (DOCROOT, user))
    tnode = txml.xpath('//test[@name="%s"]' % name)
    log = tnode[0].find('lastlog').text
    output = log.replace('/logs/', '/outputs/').replace('../', '%s/' % DOCROOT).replace('.html', '.xml')
    oxml = etree.parse(output)
    error_list = oxml.xpath('//msg[@level="FAIL"]')
    errors = []
    for err in error_list:
        sibtext = err.getparent().getparent().itertext()
        skip = False
        while True:
            try:
                if sibtext.next().find('Benign') >= 0:
                    skip = True
                    break
            except StopIteration:
                break
        if skip == True:
            continue
        if 'local.rules' in err.text:
            continue
        errors.append("Script keyword '%s' propagated a failure:" % err.getparent().attrib['name'])
        for line in err.text.split('\n'):
            n = 0
            for item in line.split('. '):
                if item != '':
                    errors.append('     %s.' % item)
    return (errors)


def parse_testrun_XML(user, **opts):
    logging.debug('entering parse_testrun_XML')
    logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
    xml = etree.parse('%s/%s/testrun_summary.xml' % (DOCROOT, user))
    tnodes = xml.findall('testrun/test')
    if 'tid' in opts:
        tid = opts['tid']
    # txml = etree.parse('%s/%s/tests.xml' % (DOCROOT, user))
    trnode = xml.find('testrun')
    testrun = {'summary': {}, 'details': []}
    for att in trnode.attrib:
        testrun['summary'][att] = trnode.attrib[att]
    testrun_complete = True
    test_err_file = '%s/%s/%s.test_errors.txt' % (DOCROOT, user, tid)
    if os.path.exists(test_err_file) and os.path.getsize(test_err_file) > 0:
	with open(test_err_file, 'r') as ef:
		contents = ef.read()
		if 'EXCEPTION' in contents:
			raise AssertionError, (HTML_INTERNAL_SERVER_ERROR, contents)
				
    for test in trnode.findall('test'):
        testdata = {'test': {}}
        for att in test.attrib:
            testdata['test'][att] = test.attrib[att]
        testrun['details'].append(testdata)
        if test.attrib['status'] != 'Completed':
            testrun_complete = False
        if 'result' in test.attrib and test.attrib['result'] == 'Failed':
            try:
                error = get_test_failure_message(test.attrib['name'], user, tid=tid)
            except Exception as estr:
                error = [str(estr)]
            testdata['test']['test-errors'] = error
        else:
            testdata['test']['test-errors'] = ['No errors indicated']
	if testrun_complete != True:
		testdata['test']['test-errors'] = ['Results pending']
	else:
	    	rf_report = test.find('reportlink')
		if rf_report != None and rf_report != '':
			testdata['test']['report'] = rf_report.text
		else:
			testdata['test']['report'] = 'report link unavailable'
		rf_log = test.find('loglink') 
		if rf_log != None and rf_log != '':
			testdata['test']['log'] = rf_log.text
		else:
			testdata['test']['log'] = 'report link unavailable'
			
    testrun['summary']['status'] = 'Completed' if testrun_complete == True else 'In Progress'
    if 'summary' in opts and opts['summary'] == True:
        noop = testrun.pop('details')
    tagnode = trnode.find('tag')
    if tagnode != None:
        testrun['identification'] = tagnode.text
    else:
        testrun['identification'] = 'NA'
    return (testrun)


class ATF_Web_Service(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        client_ip, source_port = self.client_address
        logging.info('%s  (client is %s)' % (format % (args), client_ip))
        """
            with open('%s/ATF.log' % CGIPATH, 'a') as log:
                log.write(format % (args))
                log.write(' (client is %s)\n' % client_ip)
        """
        return

    def lock_resources(self, session, **opts):
        form = {}
        user = session.attrib['user']
        topo_node = session.find('topo')
        form['dcim'] = topo_node.attrib['name']
        bps_node = topo_node.find('bps')
        if bps_node != None:
            # form['bps'] = bps_node.attrib['address']
            form['bps'] = bps_node.attrib['name']
            form['topo'] = bps_node.attrib['topo']
            form['bpGroup'] = bps_node.attrib['bpgroup']
            port1 = bps_node.attrib['first-port']
            port2 = bps_node.attrib['second-port']
            form['bpPorts'] = 'Slot %s,Ports %s and %s' % (
                port1.split(',')[0], port1.split(',')[1], port2.split(',')[0])
        ione_node = topo_node.find('ione')
        if ione_node != None:
            form['ione'] = ione_node.attrib['address']
            form['ione_topo'] = ione_node.attrib['topo']
            form['ionePorts'] = ione_node.attrib['port-pair']
        isensor_node = session.find('isensor')
        pan_node = session.find('pan')
        ftd_node = session.find('ftd')
        if isensor_node == None and pan_node == None and ftd_node == None:
            raise AssertionError, (HTML_BAD_REQUEST, 'Invalid environment specification...DUT missing')
        if isensor_node != None:
            form['maddr'] = isensor_node.attrib['address']
        elif pan_node != None:
            form['maddr'] = pan_node.attrib['address']
        elif ftd_node != None:
            form['ftd'] = ftd_node.attrib['address']

        lockxml = etree.parse('%s/locks.xml' % DOCROOT, PARSER)
        lroot = lockxml.getroot()
        locks = lockxml.xpath('//lock[@user="%s"]' % user)
        for lock in locks:
            lroot.remove(lock)
        lock = E.lock(user=user)
        resources = {
            'topo': 'Breaking Point Topology',
            'bpPorts': 'Breaking Point Port Pair',
            'bpGroup': 'Breaking Point Group',
            'maddr': 'DUT Address',
            'ione_topo': 'IONE Topology',
            'ionePorts': 'IONE Port Pair',
            'ftd': 'FMC'

        }
        unassigned = {'bpPorts': 'topo', 'bpGroup': 'topo', 'topo': 'topo', 'ionePorts': 'ione_topo',
                      'ione_topo': 'ione_topo'}
        for resource in resources:
            # don't try to lock unnassigned resources
            if resource in unassigned:
                if unassigned[resource] not in form:
                    continue
                value = form[unassigned[resource]]
                if value == None or value == '' or value == 'UNASSIGNED':
                    continue

            try:
                locked = lockxml.xpath('//lock[@%s="%s"]' % (resource, form[resource]))
            except KeyError:
                continue
            if len(locked) > 0:
                if locked[0].attrib['user'] == user:
                    continue
                if (resource == 'bpPorts' or resource == 'bpGroup') and locked[0].attrib['bps'] == form['bps'] and not \
                        locked[0].attrib['bps'].startswith('UNASSIGNED'):
                    raise AssertionError, (HTML_CONFLICT, '%s: %s is in use by user: %s' % (
                        resources[resource], form[resource], locked[0].attrib['user']))
                elif resource == 'ionePorts' and locked[0].attrib['ione'] == form[
                    'ione'] and 'ione_topo' in form and not locked[0].attrib['ione'].startswith('UNASSIGNED'):
                    raise AssertionError, (HTML_CONFLICT, '%s: %s is in use by user: %s' % (
                        resources[resource], form[resource], locked[0].attrib['user']))
                elif resource == 'topo' and form['dcim'] != 'DirectConnect' and locked[0].attrib['dcim'] == form[
                    'dcim']:
                    raise AssertionError, (HTML_CONFLICT, '%s: %s is in use by user: %s' % (
                        resources[resource], form[resource], locked[0].attrib['user']))
                elif resource == 'maddr':
                    raise AssertionError, (HTML_CONFLICT, '%s: %s is in use by user: %s' % (
                        resources[resource], form[resource], locked[0].attrib['user']))
                elif resource == 'ftd':
                    raise AssertionError, (HTML_CONFLICT, '%s: %s is in use by user: %s' % (
                        resources[resource], form[resource], locked[0].attrib['user']))

            lock.set(resource, form[resource])
        if 'bps' in form:
            lock.set('bps', form['bps'])
        if ione_node != None:
            lock.set('ione', form['ione'])
        if 'dcim' in form:
            lock.set('dcim', form['dcim'])
        if 'ftd' in form:
            fmc_in_use = lockxml.xpath('//lock[@ftd="FMC locked"]')
            if len(fmc_in_use) > 0:
                if fmc_in_use[0].attrib['user'] != user:
                    raise AssertionError, (HTML_CONFLICT, '%s by user: %s' % (
                        fmc_in_use[0].attrib['ftd'], fmc_in_use[0].attrib['user']))
            lock.set('ftd', 'FMC locked')

        lroot.insert(0, lock)
        locked = True
        with open('%s/locks.xml' % DOCROOT, 'w') as lockfile:
            lockfile.write(etree.tostring(lockxml, pretty_print=True))
        return ('Lock Successful', None)

    def policy_request(self, request):
        from ctpapi import fetch_policy, store_policy

        try:
            policy = etree.fromstring(request, PARSER)
        except Exception as error:
            raise AssertionError, (HTML_BAD_REQUEST, 'ERROR parsing XML request - %s' % str(error))
        found = False
        for identity in ['idn', 'uin', 'regkey', 'ip-address', 'mac']:
            if identity in policy.attrib:
                found = True
                break
        assert found == True, (
            HTML_NOT_FOUND,
            'ERROR: identity unknown...specified XML policy request does not contain one of: "idn", "uin", "regkey", "address", or "mac"')

        imbedded_policy = policy.find('isensor-policy')
        imbedded_certs = policy.find('rcms-cert')
        stored_certs = '<rcms-cert/>'
        if imbedded_policy != None:
            try:
                updated, stored_policy = store_policy(imbedded_policy, imbedded_certs, **policy.attrib)
            except Exception as error:
                logging.error('ERROR - storing policy %s (%s) ' % (str(policy.attrib), str(error)))
                raise AssertionError, (HTML_INTERNAL_SERVER_ERROR, str(error))
        else:
            try:
                updated, stored_policy, stored_certs, policy_atts = fetch_policy(**policy.attrib)
            except Exception as error:
                if 'Policy not found' in str(error):
                    raise AssertionError(HTML_NOT_FOUND, str(error))
                raise AssertionError, (HTML_BAD_REQUEST, 'ERROR: %s' % str(error))
        code, message = HTML_OK

        response = '%s<policy-request-response code="%s" message="%s" updated="%s">\n%s%s</policy-request-response>' % (
            xml_header,
            code,
            message,
            'yes' if updated == True else 'no',
            stored_policy,
            stored_certs)
        return (response)

    def testreport(self, jobj, request):
        response = {'testrun-request-response': {}}
        resp = response['testrun-request-response']
        assert 'testrun-id' in request, (HTML_BAD_REQUEST, 'Missing testrun ID')
        resp['testrun-id'] = request['testrun-id']
        if 'identification' in request:
            resp['identification'] = request['identification'] if request['identification'] != "" else "NA"
        try:
            user = request['testrun-id'].split('.')[1]
        except IndexError:
            raise AssertionError, (HTML_BAD_REQUEST, 'Invalid test-run ID: \'%s\' supplied' % request['testrun-id'])
        try:
            trxml = etree.parse('%s/%s/testrun_summary.xml' % (DOCROOT, user))
        except:
            raise IOError
        if 'testrun-summary-only' in request:
            summary = request['testrun-summary-only']
        else:
            summary = False
        resp['results'] = parse_testrun_XML(user, summary=summary, tid=request['testrun-id'])
        if 'identification' in resp['results']:
            resp['identification'] = resp['results'].pop('identification')
        if resp['identification'] == None:
            resp['identification'] = 'NA'

        return ((HTML_OK), response)

    def launch_testrun(self, jobj, request):
        logging.debug('testrun launched: %s' % str(jobj))
        # logging.debug('calling function is %s line %d' % (inspect.stack()[1][3], inspect.stack()[1][2]))
        required_top_elements = [ENV, ATF_USER, CONFIG_PROFILE, TEST_GROUP]
        for element in required_top_elements:
            assert element in request, (HTML_BAD_REQUEST, 'Request does not contain required element: %s' % element)
        env = get_element_value(ENV, request)
        assert env in ['Pilot', 'Agile', 'Production'], (
            HTML_BAD_REQUEST, 'Invalid environment specification...should be one of: "%s"' % str(required_top_elements))
        user = get_element_value(ATF_USER, request)
        userxml = etree.parse('%s/admin/users.xml' % DOCROOT)
        usernode = userxml.find('user[@name="%s"]' % user)
        assert usernode != None, (
            HTML_UNAUTHORIZED, "Specified user '%s' has not been provisioned to use the automation server" % user)
        session_parameters = {'configuration-profile': {}}
        with open(LAUNCH_REQUEST_SCHEMA, 'r') as schemafd:
            schema = jobj.decode(schemafd.read())
        session_parameters.update(validate_request(schema['properties']['testrun'], request))
        ID = get_element_value('identification', request)
        if ID == None or ID == "":
            ID = 'NA'
        session_filename = ('%s/%s/sessions.xml' % (DOCROOT, user))
        if os.path.exists(session_filename):
            sessionxml = etree.parse(session_filename)
            session = sessionxml.find('session')
            if 'running' in session.attrib:
                if get_element_value('abort-test', request) == False:
            		assert session.attrib['running'] != 'yes', (HTML_TOO_MANY_REQUESTS, 'a test is already in progress')
            	else:
            		cancelTestRun(user)
            		response = {"testrun-request-response": {
                		'identification': ID,
                		'request-type': 'testrun-abort',
                		'testrun-id': get_element_value('testrun-id', request),
                		'test-status': 'Aborted',  # 'launch-engine-state' : {'pid': 0, 'ppid': 0, 'return-code':  'NA'},
                		'launch-date-time': DATE.isoformat(DATE.now())
            			}
            		}
            		return ((HTML_OK), response)

        # self.lock_resources(session)
        profile = get_element_value(CONFIG_PROFILE, request)
        group = get_element_value(TEST_GROUP, request)
        cmd_args = ['-g %s ' % group.replace(' ', '_')]
        if 'configuration-profile' in session_parameters:
            cfg = session_parameters['configuration-profile']
        else:
            cfg = {}

        try:
            xml = etree.parse('%s/admin/%s_servers.xml' % (DOCROOT, env.lower()), PARSER)
        except:
            raise AssertionError, (
                HTML_INTERNAL_SERVER_ERROR, 'failed to parse %s/%s/%s_servers.xml' % (DOCROOT, user, env.lower()))
        email = cfg['email'] if 'email' in cfg else 'ATF-Administrator'
        default = 'UNASSIGNED'
        cmd_args.append('-e "%s" ' % email)
        if 'dcim' in cfg:
            dcim_address = cfg['dcim']['address'] if 'address' in cfg['dcim'] else default
            dcim_name = cfg['dcim']['name'] if 'name' in cfg['dcim'] else default
            if dcim_address != default and dcim_name == default:  # look it up
                dcim_node = xml.find('dcim[@address="%s"]' % dcim_address)
                assert dcim_node != None, (HTML_BAD_REQUEST,
                                           'the specified DCIM IP address "%s" has not been provisioned on the server' % dcim_address)
                dcim_name = dcim_node.attrib['name'] if name in dcim_node.attrib else 'UNKNOWN'
                cmd_args.append('-d "%s" -D "%s" ' % (dcim_address, dcim_name))
            else:
                logging.info('DCIM supplied was not found in users configurarion...using default')
        else:
            logging.info('Using default DCIM parameters')
        if 'bps' in cfg:
            bps_address = cfg['bps']['address'] if 'address' in cfg['bps'] else default
            bps_topo = cfg['bps']['topology'] if 'topology' in cfg['bps'] else default
            if bps_address != default and bps_topo != default:
                cmd_args.append('-T "%s" -b "%s" ' % (bps_topo, bps_address))
                bps_node = xml.find('bps[@address="%s"]' % (bps_address))
                assert bps_node != None, (HTML_BAD_REQUEST,
                                          'the specified Breaking Point IP address "%s" has not been provisioned on the server' % bps_address)
                first_port = cfg['bps']['first-port'] if 'first-port' in cfg['bps'] else default
                second_port = cfg['bps']['second-port'] if 'second-port' in cfg['bps'] else default
                bpGroup = cfg['bps']['group'] if 'group' in cfg['bps'] else default
                if first_port != default and second_port != default:
                    cmd_args.append('--bp-port1 "%s" ' % first_port[0:3])
                    cmd_args.append('--bp-port2 "%s" ' % second_port[0:3])
                if bpGroup != default:
                    cmd_args.append('-G "%s" ' % bpGroup)
        else:
            logging.info('Using default BPS settings')

        if 'ione' in cfg:
            ione_address = cfg['ione']['address'] if 'address' in cfg['ione'] else default
            if ione_address != default:
                ione_node = xml.find('ione[@address="%s"]' % (ione_address))
                assert ione_node != None, (HTML_BAD_REQUEST,
                                           'the specified iOne IP address "%s" has not been provisioned on the server' % ione_address)
                cmd_args.append('-k "%s" ') % ione_address
            ione_topo = cfg['ione']['topology'] if 'topology' in cfg['ione'] else default
            if ione_topo != default:
                cmd_args.append('-M "%s" ' % ione_topo)
            ione_ports = cfg['ione']['ports'] if 'ports' in cfg['ione'] else default
            if ione_ports != default:
                cmd_args.append('-m "%s" ' % ione_ports)
        else:
            logging.info('Using default iOne settings')
        client_ip, source_port = self.client_address
        logging.info('REST request originated from %s:%s' % (client_ip, source_port))
        if 'isensor' in cfg:
            isensor_address = cfg['isensor']['address'] if 'address' in cfg['isensor'] else default
            if isensor_address != default:
                isensor_node = xml.find('isensor[@address="%s"]' % (isensor_address))
                assert isensor_node != None, (HTML_BAD_REQUEST,
                                              'the specified iSensor IP address "%s" has not been provisioned on the server' % isensor_address)
                cmd_args.append('-I "%s" ' % isensor_address)
            else:
                logging.info('Using default iSensor settings')
        else:
            isensor_address = default
        if 'pan' in cfg:
            pan_address = cfg['pan']['address'] if 'address' in cfg['pan'] else default
            if pan_address != default:
                cmd_args.append('-P "%s" ' % pan_address)
        else:
            pan_address = default

        if 'ftd' in cfg:
            ftd_address = cfg['ftd']['address'] if 'address' in cfg['ftd'] else default
            if ftd_address != default:
                cmd_args.append('-F "%s" ' % ftd_address)
        else:
            ftd_address = default
        if pan_address == default and isensor_address == default and ftd_address == default:
            raise AssertionError, (HTML_BAD_REQUEST, 'the device IP address is missing from the request')
        target_ruleset = session_parameters['target-ruleset'] if 'target-ruleset' in session_parameters else default
        if target_ruleset != default:
            cmd_args.append('-v "%s" ' % target_ruleset)
        print
        'USER', user
        csv_file = self.create_csv_file(user, group.replace(' ', '_'), ID, session_parameters)
        cmd_args.append('-f %s ' % csv_file)
	if ID != "NA" and ID != "":
		cmd_args.append('--title "%s" ' % ID)
        testrun_id = time.strftime('%Y%m%d_%H%M%S') + '.' + user
        cmd_str = ''.join('%s' % arg for arg in cmd_args)
        cmd = 'sudo %s/lib/atf.py -R %s %s %s %s' % (CGIPATH, cmd_str, user, env, testrun_id)
        logging.info('calling ATF engine:\n\t%s' % cmd)
        loutfd, loutfn = mkstemp(prefix='launch_service', suffix='.out')
        lerrfd, lerrfn = mkstemp(prefix='launch_service', suffix='.err')
        proc = subprocess.Popen([cmd],
                                shell=True,
                                executable='/bin/bash',
                                stderr=lerrfd,
                                stdout=loutfd
                                )
	expire = time.time() + 3
	while expire > time.time():
		proc.poll()
		if proc.returncode != None:
			break
        logging.debug('launch_engine return code=%s' % str(proc.returncode))
        if proc.returncode and proc.returncode != 0:
            with open(lerrfn, 'r') as ef:
                error = ef.read()
            logging.error('launch engine failed to launch...\n%s' % error)
	    if 'conflict' in error:
		raise AssertionError, (HTML_CONFLICT, error)
		#return ((HTML_CONFLICT), response)
	    raise AssertionError, (HTML_INTERNAL_SERVER_ERROR, error)
        response = {"testrun-request-response": {
            'identification': get_element_value('identification', request),
            'request-type': 'testrun',
            'testrun-id': testrun_id,
            'test-status': 'Launch successful',
            'launch-engine-state': {'pid': proc.pid, 'ppid': getpid(), 'return-code': str(proc.returncode)},
            'launch-date-time': DATE.isoformat(DATE.now())
        }
        }
        return ((HTML_OK), response)

    def create_csv_file(self, user, group, testID, request):

        assert 'test-suites' in request, (
            HTML_BAD_REQUEST,
            'no test suites were found in request' % (suite_name, group))
        csvfile = '%s/%s/atf_rest.%s.csv' % (DOCROOT, user, group)
        csv_content = '#Test ID:%s' % testID
        for suite in request['test-suites']:
            suite_name = suite['suite']['name'].replace(' ', '_')
            logging.debug('Insert tests from suite %s' % suite_name)
            print
            '%s/%s/%s' % (DOCROOT, group, suite_name)
            assert os.path.exists('%s/%s/%s' % (DOCROOT, group, suite_name)), (
                HTML_BAD_REQUEST,
                'the specified test suite "%s" was not found in group "%s"' % (suite_name, group))
            if 'tests' in suite['suite']:
                csv_content += '\n%s' % suite_name
                for test in suite['suite']['tests']:
                    csv_content += ',%s' % test
                csv_content += '\n'
        with open(csvfile, 'w') as f:
            f.write(csv_content)
        return (os.path.basename(csvfile))

    def send_http_header(self, return_code=200, msg='OK', **opts):
        if 'length' in opts:
            content_length = str(opts['length'])
        else:
            content_length = '0'
        self.send_response(return_code, msg)
        if 'content_type' in opts:
            self.send_header('Content-type', 'application/%s' % opts['content_type'])
        else:
            self.send_header('Content-type', 'application/json')
        self.send_header('Content-length', content_length)
        self.end_headers()

    def do_GET(self):
        # self._set_headers()
        self.send_http_header()
        parsed_path = urlparse.urlparse(self.path)
        request_id = parsed_path.path
        html_hdr = HTML_BAD_REQUEST
        code, message = html_hdr
        response = '<xml>%s</xml>' % request_id
        content = '%s<atf-response code="%s" message="%s">\n%s\n</atf-response>' % (xml_header, code, message, response)
        self.send_http_header(content_type='xml', length=len(content))
        self.wfile.write(content)

        # outfd, outfn = mkstemp(prefix='GET', suffix='.out')

    # errfd, errfn = mkstemp(prefix='GET', suffix='.err')
    #        response = subprocess.call(["echo", "{'testID': '2016xxxx', 'status' : 'running'}"], stdout=outfd, stderr=errfd)
    #        with open(outfn, 'r') as response:
    #            self.wfile.write(response.read())
    #        unlink(outfn)
    #        unlink(errfn)

    def do_POST(self):
        parsed_path = urlparse.urlparse(self.path)
        request_id = parsed_path.path
        logging.debug('incoming post: %s, request_id = %s' % (parsed_path, request_id))
        self.rfile.flush()
        ctype = self.headers.getheader('content-type')
        raw_post = self.rfile.read(int(self.headers.getheader('content-length')))
        if 'policy' in request_id:
            xml_header = '<?xml version="1.0" encoding="UTF-8"?>\n'
            try:
                content = self.policy_request(raw_post)
                logging.debug('\n%s\n' % content)
                self.send_http_header(content_type='xml', length=len(content))
            except AssertionError as request_error:
                logging.debug(str(request_error))
                html_hdr, error_string = request_error
                code, message = html_hdr
                content = '%s<policy-request-response code="%s" message="%s">%s</policy-request-response>' % (
                    xml_header, code, message, error_string)
                self.send_http_header(code, message, content_type='xml', length=len(content))
            except Exception as error:
                html_hdr = HTML_INTERNAL_SERVER_ERROR
                code, message = html_hdr
                content = '%s<policy-request-response code="%s" message="%s">%s</policy-request-response>' % (
                    xml_header, code, message, str(error))
                self.send_http_header(code, message, content_type='xml', length=len(content))

            self.wfile.write(content)
            return

        process_request = {'testrun': self.launch_testrun, 'testrun-report': self.testreport}
        try:  # see of it can be parsed as XML
            J = JSONDecoder()
            post = J.decode(raw_post)
            datatype = 'json'  # probably
        except Exception as estr:
            datatype = None
        if datatype == None:
            self.send_http_header(400, 'Unable to parse POST data: %s' % estr)
            return
        # uncomment to save the data posted by the client

        response = 'Invalid service request'
        html_hdr = HTML_BAD_REQUEST
        valid_request = False
        for request in process_request:
            if request in post:
                valid_request = True
                try:
                    logging.debug('processing request "%s" in post:\n%s' % (request, post))
                    html_hdr, response = process_request[request](J, post[request])
                except AssertionError as request_error:
                    logging.error('ERROR from process_request: %s\n%s' % (str(list(request_error[0])), process_request))
                    try:
                        html_hdr, error_string = request_error
                    except:
                        html_hdr, error_string = list(request_error[0])
                    response = {
                        'testrun-request-response': {
                            'identification': get_element_value('identification', post[request]),
                            'error-detail': error_string}}
		    logging.debug('testrun-request-response: \n\t%s' % str(response))

        code, msg = html_hdr
	
        E = JSONEncoder()
        if valid_request == False:
            response = {
                'atf-invalid-request-response': {'error-detail': '"%s" is not a valid request key' % post.keys()[0]}}
            content = E.encode(response)
            self.send_http_header(length=len(content))
            self.wfile.write(content)
            return
        if 'policy-response' in response:
            content = response['policy-response']['xml'] + request_id
            self.send_http_header(content_type='xml', length=len(content))
            self.wfile.write(content)

        elif code == 200:
            response['testrun-request-response']['html-return-code'] = code
            response['testrun-request-response']['html-return-string'] = '%s' % msg
            content = E.encode(response)
            self.send_http_header(length=len(content))
            self.wfile.write(content)
        else:
            response['testrun-request-response']['html-return-code'] = code
            response['testrun-request-response']['html-return-string'] = '%s' % msg
	    logging.debug('msg:: \n\t%s' % str(msg))
	    logging.debug('testrun-request-response: \n\t%s' % str(response))

            content = E.encode(response)
            self.send_http_header(code, msg, length=len(content))
            self.wfile.write(content)
	    
        return

    def do_HEAD(self):
        self.json_http_header()


def validate_client_cert(cnx, x509, err, edepth, valid):
    # valid = True
    state = cnx.state_string()
    logging.error('SSL connection state at the time of client cert validation: %s' % state)

    if valid == False:
        logging.error('ERROR:Client certificate is INVALID: %s,%s' % (
            str(err), str(edepth)))
    elif edepth == 0:
        logging.info('Client certificate is valid')
    return valid


class Secure_ATF_Web_Service(HTTPServer):
    """
    def error_handler(self, request, client_address):
        import traceback
        import sys

        exstr = traceback.format_exception_only(sys.exc_type, sys.exc_value)
	if 'shutdown' not in exstr:
	        estr = 'An error occurred during a REST session with %s...\n%s\n' % (client_address[0], str(exstr))
        logging.error(estr)
        #estr = traceback.format_exc()
    """

    def error_handler(self, request, client_address):
        import traceback
        import sys

        exstr = traceback.format_exception_only(sys.exc_type, sys.exc_value)
        estr = 'An error occurred during a REST session with %s...\n%s\n' % (client_address[0], exstr)
        logging.error(estr)
        logging.error('trap: %s' % traceback.format_exc(30))

    def rest_info_callback(cobj, val1, val2):
        logging.info('obj:%s\nvalone:%d, val2: %d' % (str(cobj), val1, val2))

    def shutdown_request(self, request):
        import traceback
        import sys

        exc_type, exc_value, exc_traceback = sys.exc_info()

        exinfo = traceback.format_exception_only(exc_type, exc_value)
        exec_line = None
        # exloc = traceback.extract_tb(exc_traceback, None)
        exloc = traceback.extract_stack()
        for tb in traceback.format_list(exloc):
            logging.error('traceback: \n%s' % tb)
        logging.info(str(exinfo))

        state = request.state_string()
        logging.error('SSL connection state at the time of error: %s' % state)

        # request.shutdown()

    # if 'SSL negotiation finished successfully' not in state:
    #	request.shutdown()

    def __init__(self, server_address, HandlerClass):
        # import apache_startup as A
        import re
        try:
            with open('/etc/hosts', 'r') as hosts:
                fqdn_parse = re.findall('(a|p|r)(-atf.*net)', hosts.read(), re.MULTILINE)[0]
                fqdn = fqdn_parse[0] + fqdn_parse[1]
                logging.info('FQDN is %s' % fqdn)
        except Exception as estr:
            logging.debug('failed to determine FQDN "%s"...exiting' % str(estr))
            exit(1)
        SocketServer.BaseServer.__init__(self, server_address, HandlerClass)
        logging.debug('BaseServer allocated for %s%s' % server_address)

        # self.handle_error = self.error_handler

        logging.debug('error handler set')
        context = Context(SSLv23_METHOD)
        logging.debug('service context defined')
        # context.set_passwd_cb(A.submit_passphrase)
        # logging.debug('apache passphrase callback set to %s' % A.submit_passphrase.func_name)
        context.set_options(SSL.OP_NO_SSLv2)
        print('FQDN: %s' % fqdn)
        context.load_verify_locations('/etc/pki/tls/certs/%s.crt' % fqdn, None)
        context.use_privatekey_file('/etc/pki/tls/private/%s.key' % fqdn)
        context.use_certificate_file('/etc/pki/tls/certs/%s.crt' % fqdn)
        #context.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT | VERIFY_CLIENT_ONCE, validate_client_cert)
        context.set_verify(VERIFY_PEER |  VERIFY_CLIENT_ONCE, validate_client_cert)
        context.set_verify_depth(10)
        try:
            self.socket = Connection(context, socket.socket(self.address_family, self.socket_type))

            self.server_bind()
            self.server_activate()
        except Exception as estr:
            print
            "CONNECTION:", estr
        logging.info('Secure Web Service started')


class SecureHTTPRequestHandler(ATF_Web_Service):
    def setup(self):
        self.connection = self.request
        state = self.connection.state_string()
        logging.error('SecureHTTPRequestHandler invoked, SSL connection state: %s' % state)
        self.rfile = socket._fileobject(self.request, 'rb', self.rbufsize)
        self.wfile = socket._fileobject(self.request, 'wb', self.wbufsize)


def runSecure(ServerClass=Secure_ATF_Web_Service, HandlerClass=SecureHTTPRequestHandler):
    server_address = ('', 8443)
    logging.info('secure REST service listening on %s:%s' % server_address)
    httpd = ServerClass(server_address, HandlerClass)
    try:
        logging.info('httpd server starting')
        httpd.serve_forever()
    except socket.error:
        logging.info('httpd server failed to start due to socket error')
        raise AssertionError, 'ERROR: httpd server failed'

    except TypeError as estr:
        httpd.server_close()
        if 'shutdown' not in str(estr):
            logging.error('typeerror %s' % str(estr))
        return (False)

    except Exception as estr:
        import traceback
        import sys

        logging.info('httpd server crashed due to unknown error %s' % estr)
    httpd.server_close()
    return (False)


def run(server_class=HTTPServer, handler_class=ATF_Web_Service, port=8080):
    server_address = ('', port)
    try:
        httpd = server_class(server_address, handler_class)
    except Exception as error:
        print
        "The testrun service failed to start up: %s" % str(error)
        exit(1)

    # print 'Starting httpd...'
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
        # run(port=int(argv[1]))
        runSecure()
    else:
        pid = fork()
        #pid = 0
        if pid == 0:
            logging.info('starting up REST service in secure mode')
            runflag = True
            while runflag == True:
                runflag = runSecure()
            # run()
        else:
            with open('%s/launch_service.pid' % DOCROOT, 'w') as pf:
                pf.write(str(pid))
            exit(0)
