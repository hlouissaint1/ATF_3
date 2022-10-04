#!/usr/bin/python
import sys
import axsess
from scwxDRAClib import Connect
import os
from lxml import etree
from lxml.builder import E as XML
import re
from time import strftime, gmtime, time, localtime, asctime, tzname, mktime
import logging
from optparse import OptionParser
from json import JSONDecoder, JSONEncoder, dumps
from copy import deepcopy
from subprocess import call
from tempfile import mkstemp
from atfvars import varImport


# os.environ['ATF_CIPHER'] = '835e00f00e18b710c9b7f124872dd893'
#os.environ['ATF_LIBPATH'] = '/var/www/cgi-bin/lib'
PARSER = etree.XMLParser(remove_blank_text=True)
MINOR_VERSION = re.compile('\d{1,2}\.\d{1,2}\.\d{1,2}\-\d{1,2}')
MAJOR_VERSION = re.compile('\d{1,2}\.\d{1,2}\.\d{1,2}')
NOW = lambda: strftime('%4Y-%2m-%2dT%2H:%2M:%2S.%Z', gmtime(time() + 2))
CGILIB = '/var/www/cgi-bin/lib'
DOCROOT = '/var/www/html/htdocs'
ATFURL = 'http://p-atl100955.mss-fo.secureworks.net'
DUT = '172.16.240.78'
CERTFILENAME = 'device.crt'
CGIPATH = '/var/www/cgi-bin'
CERTPATH = '/etc/ssl/certs'
global options
os.environ['ATF_CIPHER'] = '835e00f00e18b710c9b7f124872dd893'
os.environ['ATF_LIBPATH'] = '/var/www/cgi-bin/lib'
INTERACTIVE = False
TRUE = 'store_true'
FALSE = 'store_false'
STORE = 'store'
RUN = True
STATUS = False

LOGPATH = '/var/www/cgi-bin/logs'
MODULE = 'depot_monitor.py'
LOG = 'auto_regression.log'

if not os.path.exists('%s/%s' % (LOGPATH, LOG)):
    with open('%s/%s' % (LOGPATH, LOG), 'w') as create:
        create.write('created new log')

logging.basicConfig(format='%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)


def launch_status_request_json():
    E = JSONEncoder()
    json = {
        'testrun-report': {
            #'identification' : options.tag,
            'testrun-id': None,
            'testrun-summary-only': False
        }
    }
    json['testrun-report']['testrun-id'] = options.tid
    json['testrun-report']['testrun-summary-only'] = options.summary
    logging.debug('status request for test ID %s, summary=%s' % (options.tid, str(options.summary)))

    rval = E.encode(json)
    return (rval)


def launch_request_json():
    E = JSONEncoder()
    json = {
        'testrun': {
            'environment': options.env,
            #'identification' : options.tag,
            'user': options.user,
            'target-ruleset': '',
            'test-group': options.group,
            'test-suites': [],
            'configuration-profile': {},
            'abort-test': False,
            'testrun-id': ''
        }
    }

    if options.tests == None:
        options.test = import_test_list()


    #    for tests in options.tests.split(','):
    for tests in options.tests:
        suite, test = tests.split(':')
        if suite == '*':
            json['testrun']['test-suites'] = []
            break
        if test == '*':
            json['testrun']['test-suites'].append({'suite': {'name': suite, 'tests': []}})
            continue
        suite_exists = False
        for ste in json['testrun']['test-suites']:
            if ste['suite']['name'] == suite:
                ste['suite']['tests'].append(test)
                suite_exists = True
                break
        if suite_exists == False:
            json['testrun']['test-suites'].append({'suite': {'name': suite, 'tests': [test]}})

    if options.config == None:

        json['testrun']['configuration-profile'] = {'name': '%s.%s' % (options.user, 'last.testrun')}
    else:
        json['testrun']['configuration-profile'] = {'name': options.config}
    config = json['testrun']['configuration-profile']
    try:
        with open('%s.cfg' % config['name'], 'r') as cfg:
            config = eval(cfg.read())
    except Exception as error:
        config = {}
    if not 'bps' in config:
        # Truet config
        config['bps'] = {}
        #trap
    if options.bpsIP != None:
        config['bps']['address'] = options.bpsIP
    if options.bpPorts != None:
        try:
            pair1, pair2 = options.bpPorts.split(':')
            config['bps']['first-port'] = '%s,1,1' % pair1
            config['bps']['second-port'] = '%s,1,1' % pair2
        except ValueError:
            raise AssertionError, 'Invalid specification for option -P'
    if options.bpTopo != None:
        config['bps']['topology'] = options.bpTopo
    if options.bpGroup != None:
        config['bps']['group'] = options.bpGroup
    config['ione'] = {'address': options.ioneIP, 'ports': options.ionePorts}
    if options.ioneTopo != None:
        config['ione']['topology'] = options.ioneTopo
    config['dcim'] = {'address': options.dcimIP, 'name': options.dcim}
    if options.ip != None:
        config['isensor'] = {"address": options.ip}

    config['email'] = options.email
    config['name'] = options.config
    json['testrun']['configuration-profile'] = deepcopy(config)
    with open('%s.cfg' % config['name'], 'w') as cfg:
        cfg.write(str(json['testrun']['configuration-profile']))

    rval = E.encode(json)
    logging.debug('launching...%s' % str(rval))
    return (rval)


def get_iso_list(version=None, env='agile', user='admin'):
    depot = Connect(remote_host='depot', TestEnv=env, ATF_User=user)
    vstr = version if version != None else '*'
    try:
        inventory = etree.parse('%s/iso_inventory.xml' % CGILIB, PARSER)
    except Exception as estr:
        logging.error('ERROR - unable to read ISO inventory file')
        inventory = None
    cmdstr = 'ls /local/repos/isensor/development/%s/agile/isos/*auto*.iso |sort -r' % vstr
    iso_list = depot.cmd(cmdstr).split('\n')
    if len(iso_list) == 0:
        logging.debug('Empty list return from depot after requesting %s' % cmdstr)
        return (None)
    md5sums = {}
    touched = False
    for iso in iso_list:
        if iso == '':
            continue
        moddate = None
        if inventory != None:
            moddate = depot.cmd('stat %s |grep Modify: | sed s/"Modify: "//g' % iso)
            modded_iso = inventory.find('iso[@mod-date="%s"]' % moddate.split('.')[0])
            logging.info('searching iso inventory for iso with mod-date of %s' % moddate)
            if modded_iso != None:
                logging.info('found mod-date for iso image version %s' % modded_iso.attrib['version'])
                continue
            logging.info('did not find mod-date %s for iso inventory of image %s' % (moddate, iso))

        md5sum = depot.cmd('md5sum %s' % iso).split(' ')
        md5_iso = inventory.find('iso[@md5sum="%s"]' % md5sum[0])
        if md5_iso != None and moddate != None and inventory != None:
            md5_iso.set('mod-date', moddate.split('.')[0])
            logging.debug('set mod-date of iso %s to %s' % (md5_iso.attrib['version'], moddate))
            touched = True
        md5sums[md5sum[0]] = iso

    if touched == True:
        with open('%s/iso_inventory.xml' % CGILIB, 'w') as f:
            f.write(etree.tostring(inventory, pretty_print=True))
    logging.debug('returned %d md5 sums' % len(md5sums))
    return (md5sums)


def match_sums_to_inventory(sums):
    logging.debug('attempting to match sums \n\t %s' % str(sums))
    try:
        inventory = etree.parse('%s/iso_inventory.xml' % CGILIB, PARSER)
    except Exception as estr:
        logging.error('ERROR - unable to read ISO inventory file')
        return (None, None)

    for md5sum in sums:
        iso = inventory.find('//iso[@md5sum="%s"]' % md5sum)
        if iso != None:  # the ISO exists and the sum hasn't changed
            continue
        try:
            is_in_inventory = inventory.xpath('//path[text()="%s"]' % sums[md5sum])[0]
            iso_parent = is_in_inventory.getparent()
            if iso_parent.find('ignore') != None:
                logging.info(
                    'skipping version %s...reason:%s' % (iso_parent.attrib['version'], iso_parent.find('ignore').text))
                continue
        except:
            pass
        logging.info('found new or changed md5sum %s - %s' % (md5sum, sums[md5sum]))
        return (md5sum, sums[md5sum])  # it is a new ISO.
    logging.info('No new ISOs detected')
    return (None, None)


def test_is_running(version=None, **opts):
    """
        This function serves two purposes. If a calling function needs to know if a test has been tagged as running then
        its sets version=None (or calls the script with no arguments) and if a test has been tagged to run it will return
        its testrun-id.  If a version is supplied along the 'launch' keyword defined with a testrun-id , then if there if
        there is  no test currently running, the iso image version is tagged as running (the attribute 'test-in-progress'
        is set to "yes" and the testrun-id that was supplied will be returned.  If the same or different test version is
        already running, then the testrun-id of the version under test will be returned along with the md5sum of the iso.

        If a version is supplied with the 'complete' keyword defined with a testrun-id, the iso version marked as
        'test-in-progress' will be tagged as no and 'None' will be return unless a different version has been tagged for
        running, in which case the testrun id and md5sum is return.

    """
    logging.debug('checking catalog for running test - %s' % str(opts))
    touched = False
    inventory = etree.parse('%s/iso_inventory.xml' % CGILIB, PARSER)
    running_test = inventory.find('iso[@test-in-progress="yes"]')
    md5sum = None
    if running_test == None:
        logging.info('there is no testrun currently in progress')
        if version == None:
            return (None, None, None)  #No test is running and no new test is set to run
        if 'launched' in opts:
            tid = opts['launched']
            launched = sorted(inventory.findall('iso[@version="%s"]' % version), None, None, True)
            if len(launched) == 0:
                logging.error('ERROR: attempted to set launched tag on  a version for which an ISO does not exist')
                return (None, None, None)
            md5sum = launched[0].attrib['md5sum'] if not 'md5dum' in opts else opts['md5sum']
            pid = opts['pid'] if 'pid' in opts else launched[0].attrib['pid'] if 'pid' in launched[0].attrib else ''
            old_tid_node = launched[0].find('testrun-id')
            if old_tid_node != None:
                logging.debug('remove previous tid from node :\n%s' % etree.tostring(launched[0], pretty_print=True))
                launched[0].remove(old_tid_node)
            launched[0].insert(0, XML('testrun-id', tid, md5sum=md5sum, pid=pid))
            launched[0].set('test-in-progress', 'yes')
            launched[0].set('md5sum', md5sum)
            touched = True
            logging.info('tagging testrun on version %s as running' % version)
    else:
        logging.info('found a test already marked as running: %s' % etree.tostring(running_test, pretty_print=True))
        tidnode = running_test.find('testrun-id')
        tid = tidnode.text
        if 'md5sum' in tidnode.attrib:
            md5sum = tidnode.attrib['md5sum']
        else:
            md5sum = running_test.attrib['md5sum']
            tid.set('md5sum', md5sum)
            touched = True
        version = running_test.attrib['version']
        error_node = running_test.find('error')
        if error_node != None and error_node.text != 'None':
            logging.info('tagging testrun w/no error on version %s (testrun-is: %s) as complete' % (version, tid))
            running_test.set('test-in-progress', 'no')
            touched = True
        elif 'complete' in opts:
            logging.info('tagging testrun on version %s (testrun-is: %s) as complete' % (version, tid))
            running_test.set('test-in-progress', 'no')
            touched = True
        else:
            return (tid, md5sum, version)
    if touched == True:
        with open('%s/iso_inventory.xml' % CGILIB, 'w') as f:
            f.write(etree.tostring(inventory, pretty_print=True))
    return (tid, md5sum, version)


def update_iso_status(tid, **opts):
    logging.debug('updating iso status as testrun completed for tid: %s' % tid)
    inventory = etree.parse('%s/iso_inventory.xml' % CGILIB, PARSER)
    tidnodes = inventory.xpath('//testrun-id[text()="%s"]' % tid)
    if len(tidnodes) == None:
        logging.debug('iso catalog does not contain the running tid\n%s' % etree.tostring(inventory, pretty_print=True))
        return
    for tidnode in tidnodes:
        iso = tidnode.getparent()
        if iso.attrib['test-in-progress'] == 'yes':
            iso.set('test-in-progress', 'no')
            tidnode.text = 'C%s' % tidnode.text
            break

    with open('%s/iso_inventory.xml' % CGILIB, 'w') as f:
        f.write(etree.tostring(inventory, pretty_print=True))


def update_inventory(sums, **opts):
    logging.debug('updating iso inventory (%s)' % str(opts))
    inventory = etree.parse('%s/iso_inventory.xml' % CGILIB, PARSER)
    newISO = False
    for md5sum in sums:
        path = sums[md5sum]
        logging.debug('looking for match on md5sum: "%s"' % md5sum)
        try:
            version = re.findall(MINOR_VERSION, path)[0]
            logging.debug('found match on %s' % version)
        except IndexError:
            try:
                logging.debug('searching for  most current major version in the iso catalog')
                versions = sorted(re.findall(MAJOR_VERSION, path), None, None, True)
                version = versions[0]
                logging.debug('found match on version %s' % version)
            except IndexError:
                try:
                    logging.debug('searching for  most current iSensor version x.x in the iso catalog')
                    versions = sorted(re.findall('\d{1,2}\.\d{1,2}', path), None, None, True)
                    version = versions[0]
                    logging.debug('found match on version %s' % version)
                except:
                    raise AssertionError, 'ISO filename does not contain a matching version number: %s ' % path
        logging.debug('scanning iso catalog for v%s image' % version)
        iso = inventory.find('iso[@version="%s"]' % version)
        ignore = None
        if iso != None:
            if iso.attrib['md5sum'] == md5sum:
                continue
            logging.info('found matching iso image in catalog % s' % str(iso.attrib))
            if 'test-in-progress' in iso.attrib and iso.attrib['test-in-progress'] == 'no':
                logging.debug('remove previous node:\n%s' % etree.tostring(iso, pretty_print=True))
                ignore = iso.find('ignore')
                if ignore != None:
                    ignore = deepcopy(iso.find('ignore'))
                iso.getparent().remove(iso)
            else:
                tidnode = iso.find('testrun-id')
                if tidnode != None:
                    tid = tidnode.text
                else:
                    tid = 'No testrun node found in catalog'
                logging.debug('iso catalog was not updated do to running test: %s' % str(tid))
                break
        pid = opts['pid'] if 'pid' in opts else ''
        if not 'tid' in opts or opts['tid'] == None:
            iso = XML.iso(XML.path(path), version=version, md5sum=md5sum, pid=str(pid), timestamp=NOW())
        else:
            tid = XML('testrun-id', opts['tid'], pid=str(pid))
            iso = XML.iso(
                XML.path(path),
                XML('testrun-id', opts['tid'], pid=str(pid)),
                version=version, md5sum=md5sum, timestamp=NOW())
            if not 'pid' in iso.attrib or iso.attrib['pid'] == '':
                iso.set('pid', 'pid')
        if 'error' in opts:
            iso.append(XML.error(str(opts['error'])))
        logging.debug('inserting ISO into catalog:\n%s' % etree.tostring(iso, pretty_print=True))
        if ignore != None:
            iso.insert(0, ignore)
        inventory.getroot().insert(0, iso)
        newISO = True

    if newISO == True:
        logging.debug('writing updated catalog to disk')
        with open('%s/iso_inventory.xml' % CGILIB, 'w') as f:
            f.write(etree.tostring(inventory, pretty_print=True))


def call_ATF_REST_Service(args):
    D = JSONDecoder()
    if options.launch == True:
        logging.info('Requesting test launch')
        json = launch_request_json()
        try:
            djson = D.decode(json)
            logging.debug('outgoing JSON is good:')
            logging.debug(dumps(djson, sort_keys=True, indent=4, separators=(',', ':')))
        except Exception as error:
            logging.error(str(error))
            logging.error(str(json))
            logging.error('outgoing JSON is malformed')
            exit(1)
    elif options.report == True:
        logging.info('Requesting test report')
        json = launch_status_request_json()
        try:
            djson = D.decode(json)
            logging.debug('outgoing JSON is good:')
            logging.debug(dumps(djson, sort_keys=True, indent=4, separators=(',', ':')))
        except Exception as error:
            logging.error(str(error))
            logging.error(str(error))
            logging.error(str(json))
            logging.error('outgoing JSON is malformed')
            exit(1)
    try:
        url = args[1]
    except IndexError:
        url = 'https://x-atl1ngpcsau02.internal.secureworkslab.net:8443/launch'
    if options.interactive == True:
        ready = raw_input('Ready to Post JSON request to server? <y,N>')
    else:
        ready = 'yes'
    if not ready.lower().startswith('y'):
        logging.info('request aborted')
        return (None, 'ERROR: request aborted')
    if options.abort == False:
        request_file = 'last_launch.request' if 'testrun' in djson else 'last_status.request'
        with open(request_file, 'w') as resp:
            resp.write(str(djson))

    response_file = 'last_launch.response' if 'testrun' in djson else 'last_status.response'
    with open(response_file, 'w') as outfd:
        errfd, errfn = mkstemp(prefix='response', suffix='.err')
        #rcode = call(['curl -v -X POST -d %s %s ' % (dumps(json), url)], shell=True, stdout=outfd, stderr=errfd)
        certstr = '-E /var/www/cgi-bin/lib/%s --capath %s' % (CERTFILENAME, CERTPATH)
        cmdstr = 'curl --noproxy secureworkslab.net %s -v -X POST -d %s %s ' % (certstr, dumps(json), url)
        logging.info(cmdstr)
        rcode = call([cmdstr], shell=True, stdout=outfd, stderr=errfd)
        if rcode != 0:
            estr = 'cURL return error Code %d' % rcode
            logging.error(estr)
            return (None, estr)
    outfd.close()
    #errfd.close()
    with open(response_file, 'r') as response:
        rjson = response.read()
        try:
            djson = D.decode(rjson)
            logging.info('Response is well-formed JSON:')
        except:
            estr = 'Received malformed JSON from server'
            logging.error(estr)
            logging.error(str(rjson))
            return (None, estr)
            #logging.debug(dumps(eval(rjson), sort_keys=True, indent=4, separators=(',', ':')))

    response_type = djson.keys()[0]
    if True:  #if options.report == False:
        try:
            if 'testrun-id' in djson[djson.keys()[0]]:
                logging.debug('parsing "testrun-id"')
                tid = djson[djson.keys()[0]]['testrun-id']
            else:
                logging.debug('No testrun-id found')
                tid = None
            return (tid, dumps(eval(rjson), sort_keys=True, indent=4, separators=(',', ':')))
        except Exception as error:
            logging.error(str(error))
            #estr = djson[djson.keys()[0]]['error-detail']
            return (
            None, 'ERROR: %s\n%s' % (str(error), dumps(eval(rjson), sort_keys=True, indent=4, separators=(',', ':'))))
    try:
        a = djson.keys()[0]['testrun-id']
    except Exception as error:
        return (None, dumps(eval(rjson), sort_keys=True, indent=4, separators=(',', ':')))

    return (djson[djson.keys()[0]]['testrun-id'], dumps(eval(rjson), sort_keys=True, indent=4, separators=(',', ':')))


#-r -u Auto_Regression -I 172.16.240.244 -G 6 -g "iSensor Regression" -L "PreTest:Install_iSensor.txt,PreTest:Config_Inspector,AgentandAlerting:TC-8413.txt"
class AutoTrigger:
    @varImport()
    def __init__(self, **opts):
        self.__dict__.update(opts)
        from ctpapi import PCSMS
        from scwxBPlib2 import BreakingPoint
        from axsess import Password
        #logging.debug('EVARS:\n%s' % str(opts))
        global options
        optparser = OptionParser()
        setoption = lambda option_name, action, value: optparser.add_option('', '--%s' % option_name, action=action,
                                                                            dest=option_name, default=value)
        setoption('launch', FALSE, self.mode)
        setoption('report', TRUE, not self.mode)
        setoption('env', STORE, self.TestEnv.capitalize())
        setoption('user', STORE, self.ATF_User)
        setoption('group', STORE, 'iSensor Regression')
        setoption('tests', STORE, self.tests)
        setoption('config', STORE, 'default_regression')
        setoption('bpsIP', STORE, self.bps_IP)  #'172.16.193.252'
        setoption('bpPorts', STORE, '%s:%s' % (self.Firstport, self.SecondPort))
        setoption('bpTopo', STORE, self.bps_Topology)
        setoption('bpGroup', STORE, self.bps_Group)
        setoption('ioneIP', STORE, self.ione_IP)
        setoption('ioneTopo', STORE, self.ione_Topology)
        setoption('ionePorts', STORE, self.ione_Ports)
        setoption('dcim', STORE, self.DCIM_ID)
        setoption('dcimIP', STORE, self.dcim_IP)
        setoption('ip', STORE, self.isensor_IP)
        setoption('email', STORE, 'Squad iSensor')
        #setoption('email', STORE, 'ATF-Administrator')
        setoption('interactive', TRUE, INTERACTIVE)
        setoption('abort', FALSE, False)
        setoption('summary', FALSE, False)
        setoption('debug_flag', TRUE, True)

        for opt in opts:
            if isinstance(opts[opt], bool) == True:
                setoption(opt, FALSE, opts[opt])
            else:
                setoption(opt, STORE, opts[opt])

        options, cliargs = optparser.parse_args()

        self.options = options
        exml = etree.parse('%s/email.xml' % DOCROOT)
        egrp = exml.find('group[@name="%s"]' % options.email)
        mailserver = exml.find('mail-server')
        if mailserver != None and 'url' in mailserver.attrib:
            self.mailserver = mailserver.attrib['url']
        else:
            self.mailserver = None
        mailclient = exml.find('mail-client')
        if mailclient != None and 'url' in mailclient.attrib:
            self.mailclient = mailclient.attrib['url']
        else:
            self.mailclient = 'x-atl1ngpcsau02@internal.secureworkslab.net'
        self.recipients = ['%s@%s' % (recipient.attrib['name'], egrp.attrib['domain']) for recipient in
                           egrp.findall('recipient[@hourly-updates="yes"]')]
        self.no_update_recipients = ['%s@%s' % (recipient.attrib['name'], egrp.attrib['domain']) for recipient in
                                     egrp.findall('recipient[@hourly-updates="no"]')]
        self.all_recipients = self.recipients
        if len(self.no_update_recipients) != 0:
            self.all_recipients.extend(self.no_update_recipients)

        self.blame = None
        logging.debug('AutoTrigger object created: mode = %s, number of tests = %s, environment= %s' % (
        'Check Status' if mode == False else 'Launch Testrun',
        len(tests),
        environment))

    def Test_Connections(self):
        #return(None)
        from scwxBPlib2 import BreakingPoint
        from scwxDCIMlib import LabManager

        B = BreakingPoint(options)
        try:
            B.testBPConnections()
        except AssertionError as error:
            estr = str(error)
            reservedby = estr.find('reserved by ')
            if reservedby > 0:
                reservedby += 12
                self.blame = estr[reservedby:].split(' ')[0]
        L = LabManager(options)
        try:
            L.Test_BP_Topology()
            L.Test_IONE_Topology()
        except AssertionError as estr:
            return (str(estr))
        return (None)

    def check_for_bad_return_code(self, raw):
        json = eval(raw)

        logging.debug('checking for bad html return code %s in :\n%s' % (type(json), json))
        rtype = json.keys()[0]
        if 'html-return-code' in json[rtype]:
            rcode = json[rtype]['html-return-code']
        if rcode == 200:
            logging.debug('"html-return-code" is OK')
            return (None)
        logging.debug('parsing error details"')
        if 'error-detail' in json[rtype]:
            estr = json[rtype]['error-detail']
        else:
            estr = 'no error details for HTML return code %d' % rcode
        return ('ERROR: %s' % estr)


    def Run(self, **opts):
        logging.info('Executing  AutoTrigger on build version %s' % options.buildimage)
        rval, raw_return = call_ATF_REST_Service([])
        rerror = None
        logging.debug('received rval=%s\nraw_return=\n%s' % (rval, raw_return))
        if rval == None and not str(raw_return).startswith('ERROR'):
            try:
                rerror = self.check_for_bad_return_code(raw_return)
                if rerror != None:
                    #raw_return = rval
                    json = eval(raw_return)
                    try:
                        rtype = json.keys()[0]
                        rerror = '\nError Detail:\n\t%s' % json[rtype]['error-detail']
                    except:
                        pass
            except Exception as estr:
                logging.error('ERROR: %s' % estr)
            if rval == None:
                return (rval, raw_return, rerror)
        if rval == None:
            rerror = self.check_for_bad_return_code(raw_return)
            if rerror == None:
                rerror = 'ERROR: Unhandled exception' + rerror
                logging.error('%s: %s' % raw_return)
                return (rval, raw_return, rerror)
        md5sum = opts['md5sum'] if 'md5sum' in opts and opts['md5sum'] != None else 'Unknown'
        if rerror != None:
            self.sendMail(
                'Auto Regression Test FAILED to launch on build image: %s' % options.buildimage,  # subject
                self.all_recipients,  # addresses
                'Test ID: %s\nMD5sum-%s\nError:%s\n%s' % (str(rval), md5sum, str(rerror), raw_return)  # body of email

            )
        else:
            test_run_complete = False
            logging.debug('parsing summary')
            try:
                content, test_run_complete = parse_summary(raw_return)
            except Exception as estr:
                content = 'Error parsing summary...' + str(estr) + raw_return
            try:
                session = etree.parse('%s/%s/tests.xml' % (DOCROOT, options.user))
            except Exception as estr:
                content = 'Error parsing test catalog...' + str(estr) + '%s/%s/tests.xml' % (DOCROOT, options.user)

            tests_in_q = session.xpath('//test[@status="Running"]')
            if len(tests_in_q) > 0:
                test_in_progress = tests_in_q[0]
                tests = get_test_descriptions(
                    ['%s:%s' % (test_in_progress.attrib['suite'], test_in_progress.attrib['name'])])
                content += '\nTest in Progress: "%s"\n' % (tests[test_in_progress.attrib['name']])
            try:
                content += parse_details(raw_return)
                if content.find('Critical Failure') >= 0:
                    self.sendMail('Auto Regression Notification-CRITICAL FAIL', self.all_recipients, content)
            except Exception as estr:
                content = 'Error parsing details..' + str(estr) + raw_return
            if test_run_complete == True:
                subject_insert = 'COMPLETED'
                recipients = self.all_recipients
            else:
                subject_insert = 'status'
                recipients = self.recipients
                if content.find('Test Run was launched successfully') >= 0:
                    self.all_recipients
            self.sendMail(
                'Auto Regression Test Run %s on build image: %s' % (subject_insert, options.buildimage),
                recipients,
                'Test ID: %s\nMD5sum: %s\n%s' % (str(rval), md5sum, content))

        return (rval, eval(raw_return), rerror)


    def sendMail(self, subject='Auto Regression Notification', recipients=['gowen@secureworks.com'],
                 content='No content', **opts):
        import smtplib

        if self.mailserver != None:
            smtp_server = self.mailserver
        else:
            smtp_server = 'atl1mxhost01.internal.secureworkslab.net'  # this is the agile and production server
        logging.debug('email server URL is: %s' % smtp_server)
        from_address = self.mailclient

        emails = ''
        logging.debug('sending out mail...\n\tDistribution:%s\n\tsubject: %s\n\tTo: %s\n\tBody:%s' % (
        emails, subject, recipients, content))
        body = 'Subject:%s\n\n%s' % (subject, content)
        try:
            smtpObj = smtplib.SMTP(smtp_server)
            smtpObj.helo("x-atl1ngpcsau02")
            smtpObj.sendmail(from_address, recipients, body)
            logging.info('Successfully sent mail with subject "%s" to %s' % (
            subject,
            ''.join('%s;' % recipient for recipient in recipients),
            ))
            return ('Message "%s" Sent' % subject)
        except Exception as merror:
            logging.error('ERROR in attempting to send mail with subject "%s" to %s: %s' % (
                subject,
                str(recipients),
                str(merror)
            ))
            return ('ERROR sending email to %s with subject %s\n%s\n' % (str(recipients), subject, str(merror)))


def main(args):
    starttime = None
    endtime = None
    logging.info('starting depot monitor with arguments %s' % str(args))
    if len(args) > 1:
        environment = args[1].lower()
    else:
        environment = 'agile'

    if len(args) > 2:
        user = args[2]
    else:
        user = "Auto_Regression"
    # defines the hours when testruns CANNOT be launched
    if len(args) > 3:
        starttime = args[3]
    elif not starttime:
        starttime = '12:10:20'
        endtime = '12:10:20'
    if len(args) > 4:
        endtime = args[4]
    elif not endtime:
        endtime = '12:10:21'

    rerror = None
    launchOK = True
    if starttime != None:
        parse_time = lambda t: [int(e) for e in t.split(':')]
        now = mktime(localtime(time()))
        template = [n for n in localtime(time())]
        template[3], template[4], template[5] = parse_time(starttime)
        no_launch_start_time = mktime(template)
        template[3], template[4], template[5] = parse_time(endtime)
        no_launch_end_time = mktime(template)
        logging.debug('time check - now: %s (%d), start: %s (%d), end: %s (%s)' % (
        asctime(), now,
        starttime, no_launch_start_time,
        endtime, no_launch_end_time
        )
        )
        if now >= no_launch_start_time and now <= no_launch_end_time:
            logging.debug('launch prohibited')
            launchOK = False
        else:
            logging.debug('launch allowed')
            launchOK = True
    print starttime, endtime
    test_already_running, md5sum, running_version = test_is_running()
    if test_already_running != None:
        logging.info('Testrun is already in progress...checking status')
        if test_already_running.startswith('ERROR'):
            logging.error(test_already_running)
            return (test_already_running, None, rerror)
        logging.debug('calling REST service to retrieve testruninfo')
        #S = AutoTrigger(STATUS,[], environment, tid=test_already_running, buildimage=running_version)
        S = Autorigger(environment, user, mode=STATUS, tests=[], tid=test_already_running, buildimage=running_version)
        rval, json, rerror = S.Run(md5sum=md5sum)
        #logging.debug('info received from REST service%s\n%s' % (str(rval), str(json)))
        return (rval, json, rerror)
    version = None
    depot_iso_md5sums = get_iso_list(version, environment, 'Auto_Regression')
    new_iso_sum, new_iso_path = match_sums_to_inventory(depot_iso_md5sums)

    if new_iso_sum != None and launchOK == True:
        logging.info('New ISO detected on depot...triggering regression tests on image:\n\t%s' % new_iso_path)
        testlist = []
        with open('%s/Auto_Regression/auto_regression.csv' % DOCROOT, 'r') as f:
            testrun = f.read().split('\n')
            for line in testrun:
                if line == '' or line.startswith('#'):
                    continue
                items = line.split(',')
                if len(items) < 2:
                    continue
                suite = items[0]
                tests = ['%s:%s' % (suite, items[x]) for x in range(1, len(items))]
                testlist.extend(tests)
        version = re.findall(MINOR_VERSION, new_iso_path)[0]
        #T = AutoTrigger(RUN, testlist, buildimage=version, ruleset=version)
        T = AutoTrigger(environment, user, mode=RUN, tests=testlist, buildimage=version, ruleset=version)
        resource_conflict = T.Test_Connections()
        resource_conflict = None
        if resource_conflict != None:
            msg = 'The iSensor Auto Regression Test Run failed to start up due to a resource conflict:\n\n%s' % resource_conflict

            T.sendMail(
                'Auto Regression Test Run status on build image: %s' % T.options.buildimage,
                T.all_recipients,
                msg)
            if T.blame != None:
                logging.error('blaming %s for testrun failure' % T.blame)
                T.sendMail('The iSensor Auto Regression is blocked from running',
                           [T.blame + '.secureworks.com', 'gowen@secureworks.com'],
                           'It appears you have a resource reserved which is preventing the regression tests from running:\n\t%s\n\n' % resource_conflict +
                           'Please release the resource so that the tests can run.\n')
            return (None, None, msg)

        logging.info('starting auto regression trigger')
        rval, jsonstr, rerror = T.Run(md5sum=md5sum)
        logging.debug('(Type:%s) %s, \n(Type:%s) %s, \n(Type:%s) %s ' % (
        type(rval), rval,
        type(jsonstr), jsonstr,
        type(rerror), rerror
        )
        )
        if isinstance(jsonstr, str):
            json = eval(jsonstr)
        else:
            json = jsonstr
        pid = ''
        tid = None
        if rval == None and rerror.find('already in progress') > 0:
            update_inventory(depot_iso_md5sums, tid=None, pid=pid, error=rerror)
            return (rval, json, str(rerror))
        elif rval == None:
            rerror = 'ERROR: calling service...%s' % rval
            logging.error('ERROR: calling service...%s:%s' % (rerror, jsonstr))
            return (None, rval, rerror)
        try:
            if 'testrun-request-response' in json:
                if 'launch-engine-state' in json['testrun-request-response']:
                    if 'pid' in json['testrun-request-response']['launch-engine-state']:
                        pid = json['testrun-request-response']['launch-engine-state']['pid']
                if 'testrun-id' in json['testrun-request-response']:
                    tid = json['testrun-request-response']['testrun-id']
                logging.info('TestID= %s, pid= %s' % (tid, pid))
        except Exception as estr:
            logging.debug('%s, %s\n%s' % (estr, type(json), json))
        update_inventory(depot_iso_md5sums, tid=tid, pid=pid, error=rerror)
        test_already_running, md5sum, version = test_is_running(version, launched=rval, md5sum=new_iso_sum,
                                                                pid=str(pid))
        return (rval, jsonstr, rerror)
    elif new_iso_sum != None and launchOK == False:
        logging.info('A new ISO was detected on the depot but test runs are prevented from launching at this time')
    else:
        logging.info('No new ISO detected on depot')
    return (None, None, None)


def get_test_descriptions(testlist):
    tests = {}
    testXML = etree.parse('%s/%s/tests.xml' % (DOCROOT, options.user))
    nondescript = 'No description available'
    for suitetest in testlist:
        suite, test = suitetest.split(':')
        testnode = testXML.xpath('//suite[@name="%s"]/tests/test[@name="%s"]' % (suite, test))
        if len(testnode) > 0:
            descript = testnode[0].find('description')
            if descript != None:
                tests[test] = '%s:%s- %s' % (suite, test, descript.text)
            else:
                tests[test] = nondescript
        else:
            tests[test] = nondescript
    return (tests)


def parse_summary(json):
    response = eval(json)
    rstr = '\nTest Run Summary:\n\n'
    completeflag = False
    if response.keys()[0] == 'testrun-request-response':
        body = response['testrun-request-response']
        if 'results' in body:
            summary = body['results']['summary']
            starttime_f = float(body['results']['summary']['start-time'])
            starttime = '%s %s' % (asctime(localtime(starttime_f)), tzname[localtime().tm_isdst])
            body['results']['summary']['start-time'] = starttime
            rstr += ''.join('\t%s: %s\n' % (key, summary[key]) for key in sorted(summary.keys()))
            if body['results']['summary']['status'] == 'Completed':
                update_iso_status(body['testrun-id'])
                completeflag = True
            runtime = strftime('%02H:%02M:%02S', gmtime(time() - starttime_f))
            rstr += '\trun-time: %s\n' % str(runtime)
        elif 'error-detail' in body:
            return ('ERROR: %s' % body['error-detail'], completeflag)
        elif 'test-status' in body and body['test-status'] == 'Launch successful':
            tests = get_test_descriptions(options.tests)
            order_test_by_suite_name = lambda x, y: cmp(tests[x].lower(), tests[y].lower())

            return (
            '\nTest Run was launched successfully\n\nLaunch Date/Time: %s\n\niSensor Mgmt Address%s\n\nTests in this Test Run:\n\n%s' % (
            body['launch-date-time'],
            options.ip,
            ''.join('%s\n' % tests[test] for test in sorted(tests, order_test_by_suite_name))
            ),
            completeflag
            )
        else:
            raise AssertionError, 'unexpected response from ATF REST service\n%s' % response
    return (rstr, completeflag)


def get_log_link(test):
    txml = etree.parse('%s/%s/tests.xml' % (DOCROOT, options.user))
    tnode = txml.xpath('//test[@name="%s"]' % test['name'])
    if len(tnode) == 0:
        return ("Can't find tnode")
    log = tnode[0].find('lastlog')
    if log == None:
        return ("Can't find log link")
    loglink = '%s/%s' % (ATFURL, log.text.replace('..', ''))
    return (loglink)


def check_pulse(heartbeat, tid, test_name):
    engine_is_running = True
    logging.debug('checking heartbeat for test %s in testrun %s...received heartbeat %s' % (test_name, tid, heartbeat))
    if time() - float(heartbeat) > 600:  # something is wrong if the heartbeat hasn't been updated
        inventory = etree.parse('%s/iso_inventory.xml' % CGILIB, PARSER)
        testrun = inventory.xpath('//testrun-id[text()="%s"]' % tid)
        logging.debug('heartbeat is late (current time %d)...checking if engine is up' % int(time()))
        if len(testrun) > 0:
            pid = testrun[0].attrib['pid']
            engine_is_running = os.path.exists('/proc/%s' % pid)
            if engine_is_running == False:
                logging.error(
                    'CARDIAC ARREST...engine died prior to testrun completion (%s:%s)' % (str(time()), heartbeat))
            else:
                with open('/proc/%s/cmdline' % pid, 'r') as c:
                    cmdline = c.read()
                    engine = cmdline.find('launch_engine')
                    if engine < 0:
                        engine_is_running = False
                        logging.error('CARDIAC ARREST: launch engine process (%s) terminated' % (pid))
                    else:
                        logging.debug('engine is still running on pid %s' % pid)
    else:
        logging.debug('heartbeat was generated within the last ten minutes')
    return (engine_is_running)


def parse_details(json):
    test_fields = ['name', 'suite', 'status', 'run-time', 'result']
    response = eval(json)
    rstr = '\nTest Run Details:'
    heartbeat = None
    if response.keys()[0] == 'testrun-request-response':
        body = response['testrun-request-response']
        if not 'results' in body:
            return ('')
        details = body['results']['details']
        summary = body['results']['summary']
        in_progress = summary['status'] == 'In Progress'

        for item in details:
            if not 'result' in item['test']:
                continue
            if 'test' in item:
                if in_progress == True and item['test']['status'] == 'Running':
                    heartbeat = item['test']['heartbeat']
                    cardiac_arrest = check_pulse(heartbeat, summary['id'], item['test']['name'])
                if item['test']['result'] != 'Failed' and item['test'][
                    'result'] != 'Passed':  # the result is pending or there is no result yet
                    continue
                rstr += '\n\n\tTest ' + ''.join('%s: %s\n\t' % (key, item['test'][key]) for key in test_fields)
            """
            if 'test-errors' in item['test']:
                rstr += 'error details:'
                if isinstance(item['test']['test-errors'], str) == True:
                    if item['test']['test-errors'].find('index out of range') < 0:
                        rstr += '\n\t\t\t' + item['test']['test-errors']
                    else:
                        rstr += ' unavailable'
                        continue
                else:
                    rstr += ''.join('\n\t\t\t%s' % error for error in item['test']['test-errors'])
            """
            loglink = get_log_link(item['test'])
            if loglink == None:
                rstr += '\n\tLog URL:\n\t\t%s' % item['test']['log']
            else:
                rstr += '\n\tLog URL - %s' % loglink
            if item['test']['result'] != 'Failed':
                continue
            try:

                killed = kill_testrun_if_fatal_error(item['test']['name'], body['testrun-id'])
                if len(killed) > 0:
                    estr = '\n%s\n%s\n\n' % (killed, rstr)
                    rstr = estr
                    break;
            except Exception as estr:
                logging.error('failed to kill testrun: %s' % str(estr))
                rstr += '\n...this critical test failed but received an error when attempting to stop testrun\n%s' % estr

        return (rstr)


def kill_testrun_if_fatal_error(testname, testrunID):
    #return
    tiduser = testrunID.split('.')
    tiduser.reverse()
    user = tiduser[0]
    txml = etree.parse('%s/%s/tests.xml' % (DOCROOT, user))
    tests = txml.xpath('//test[@name="%s"]' % testname)
    if len(tests) > 0:
        test = tests[0]
        suite = test.getparent().getparent()
        if 'critical' in suite.attrib and suite.attrib['critical'] == 'yes':
            logging.error('current test %s is in a critical test suite %s' % (testname, suite.attrib['name']))
            logging.error('attempting to abort testrun due to critical error')
            from testrun_reset import KILL_TID

            logging.info('Cancelling test run ID: %s' % testrunID)
            parsed_tid = testrunID.split('.')
            parsed_tid.reverse()
            user = parsed_tid[0]
            K = KILL_TID(user=user)
            K.killTestNow()
            inventory = etree.parse('%s/iso_inventory.xml' % CGILIB, PARSER)
            tids = inventory.xpath('//testrun-id[text()="%s"]' % testrunID)
            if len(tids) > 0:
                iso = tids[0].getparent()
                iso.set('test-in-progress', 'no')
                errstr = 'Critical Failure in "%s:%s"' % (suite.attrib['name'], testname)
                error = iso.find('error')
                if error != None:
                    if error.text != 'None':
                        errstr += error.text

                    iso.remove(error)
                iso.append(XML.error(errstr))
                with open('%s/iso_inventory.xml' % CGILIB, 'w') as f:
                    f.write(etree.tostring(inventory, pretty_print=True))
                return (errstr)

            else:
                logging.error(
                    'unable to locate the test id: %s\n%s' % (testrunID, etree.tostring(inventory, pretty_print=True) ))
        else:
            logging.error('current test %s is NOT in a critical test suite %s' % (testname, suite.attrib['name']))
            return ('')
    else:
        logging.error('no tests found to kill this session')
        return ('')


if __name__ == '__main__':
    logging.info('Starting up depot_monitor.py')
    testbeds = {}
    if len(sys.argv) > 1:
        rval, json, error = main(sys.argv)
    else:
        fxml = etree.parse('%s/framework.xml' % DOCROOT)
        envnode = fxml.find('environment[@selected="selected"]')
        if envnode is None:
            estr = 'ERROR:No configuration specified'
            logging.error(estr)
            raise AssertionError, estr
        environment = envnode.attrib['name']
        try:
            usrnodes = fxml.xpath('auto-regression/user[@inactive!="yes"]')
            assert len(usrnodes) != 0, 'No active regression test bed available'
            for testbed in usrnodes:
                testbeds[testbed.attrib['name']] = [sys.argv[0], environment, testbed.attrib['name'],
                                                    testbed.attrib['starttime'], testbed.attrib['endtime']]
        except Exception as estr:
            print estr
            trap
            exit(1)
    error = 'None'
    for testbed in testbeds:
        rval, json, error = main(testbeds[testbed])
        logging.info('launching regression test in the %s testbed' % testbed)
        print 'launching regression test in the %s testbed' % testbed
    logging.info('Exiting depot_monitor.py, Error=%s' % error)
    exit(0)

