# Author G. Owen, gowen@secureworks.com

import os
import requests
from requests.auth import HTTPBasicAuth
from lxml import etree
from lxml.builder import E
from time import time, strftime, sleep, gmtime, localtime, mktime, strptime
import re
import sys
import logging
from robot.api.deco import keyword
from tempfile import mkstemp
from copy import deepcopy
from atfvars import varImport

from requests.packages.urllib3.exceptions import InsecureRequestWarning

CGILIBPATH = '/var/www/html/htdocs/lib/'
DOCROOT = '/var/www/html/htdocs'
LOGPATH = '/var/www/cgi-bin/logs'
LOG = 'pan_test.log'

logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)

# suppess POST contents so passwords aren't exposed in the logs
logging.getLogger("request").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

PARSER = etree.XMLParser(remove_blank_text=True)
NOW = lambda: strftime('%4Y-%2m-%2dT%2H:%2M:%2S.%Z', localtime(time() + 2))
LOCATION = lambda L: '@location="%s" or @location="%s" or @location="ANY"' % (L.capitalize(), L.lower())

CHECK_FOR_ERROR = lambda d, v: 'ERROR: %s' % d['error'] if d['error'] != None else v
BENIGN_ERROR = [
    'Config is not currently locked for scope shared',
    'Commit lock is not currently held by admin',

]


class panCall(object):
    class PANKeyword_Error(RuntimeError):
        ROBOT_CONTINUE_ON_FAILURE = True

    # decorator to make the calls to the PAN API service, handle errors and pass the PAN output to the decorated function
    def __call__(self, pFunction):

        def pan_api_call(self, api_cmd=None, action=None, category=None, files=None, logtype=None, **data):
            api_call_type = pFunction.__name__.replace('pan_', '').lower()
            uri = '&type=%s' % api_call_type
            if action != None:
                uri += '&action=%s' % action
            if category != None:
                uri += '&category=%s' % category
            if api_cmd != None:
                uri += '&cmd=%s' % (etree.tostring(api_cmd))
            if logtype != None:
                uri += '&log-type=%s' % logtype
            logging.debug('posting to URL: %s' % (self.pan_base_url_for_logs + uri))
            if files != None:
                logging.info('uploading ruleset file: %s' % files)
                with open(files, 'rb') as f:
                    resp = self.session.post(self.pan_base_url + uri, files={'file': f}, verify=False)
            else:
                resp = self.session.post(self.pan_base_url + uri, verify=False)
            dots = '...(truncated)' if len(resp.text) > 800 else ''
            logging.debug('data returned from PAN device:\n%s' % resp.text[0:800] + dots)
            self.pan_call_error = False
            try:
                assert resp.status_code == 200, 'ERROR: PAN device rejected this command:\n%s\n%s' % (
                    self.pan_base_url + uri,
                    files)

                try:
                    resp_xml = etree.fromstring(resp.text)
                except:
                    raise AssertionError, 'ERROR:PAN device return badly formed XML:\n%s' % resp.text
            except AssertionError as error:
                return ('%s\%s' % (str(error), resp.text))
            if resp_xml.attrib['status'] != 'success':
                error_text = resp_xml.find('msg/line').text
                if error_text == None or error_text in BENIGN_ERROR:
                    return ({'result': 'WARNING: %s' % error_text})
                else:

                    self.pan_return_error = True
                    logging.warning(
                        'PAN device reported an unsuccessful call to %s: \n%s\n%s' % (api_call_type, uri, resp.text))
                    self.errstr = self.pan_return_errorstr = error_text
            else:
                self.pan_return_error = False

            # here is where we call the decorated function
            self.pan_response = pFunction(self, resp_xml, **data)

            if self.pan_return_error == True:
                self.errstr = self.pan_response['result'] = self.pan_response['error'] = deepcopy(
                    self.pan_return_errorstr)

            self.pan_response['raw'] = resp.text
            self.warning = 'Job successful'
            if self.pan_return_error == True:
                errstr = resp_xml.find('msg/line')
                if errstr != None:
                    self.warning = errstr.text
                    return ({'result': 'WARNING: %s' % self.warning})
                else:
                    self.errstr = 'Unknown return error: %s' % etree.tostring(rxml, pretty_print=True)
                    self.error = True
                    return ({'result': 'ERROR: %s' % self.errstr})
            return (self.pan_response)

        return (pan_api_call)


class PAN:
    class PANKeyword_Error(RuntimeError):
        ROBOT_CONTINUE_ON_FAILURE = True

    @varImport()
    def __init__(self, **evars):

        from axsess import Password

        if 'TestEnvironment' in evars:
            env = evars['TestEnvironment']
        elif 'TestEnvironment' in os.environ:
            env = os.environ['TestEnvironment']
        else:
            env = 'Agile'
        if 'ATF_User' in evars:
            user = evars['ATF_User']
        elif 'ATF_User' in os.environ:
            user = os.environ['ATF_User']
        else:
            user = None
        logging.debug('PAN environment is: %s' % env)
        assert user != None, 'Session user is not defined'
        logging.debug('PAN environment is: %s, user is:%s' % (env, user))

        P = Password(env.lower(), user)

        requests.packages.urllib3.disable_warnings()
        if 'pan_IP' in evars:
            self.pan_ip = evars['pan_IP']  # the RF script var file
            logging.debug('using var file PAN IP address %s' % self.pan_ip)
            self.env_method = 'evars'
        elif 'pan_IP' in os.environ:
            self.pan_ip = os.environ['pan_IP']
            logging.debug('using OS environment PAN IP address %s' % self.pan_ip)
            self.env_method = 'OSenv'
        else:
            self.pan_ip = P.get_device('pan', 'address')
            logging.debug('using %s server PAN IP address %s' % (self.environment, self.pan_ip))
            self.env_method = 'server_file'
        logging.info('target PAN device is %s' % self.pan_ip)
        device, pan_user, pan_password, creds = P.getCredentials(address=self.pan_ip)
        self.git_url = P.get_device('gitlab', 'address')
        get_device, git_user, self.access_token, git_creds = P.getCredentials(address=self.git_url)
        self.headers = {'PRIVATE-TOKEN': self.access_token}
        self.pan_creds = {'user': pan_user, 'password': pan_password}
        self.session = requests.Session()
        self.session.trust_env = False
        try:
            logging.debug(
                'GET to %s' % 'https://%s/api/?type=keygen&user=%s&password=********' % (self.pan_ip, pan_user))
            resp = self.session.get(
                'https://%s/api/?type=keygen&user=%s&password=%s' % (self.pan_ip, pan_user, pan_password), verify=False)
            keyxml = etree.fromstring(resp.text)
            keynode = keyxml.xpath('//key')
            assert len(keynode) > 0, 'No key node in response xml'
            self.pan_creds['key'] = keynode[0].text
        except Exception as estr:
            raise AssertionError, 'cannot authenticate to PAN device at %s: %s' % (self.pan_ip, estr)
        self.pan_base_url = 'https://%s/api/?key=%s' % (self.pan_ip, self.pan_creds['key'])
        self.pan_base_url_for_logs = 'https://%s/api/?key=********' % (self.pan_ip)
        self.loads = None
        self.uptimeparsed = None
        self.ruleset_xml = None
        self.added = {}
        self.changed = {}
        self.removed = {}
        self.rulesets = None
        self.counts = None
        self.rcid = None
        self.pan_response = ''
        self.pan_processes = None
        self.pan_call_error = False
        self.pan_call_errstr = ''
        self.pan_return_error = False
        self.pan_return_errorstr = ''
        self.warning = None
        self.errstr = None
        self.error = False
        self.customizations = None
        self.custom_xml = None
        self.filen = '%s_PANRC.xml' % self.pan_ip
        self.filed = None
        self.pan_jobid = None
        self.cpu = None
        self.lastcpu = None
        self.delta = {}
        self.deltastr = {}
        self.limit = {'memvals': {}, 'loads': {}, 'cpu': {}, 'swap': {}}
        self.memvals = self.lastmem = None
        self.loads = self.lastloads = None
        self.swap = self.lastswap = None
        self.pan_version = ''
        self.pan_model = ''
        self.limits = {
            'cpu':  # top		Robot Framework				  #      mnemonic		variable		Limit		lambdas (ceiling, floor, pcnt_ceiling, pcnt_floor, pcnt_variance)
                {

                    'us': ['CPU_USER', None, []],
                    'sy': ['CPU_KERNAL', None, []],
                    'ni': ['CPU_LOW_PRIORITY', None, []],
                    'id': ['CPU_IDLE', None, []],
                    'wa': ['CPU_IO_WAIT', None, []],
                    'hi': ['CPU_HW_INTERRUPT', None, []],
                    'si': ['CPU_SW_INTERRUPT', None, []],
                },
            'loads':
                {
                    '1  ': ['LOAD_1MIN', None, []],
                    '5  ': ['LOAD_5MIN', None, []],
                    '15 ': ['LOAD_15MIN', None, []],
                },
            'memvals':
                {'total  ': ['MEM_TOTAL', None, []],
                 'used   ': ['MEM_USED', None, []],
                 'free   ': ['MEM_FREE', None, []],
                 'buffers': ['MEM_BUF', None, []],
                 },
            'swap':
                {'total ': ['SWAP_TOTAL', None, []],
                 'used  ': ['SWAP_USED', None, []],
                 'free  ': ['SWAP_FREE', None, []],
                 'cached': ['SWAP_BUF', None, []],
                 }

        }

    """
    limit_ceiling = lambda v1,v2 L: True if L == None or (v2 - v1) <= L else False
    limit_floor = lambda v1,v2 L: True if L == None or (v2 - v1) >= L else False
    #limit_pceiling = lambda v1, v2, L : True if L == None or


    def Set_PAN_Limit(self, metric=None, func=None, value=None):
        assert metric != None, 'first argument to theis key word is missing'
        limit_func =  {
                'reset' 	: limit_reset ,
                'ceiling' 	: limit_ceiling,
                'floor' 	: limit_floor ,
                'pcnt-ceiling' 	: limit_pceiling,
                'pcnt-floor'	: limit_pfloor
                }
        assert func in limit_func, 'Invalid limit function'


        return
    """

    def parse_varfile(self, varfile_path):
        evars = {}
        try:
            with open(varfile_path, 'r') as f:
                varlist = f.readlines()
                line = 0
                for var in varlist:
                    if var[0] == '#':
                        continue
                    varname, value = var.strip().replace('--variable ', '').split(':', 1)
                    evars[varname] = value
            return (evars)
        except Exception as error:
            return ({'debug2': str(error)})

            ############################################################ methods used to communicate with PAN device #########################################

    def insert_error(self):
        if self.pan_call_error == True:
            error = self.pan_call_errstr
        elif self.pan_return_error == True:
            error = self.pan_return_errorstr
        else:
            error = None
        return (error)

    def extract_values(self, rxml, data):
        values = {}
	logging.debug('data values:\n%s' % str(data))
        if self.pan_call_error == True:
            error = self.pan_call_errstr
        elif self.pan_return_error == True:
            error = self.pan_return_errorstr
        else:
            error = None
        values['error'] = error
        if not 'xpath' in data and not 'values' in data:
            return ({'raw': etree.tostring(rxml, pretty_print=True)})
        if 'xpath' in data:
            xpath = '%s/' % data['xpath']
        else:
            xpath = ''
        for value in data['values'].split(','):
            nodes = rxml.xpath(xpath + value)
            if len(nodes) > 0:
                values[value] = ''
                for node in nodes:
		    if node != None and node.text != None:
                    	values[value] += '\n\t' + node.text
		    else:
			logging.debug('Empty node %s' % str(nodes)) 
            else:
                values[value] = 'parameter "%s" not found' % (xpath + value)
        return (values)

    @panCall()
    def pan_OP(self, rxml, **data):
        values = self.extract_values(rxml, data)
        return (values)

    @panCall()
    def pan_CONFIG(self, rxml, **data):
        values = self.extract_values(rxml, data)
        return (values)

    @panCall()
    def pan_IMPORT(self, rxml, **data):
        values = self.extract_values(rxml, data)
        # os.unlink(self.filen)
        return (values)

    @panCall()
    def pan_COMMIT(self, rxml, **data):
        values = self.extract_values(rxml, data)
        return (values)

    @panCall()
    def pan_LOG(self, rxml, **data):
        values = self.extract_values(rxml, data)
        return (values)

    ###########################################################  PAN communication exposed to Robot Framework as keywords ###########################

    @keyword()
    def Get_ATF_Meta_Data(self):
        return (''.join('\n%s' % str(s) for s in [self.env_method, self.pan_ip]))

    @keyword()
    def Get_Last_PAN_Warning(self):
        return (self.warning if self.warning != None else 'No Warnings')

    @keyword()
    def Get_Last_PAN_Error(self):
        return (self.errstr if self.errstr != None else 'No Errors')

    @keyword()
    def Get_PAN_Time(self):
        data = self.pan_OP(
            E.show(
                E.clock()
            ),
            xpath='//response',
            values='result'
        )
        timestr = data['result'].strip().replace(' EST', '').replace(' EDT', '')

        logging.debug('converting time "%s"' % timestr)
        tup = strptime(timestr[4:], '%b %d %H:%M:%S %Y')
        timestamp = str(mktime(tup))
        return (data['result'].strip(), timestamp)

    def get_log_data(self, timestamp, waittime, query):
        PAN_TIME_FORMAT = lambda t: strftime('%04Y/%2m/%d %02H:%02M:%02S', localtime(t))
        assert waittime.isdigit(), 'Specified wait time is not numeric'
        logging.info(
            'retrieving traffic since %s to current %s' % (PAN_TIME_FORMAT(float(timestamp)), PAN_TIME_FORMAT(time())))
        data = self.pan_LOG(None, None, None, None,
                            "%s&query=(time_generated geq '%s')" % (query, PAN_TIME_FORMAT(float(timestamp))),
                            xpath='//result',
                            values='job'
                            )
        jobid = data['job']
        logging.debug('extracted job ID %s' % str(jobid))
        expire = time() + int(waittime)
        timeout = True
        while time() <= expire:
            data = self.pan_LOG(
                None,
                'get&job-id=%s' % jobid,
                xpath='//job',
                values='status'
            )
            if data['status'].strip() == 'FIN':
                timeout = False
                break
            else:
                print
            sleep(10)
        assert timeout == False, 'timed out waiting %s seconds for log data using job ID %s' % (waittime, jobid)
        return (data)

    @keyword()
    def Get_Traffic_Data(self, timestamp, waittime='300'):
        data = self.get_log_data(timestamp, waittime, "traffic")
        return (str(data))

    @keyword()
    def Get_Packet_Counts(self, iface):
        data = self.pan_OP(
            E.show(
                E.interface(iface)
            ),
            xpath='//counters/ifnet/entry',
            values='ibytes,obytes'
        )

        return (int(data['obytes'].strip()), int(data['ibytes'].strip()))

    @keyword()
    def Get_Threat_Data(self, timestamp, waittime='300', include_pan_alerts=True):
        data = self.get_log_data(timestamp, waittime, "threat")
        xml = etree.fromstring(data['raw'])
        threats = xml.xpath('//logs/entry')
        rstr = ''
        pan_alerts = 0
        swcx_alerts = 0
        for x in threats:
            tid = int(x.find('tid').text)
            if tid < 16000 or tid > 18000:
                pan_alerts += 1
                if include_pan_alerts == False:
                    continue
            else:
                swcx_alerts += 1
            rstr.join('%s:%s-%s %s %s:%s->%s:%s %s\n' % (
                tid,
                x.find('time_received').text,
                x.find('threatid').text,
                x.find('proto').text,
                x.find('src').text,
                x.find('sport').text,
                x.find('dst').text,
                x.find('dport').text,
                x.find('action').text
            )
                      )
        return (swcx_alerts, pan_alerts, rstr)

    def versionIsEqual(self, ver1, ver2):
        v1 = re.findall('(release|Number)(\-|\s)(\d+)', ver1, re.IGNORECASE)
        v2 = re.findall('(release|Number)(\-|\s)(\d+)', ver2, re.IGNORECASE)
        try:
            if v1[0][2] != v2[0][2]:
                return (False)
            return (True)
        except IndexError:
            raise AssertionError, 'ERROR: unable to parse ruleset version strings:\n\trcid(%s):%s\n\tPAN(%s):%s' % (
                v1, ver1, v2, ver2)

    @keyword()
    def Import_PAN_Ruleset(self):
        if self.filen == None:
            self.errstr = 'The release candidate was never downloaded from Github diring this session'
            raise AssertionError, self.errstr
        self.pan_IMPORT(None, None, 'configuration', self.filen)
        if self.error == False:
            return ('Import of release candidate was successful')
        else:
            return ('ERROR: %s' % self.errstr)

    @keyword()
    def Deploy_PAN_Ruleset(self, rcid, **opts):
        logging.info('using batch commands to deploy ruleset %s to PAN device at %s' % (rcid, self.pan_ip))
        v = re.findall('release\-\d+\-\d+', rcid)
        assert len(v) > 0, 'invalid version format'
        rel_no = self.get_release_no_from_git(rcid)
        logging.info('obtaining ruleset version that is currently on the PAN device prior to deployment')
        version_on_pan = self.Get_PAN_Ruleset_Version()
        logging.info(
            'ruleset version:\n\t"%s"\nthat is currently on the PAN device will be replaced with version:\n"%s"' % (
                version_on_pan, rcid))
        if self.versionIsEqual(version_on_pan, rcid):
            logging.info('WARNING: Deploying the same version (%s) that is already on the PAN device' % rcid)

        rcxml = self.Get_PAN_Ruleset_RC(rcid, returnXML=True)
        rcn = self.get_release_no_from_git(rcid)
        self.filen = '%s_PANRC.xml' % self.pan_ip
        with open(self.filen, 'w') as f:
            f.write(rcxml)
        rc = etree.fromstring(rcxml, PARSER)
        rcnodes = rc.xpath('//entry[@name="16000"]')
        assert len(rcnodes) > 0, 'Unable to locate SCWX ruleset ID'
        rc_threatname = rcnodes[0].find('threatname')
        self.Remove_All_Locks()
        self.Set_PAN_Commit_Lock()
        self.Set_PAN_Config_Lock()
        self.Save_PAN_Config()
        data = self.pan_IMPORT(None, None, 'configuration', self.filen)
        logging.info('import result:\n%s' % data)
        if self.pan_return_error:
            self.Remove_All_Locks()
            rstr = self.load_running_config()
            data['result'] = 'ERROR importing ruleset file into PAN device'
        data = self.Load_Local_PAN_XML_File()
        logging.info('load result: %s\n' % data)
        self.pan_jobid = self.PAN_Commit_RC()
        logging.info('commit result: %s\n' % data)
        logging.info('jobid=%s...waiting for job to complete' % self.pan_jobid)
        data = self.Wait_For_Successful_Commit()
        if 'successful' in data['result']:
            return ('Deployment of ruleset "%s" to PAN device at %s was successful' % (rcid, self.pan_ip))
        else:
            return ('ERROR:Deployment of ruleset "%s" to PAN device at %s FAILED' % (rcid, self.pan_ip))

    @keyword()
    def Get_PAN_Job_Status(self, jobid):
        assert jobid != None, 'Commit job ID was not specified'
        data = self.pan_OP(
            E.show(
                E.jobs(
                    E('id', jobid)
                )
            ),
            xpath='//result/job',
            values='status,result'
        )
        data['status'] = data['status'].lstrip()
        data['result'] = data['result'].lstrip()
        try:
            assert data['status'] != 'ERR', result
            assert data['result'] != 'FAIL'
        except AssertionError:
            xml = etree.fromstring(data['raw'], PARSER)
            details = xml.xpath('//details/line')
            data['result'] = 'ERROR: PAN device rejected the ruleset due to '
            for line in details:
                data['result'] += '%s\n' % line.text
        return (data['status'], data['result'])

    @keyword()
    def Wait_For_Successful_Commit(self, jobid=None, waittime='1500'):
        assert jobid != None, 'Commit job ID was not specified'
        try:
            assert int(waittime) > 0, 'Invalid wait time specified'
        except:
            raise AssertionError, 'Invalid wait time specified'
        status = result = ''
        expiration = time() + int(waittime)
        timeout = True
        while time() < expiration:
            status, result = self.Get_PAN_Job_Status(jobid)
            if status == 'FIN':
                if result.startswith('ERROR'):
                    return (result)
                timeout = False
                break
            sleep(10)
        if timeout == True:
            return ('ERROR: Job did not complete in specified %s seconds: \n\tstatus="%s", result="%s"' % (
                waittime, status, result))
        return (
                'Commit with jobid: "%s" was successful after %d seconds' % (
        jobid, int(waittime) - (expiration - time())))

    @keyword()
    def Load_Local_PAN_XML_File(self):
        from_pan_xpath = '/config/devices/entry/vsys/entry/threats/spyware'
        to_pan_xpath = '/config/shared/threats/spyware'
        data = self.pan_OP(
            E.load(
                E.config(
                    E.partial(
                        E.mode('replace'),
                        E('from', self.filen),
                        E('from-xpath', from_pan_xpath),
                        E('to-xpath', to_pan_xpath),
                    )
                )
            ),
            xpath='//result/msg',
            values='line'
        )
        return (data)

    def load_running_config(self):
        logging.info('loading running config')
        data = self.pan_OP(
            E.load(E.config(E('from', 'running-config.xml'))),
        )
        return (data)

    def Reapply_PAN_Custom_SIGS(self):  # This code not needed or used in performance test environment
        # custom sigs could impact throughput
        xpath = E.config(E.devices(E.entry(E.vsys(E.entry(E.threats(E.spyware()))))))
        for custom_rule in self.custom_xml:
            post.append(self.custom_xml[0])

        print
        etree.tostring(post, pretty_print=True)
        # so this code isn't excecuted
        trap
        data = self.pan_OP(
            E.config(E.devices(E.entry(E.vsys(E.entry(E.threats(E.spyware(self.custom_xml))))))),
            'set',
        )
        # ... Did not code the rest after discussing with Raul

        return

    @keyword()
    def PAN_Commit_RC(self):
        logging.debug('committing ruleset')
        data = self.pan_COMMIT(E.commit(), xpath='//result/msg', values='line')
        logging.debug('commit result: %s' % str(data))
        data['result'] = data['line']
        jobid = re.findall('jobid\s\d+', data['line'])
        logging.debug('extracted job ID %s' % str(jobid))
        if len(jobid) > 0:
            self.pan_jobid = jobid[0].split(' ')[1]
        assert self.pan_jobid != None, 'ERROR: failed to obtain job ID after commit'
        return (self.pan_jobid)

    @keyword()
    def Get_PAN_Stats(self, fetch='N_PACKETS,TERMINATE,DROP,CONTINUE,BYPASS,ERROR,OOR,id'):
        fetch_list = fetch.split(',')
        assert len(fetch_list) > 0, 'ERROR: No statistic label supplied in argument'
        valid = True
        for fetch_arg in fetch_list:
            if fetch == '':
                valid = False
        assert valid == True, 'ERROR: empty value in comma separated list statistic labels'
        total = {}
        data = {'raw': 'foo'}

        for metric in fetch_list:
            data = self.pan_OP(
                E.show(
                    E.statistics()
                ),
                xpath='//entry',
                values=metric
            )
            values = data[metric].lstrip().split('\n\t')
            total[metric] = sum(int(x) for x in values)

        data.pop('raw')
        return (''.join('%s: %s\n' % (d, total[d]) for d in fetch_list))

    @keyword()
    def Clear_PAN_Stats(self):
        logging.debug('clearing PAN stats')
        data = self.pan_OP(
            E.clear(
                E.statistics()
            )
        )
        return (data)

    @keyword()
    def Clear_PAN_Sessions(self):
        logging.debug('clearing PAN sessions')
        data = self.pan_OP(
            E.clear(
                E.session(E('all'))
            )
        )
        return (data)

    @keyword()
    def Get_PAN_Max_Sessions(self, timestamp=None):
        current_pan_time, current_pan_epoch = self.Get_PAN_Time()
        epoch = float(current_pan_epoch)
        logging.info('requesting session counts between times %s and %s' % (current_pan_epoch, timestamp))
        try:
            assert timestamp != None, 'Missing timestamp'
            seconds = epoch - float(timestamp) if timestamp != None else 60.0
            timespan = seconds / 60.0  # resources are viewed in one minute resolutions
            logging.info('calculate timespan to be the last %f minutes' % timespan)
            assert timespan > 1.0, 'Minimum of two minute time span required (%s - %s)' % (current_pan_epoch, timestamp)
            assert timespan < 61.0, 'Maximum of 60 minute timespan allowed (%s - %s , %f given)' % (
                current_pan_epoch, timestamp, timespan)
        except Exception as error:
            raise AssertionError, 'Invalid timestamp (%s) supplied: %s' % (timestamp, str(error))
        data = self.pan_OP(
            E.show(
                E.running(
                    E('resource-monitor', E.minute())
                )
            ),
            xpath='//resource-utilization/',
            values='value'
        )
        xml = etree.fromstring(data['raw'])
        sessions_node = xml.xpath('//name[text()="session (average)"]')
        session_averages = sessions_node[0].getparent().find('value')
        intlist = map(lambda x: int(x.replace('\n\t', '')), session_averages.text.split(','))
        in_band = intlist[0:int(timespan)]
        print
        intlist
        return ('Max session count: %d pcnt' % max(in_band))

    @keyword()
    def Test_PAN_Resources(self, timestamp=None, metric='cpu-load-maximum', limitstr='85.0'):
        limit = float(limitstr)
        current_pan_time, current_pan_epoch = self.Get_PAN_Time()
        epoch = float(current_pan_epoch)
        logging.info('testing resource metrics between times %s and %s' % (current_pan_epoch, timestamp))
        try:
            assert timestamp != None, 'Missing timestamp'
            seconds = epoch - float(timestamp) if timestamp != None else 60.0
            timespan = seconds / 60.0  # resources are viewed in one minute resolutions
            logging.info('calculate timespan to be the last %f minutes' % timespan)
            assert timespan > 1.0, 'Minimum of two minute time span required (%s - %s)' % (current_pan_epoch, timestamp)
            assert timespan < 61.0, 'Maximum of 60 minute timespan allowed (%s - %s , %f given)' % (
                current_pan_epoch, timestamp, timespan)
        except Exception as error:
            raise AssertionError, 'Invalid timestamp (%s) supplied: %s' % (timestamp, str(error))

        data = self.pan_OP(
            E.show(
                E.running(
                    E('resource-monitor', E.minute())
                )
            ),
            xpath='//%s' % metric,
            values='value'
        )
        xml = etree.fromstring(data['raw'])
        # logging.debug(data['raw'])
        test_failed = False
        result = ''
        for core in xml.xpath('//%s/entry/coreid' % metric):
            if core.text == '0':  # core 0 is the one used exclusively by the management functions
                continue
            values = core.getparent().find('value')
            intlist = map(lambda x: int(x.replace('\n\t', '')), values.text.split(','))
            print
            intlist
            logging.debug('intlist for core %s: %s' % (core.text, str(intlist)))
            in_band = intlist[0:int(timespan)]
            logging.debug('in-band list for core %s: %s' % (core.text, str(in_band)))
            failed_periods = map(lambda x: str(x > limit), in_band)
            logging.debug('failed_periods for core %s: %s' % (core.text, str(failed_periods)))
            if failed_periods.count('True') > 0:
                result += 'FAIL: One or more %s values for core %s exceeded %s pcnt. limit\t\n%s\n' % (
                    metric, core.text, limit, str(in_band))
                test_failed = True
            else:
                result += 'PASS: all %s values for core %s were within %s pcnt. limit\t\n%s\n' % (
                    metric, core.text, limit, str(in_band))
        if test_failed:
            return ('FAIL: One or more core %s values exceeded the limit of %s pcnt.' % (metric, limit), result)
        if result == '':
            return ('FAIL: Unable to retrieve resource values')
        return ('PASS: all %s periods for all cores were within %s pcnt. limit' % (metric, limit), result)

    # As it turns out this function only pulls the resources for the management port.  It is left in just in case that becomes a requirment
    @keyword()
    def Get_PAN_Resources(self, resource=None, discrete_value=None, **opts):
        expandint = lambda s: long(s.lower().replace('k', '000').replace('m', '000000'))
        value = lambda v: '+%s' % str(v) if v >= 0 else str(v)
        data = self.pan_OP(
            E.show(E.system(E.resources)),
            values='result')
        text = data['result']
        pan_procs = re.findall('\d+\:\d{2}.*pan_[a-z]*', text)
        pproc = {}
        pan_procs = re.findall('.*pan_[a-z]*', text)
        for p in pan_procs:
            fields = p.split()
            pname = fields[10]
            pproc[pname] = {'pid': fields[0], 'ptime': fields[9], 'cpupcnt': fields[7], 'mempcnt': fields[8]}
        self.pan_processes = ''.join('\t\t%s: pid=%s, time=%s, cpu%s=%s, mem%s=%s\n' % (
            pname,
            pproc[pname]['pid'],
            pproc[pname]['ptime'],
            r'%',
            pproc[pname]['cpupcnt'],
            r'%',
            pproc[pname]['mempcnt']) for pname in pproc)
        self.lastmem = deepcopy(self.memvals)

        try:
            # CPU Stats
            cpuspec = re.findall(
                '(Cpu\S+:\s+)(\d+\.\d+)(\S+,\s+)(\d+\.\d+)(\S+,\s+)(\d+\.\d+)(\S+,\s+)(\d+\.\d+)(\S+,\s+)(\d+\.\d+)(\S+,\s+)(\d+\.\d+)(\S+,\s+)(\d+\.\d+)(\S+,\s+)',
                text)[0]
            self.cpu = {
                'us': [float(cpuspec[1]), 'in user space'],
                'sy': [float(cpuspec[3]), 'in kernel space'],
                'ni': [float(cpuspec[5]), 'on low priority processes'],
                'id': [float(cpuspec[7]), 'in idle operations'],
                'wa': [float(cpuspec[9]), 'on waiting on IO peripherals (eg. disk)'],
                'hi': [float(cpuspec[11]), 'handling hardware interrupt routines'],
                'si': [float(cpuspec[13]), 'handling software interrupt routines']
            }

            self.delta['cpu'] = {}
            self.deltastr['cpu'] = {}

            for metric in self.cpu:
                if self.lastcpu != None:
                    self.delta['cpu'][metric] = self.cpu[metric][0] - self.lastcpu[metric][0]
                    self.deltastr['cpu'][metric] = value(self.cpu[metric][0] - self.lastcpu[metric][0])
                else:
                    self.delta['cpu'][metric] = 0.0
                    self.deltastr['cpu'][metric] = ''
            self.lastcpu = deepcopy(self.cpu)

            # Memory stats
            memspec = \
                re.findall('(Mem:\s+)(\d+\w)(\s+total,\s+)(\d+\w)(\s+used,\s+)(\d+\w)(\s+free,\s+)(\d+\w)(\s+buffers)',
                           text)[0]
            self.memvals = {'total  ': expandint(memspec[1]), 'used   ': expandint(memspec[3]),
                            'free   ': expandint(memspec[5]), 'buffers': expandint(memspec[7])}
            self.delta['memvals'] = {}
            self.deltastr['memvals'] = {}
            for metric in self.memvals:
                if self.lastmem != None:
                    self.delta['memvals'][metric] = self.memvals[metric] - self.lastmem[metric]
                    self.deltastr['memvals'][metric] = value(self.memvals[metric] - self.lastmem[metric])
                else:
                    self.delta['memvals'][metric] = 0
                    self.deltastr['memvals'][metric] = ''
            self.lastmem = deepcopy(self.memvals)

            # Swap stats
            swapspecs = \
                re.findall('(Swap:\s+)(\d+\w)(\s+total,\s+)(\d+\w)(\s+used,\s+)(\d+\w)(\s+free,\s+)(\d+\w)(\s+cached)',
                           text)
	    if len(swapspecs) > 0:
		swapspec = swapspecs[0]
	    else:
		raise AssertionError, 'No swap specs returned from device'
	    logging.debug('swapspec (%d) = %s' % (len(swapspec),swapspec))
            self.swap = {'total ': expandint(swapspec[1]), 'used  ': expandint(swapspec[3]),
                         'free  ': expandint(swapspec[5]), 'cached': expandint(swapspec[7])}
            self.delta['swap'] = {}
            self.deltastr['swap'] = {}
            for metric in self.swap:
                if self.lastswap != None:
                    self.delta['swap'][metric] = self.swap[metric] - self.lastswap[metric]
                    self.deltastr['swap'][metric] = value(self.swap[metric] - self.lastswap[metric])
                else:
                    self.delta['swap'][metric] = 0
                    self.deltastr['swap'][metric] = ''
            self.lastswap = deepcopy(self.swap)

            # Load Avg statrs
            loadavg_specs = re.findall('(load\saverage:\s+)(\d+\.\d+)(,\s+)(\d+\.\d+)(,\s+)(\d+\.\d+)', text)
	    if len(loadavg_specs) > 0:
		loadavg_spec = loadavg_specs[0]
	    else:
		loadavg_spec = ''
            self.loads = {'1  ': float(loadavg_spec[1]), '5  ': float(loadavg_spec[3]), '15 ': float(loadavg_spec[5])}
            self.delta['loads'] = {}
            self.deltastr['loads'] = {}
            for metric in self.loads:
                if self.lastloads != None:
                    self.delta['loads'][metric] = self.loads[metric] - self.lastloads[metric]
                    self.deltastr['loads'][metric] = value(self.loads[metric] - self.lastloads[metric])
                else:
                    self.delta['loads'][metric] = 0
                    self.deltastr['loads'][metric] = ''

            self.lastloads = deepcopy(self.loads)
            # Uptime
            uptimespec = re.findall('up.*users', text)
	    if len(uptimespec) > 0:
            	self.uptimeparsed = uptimespec[0].replace('up ', '').split(',')
	    else:
		self.uptimeparsed = ''
        except Exception as error:
            logging.warning('ERROR: encountered "%s" while parsing resource spec:\n"%s"' % (error, text[0:100]))
            return ('ERROR parsing resource spec')
        discrete = lambda r, s: '%6.2f\n' % r[discrete_value][
            0] if discrete_value != None and discrete_value in r else ''.join('%s:%6.2f\n' % (c, r[c][0]) for c in r)
        discrete2 = lambda r, s: '%6.2f\n' % r[
            discrete_value] if discrete_value != None and discrete_value in r else ''.join(
            '%s:%6.2f\n' % (c, r[c]) for c in r)
        discrete3 = lambda r, s: '%10ld\n' % r[
            discrete_value] if discrete_value != None and discrete_value in r else ''.join(
            '%s:%10ld\n' % (c, r[c]) for c in r)
        if resource == 'cpu':
            return (discrete(self.cpu, 'cpu').strip())
        elif resource == 'loads':
            return (discrete2(self.loads, 'loads').strip())
        elif resource == 'memvals':
            return (discrete3(self.memvals, 'memvals').strip())
        elif resource == 'swap':
            exceeded_limit = False
            if 'limit' in opts and discrete_value != None and self.deltastr['swap'] != None:
                if self.delta['swap'] > 0.0 and (
                        (self.delta['swap'][discrete_value] * 100) / (1 + self.swap[discrete_value])) > float(
                    opts['limit']):
                    exceeded_limit = True
            return (discrete3(self.swap, 'swap').strip(), exceeded_limit)

        rstr = '\nPAN Device Resource Report:\n\n\tUptime/Users: %s\n\tCpu Usage (percentage):%s\n\tLoad Avgs: %s\n\tMemory: %s\n\tSwap: %s\n\tPAN processes:\n%s' % (
            ''.join('%s, ' % u for u in self.uptimeparsed).rstrip(','),
            ''.join(
                '\n\t\t%5.2f\t%s\t\ttime spent %s' % (self.cpu[c][0], self.deltastr['cpu'][c], self.cpu[c][1]) for c in
                self.cpu),
            ''.join('\n\t\t%sminute: %6.2f\t%s ' % (v, self.loads[v], self.deltastr['loads'][v]) for v in self.loads),
            ''.join('\n\t\t%s: %8ld\t%s ' % (s, self.memvals[s], self.deltastr['memvals'][s]) for s in self.memvals),
            ''.join('\n\t\t%s: %10ld\t%s ' % (s, self.swap[s], self.deltastr['swap'][s]) for s in self.swap),
            self.pan_processes
        )
        data['result'] = CHECK_FOR_ERROR(data, rstr)
        return (rstr)

    @keyword()
    def Get_PAN_Info(self, values='hostname,ip-address,model,uptime,serial,sw-version', terse=False):
        from os.path import basename

        data = self.pan_OP(
            E.show(E.system(E.info)),
            xpath='result/system',
            values=values
        )
        data.pop('raw')
        if terse == False:
            result = ''.join('%s:%s\n' % (basename(p), data[p]) for p in data)
        else:
            if data['error'] == None:
                e = data.pop('error')
            result = ''.join('%s,' % data[p] for p in data).rstrip(',').strip()
            logging.info('returning..%s' % ''.join('%s=%s,' % (p, data[p]) for p in data))
            data['error'] = e
        data['result'] = CHECK_FOR_ERROR(data, result)
        # rval = ''.join('%s: %s\n' % (basename(p), result[p]) for p in result)
        return (data['result'])

    @keyword()
    def Get_PAN_Ruleset_Version(self):
        data = self.pan_CONFIG(
            E.show(E.xpath('/config/devices/entry/vsys/entry/threats/spyware', E.element())),
            xpath='//shared//entry[@name="16000"]',
            values='threatname'
        )
        threatname = data['threatname'].lstrip()
        if 'not found' in threatname:
            return ('release None 0')
        try:
            vatts = re.findall('.*(release)\D+(\d+).*(\d{10,12})', threatname, re.IGNORECASE)[0]
            assert len(vatts) == 3, 'corrupt version specification: %s' % str(vatts)
        except Exception as error:
            return ('ERROR: corrupt version specification: %s\n%s' % (threatname, str(error)))
        with open('/tmp/pan_rulesetdump', 'w') as f:
            f.write(data['raw'])
        release, version, epoch = vatts
        rstr = ''.join('%s %s %s' % ('release', version, epoch))
        logging.debug('%s\nthreatname="%s"' % (rstr, threatname))
        return (rstr)

    @keyword()
    def Compare_PAN_Ruleset_Versions(self, version1, version2):
        logging.info('comparing version "%s" to version "%s"' % (version1, version2))
        try:
            r1, v1, e1 = re.findall('.*(release)\D+(\d+).*(\d{10,12})', version1, re.IGNORECASE)[0]
        except:
            logging.error('ERROR: first version is invalid')
            return (False)
        try:
            r2, v2, e2 = re.findall('.*(release)\D+(\d+).*(\d{10,12})', version1, re.IGNORECASE)[0]
        except:
            logging.error('ERROR: second version is invalid')
            return (False)
        if v1 != v2 or abs(int(e1) - int(e2)) > 120:
            logging.error('the versions do not have the same ID or were created at different times')
            return (False)
        else:
            logging.info('both versions have the same ID and were created at the same time')
            return (True)

    @keyword()
    def PAN_Pending_Changes(self):
        data = self.pan_OP(
            E.check(E('pending-changes')),
            values='result'
        )
        self.warning = 'WARNING: PENDING CHANGES EXIST' if data['result'] == 'yes' else 'NO PENDING CHANGES'
        logging.info(self.warning)
        return (True if data['result'] != None else False)

    @keyword()
    def PAN_Commit_Locks(self):
        data = self.pan_OP(
            E.show(E('commit-locks')),
            values='result'
        )
        self.warning = 'WARNING: COMMIT LOCK EXISTS:\n%s' % data['result'] if data[
                                                                                  'result'] != None else 'NO COMMIT LOCK FOUND'
        logging.info(self.warning)
        return (True if data['result'] != None else False)

    @keyword()
    def PAN_Config_Locks(self):
        data = self.pan_OP(
            E.show(E('config-locks')),
            values='result'
        )
        self.warning = 'WARNING: CONFIG LOCK  EXISTS: %s' % data['result'] if data[
                                                                                  'result'] != None else 'NO CONFIG LOCK FOUND'
        logging.info(self.warning)
        return (True if data['result'] != None else False)

    @keyword()
    def Set_PAN_Config_Lock(self):
        data = self.pan_OP(
            E.request(E('config-lock', E.add())),
            values='result'
        )
        return (data['result'])

    @keyword()
    def Remove_PAN_Config_Lock(self):
        data = self.pan_OP(
            E.request(E('config-lock', E.remove())),
            values='result'
        )
        return (data['result'])

    @keyword()
    def Set_PAN_Commit_Lock(self):
        data = self.pan_OP(
            E.request(E('commit-lock', E.add())),
            values='result'
        )
        return (data['result'])

    @keyword()
    def Remove_PAN_Commit_Lock(self):
        data = self.pan_OP(
            E.request(E('commit-lock', E.remove())),
            values='result',
            catch=True
        )
        return (data['result'])

    @keyword()
    def Save_PAN_Config(self):
        filename = "SWRX_ATF_Test_Saved_Config"
        data = self.pan_OP(
            E.save(E.config(E.to(filename))),
            values='result'
        )
        return (data['result'])

    def Remove_All_Locks(self):
        rstr = '\n' + self.Remove_PAN_Config_Lock()
        rstr += '\n' + self.Remove_PAN_Commit_Lock()
        return (rstr)

    def Get_Custom_SIGS(self):
        data = self.pan_CONFIG(
            E.config(E.devices(E.entry(E.vsys(E.entry(E.threats))))),
            'show'
        )
        # save the customizations so they can be restore Restore_PAN_Custom_SIGS_
        no_spaces = re.compile('>\s+<')
        self.custom_xml = etree.fromstring(data['raw']).xpath('//spyware/entry[starts-with(@name,"15")]')
        customizations = ''.join(etree.tostring(c, pretty_print=True).replace('\n', '') for c in self.custom_xml)
        self.customizations = no_spaces.sub('><', customizations.replace('\n', ''))

        data['result'] = CHECK_FOR_ERROR(data, ''.join(
            '%s - %s' % (sig.attrib['name'], sig.find('threatname').text) for sig in self.custom_xml))
        return (data['result'])

    @keyword()
    def Get_PAN_Metric(self, metric_label, **opts):
        data = self.pan_OP(
            E.show(
                E.counter(
                    E('global',
                      E.name(metric_label)
                      )
                )
            ),
            xpath='//entry',
            values='desc,value'
        )
        if 'desc' not in data:
            return ('The PAN device reject the metric name %s: %s' % (metric_label, data['result']))
        if not 'terse' in opts or opts['terse'] == False:
            data['result'] = CHECK_FOR_ERROR(data, '%s = %s' % (data['desc'].strip(), data['value'].strip()))
        else:
            data['result'] = data['value'].strip()

        return (data['result'])

    @keyword()
    def Get_All_PAN_Metrics(self, **opts):
        try:
            with open('%s/pan_metrics.manifest' % CGILIBPATH) as m:
                mstr = m.read()
            metrics = eval(mstr)
        except IOError:
            raise AssertionError, 'Missing PAN Metrics Manifest'
        results = ''
        for metric in metrics:
            metric_value = self.Get_PAN_Metric(metric, terse=False)
            results += '%s: %s\n' % (metric, metric_value)
        return (results)

    @keyword()
    def Publish_Performance_Results(self, results_file='pan_performance_samples.csv', **opts):
        from atf_results import PAN_Results
        R = PAN_Results('Ruleset_Performance')
        R.processPerformanceSamples(results_file)

    ###########################################################  methods to pull release candidate from GIT #############################################
    def get_release_no_from_git(self, rcid):
        # if this call fails its probably because the token has expired.  The current token expires 1/1/2020 and is under my account g.m.o
        # if a new token is genned, place the token in the servers file 'git' node then run the ATF password encryption program
        self.rcid = rcid
        rc_url = '%s/RELEASE_NUMBER/raw?ref=%s&private_token=%s' % (self.git_url, rcid, self.access_token)
        # rc_url = '%s/%s/RELEASE_NUMBER?private_token=%s' % (self.git_url, rcid, self.access_token)
        logging.debug('contacting GitLab at to retrieve release number:\n%s' % rc_url)
        resp = requests.get(rc_url, verify=False)
        logging.debug('received the following response from GitLab:\n%s' % resp.text)
        assert resp.text.find('DOCTYPE html') < 0, 'specifed ruleset candidate "%s" does not exist' % rcid
        return (resp.text)

    @keyword()
    def Get_PAN_Ruleset_RC(self, rcid, **opts):
        if '-subPA3000' in rcid:
            rcid = rcid.replace('-subPA3000', '')
            small = '-subPA3000'
        else:
            small = ''
        release_number = self.get_release_no_from_git(rcid)
        release_number += small
        ruleset_url = '%s/releases%%2FCTU-PAN-ruleset-release-%s.xml/raw?ref=%s&private_token=%s' % (
            self.git_url, release_number, rcid, self.access_token)
        logging.debug('using the following URL to retrieve ruleset:\n%s' % ruleset_url)
        resp = requests.get(ruleset_url, verify=False)
        assert resp.text.find('DOCTYPE html') < 0, 'specifed ruleset candidate "%s" does not exist' % rcid
        self.rulesets = resp.text
        logging.debug('received the following text from GitLab\n%s' % resp.text)
        if 'returnXML' in opts and opts['returnXML'] == True:
            return (self.rulesets)
        with open(self.filen, 'w') as f:
            f.write(self.rulesets)
        xpath = '//entry[@name="16000"]/threatname'

	if resp.status_code != 200:
		raise AssertionError, resp.text

        rxml = etree.fromstring(resp.text)
        self.rsid = rxml.xpath(xpath)
        return (self.rsid)

    @keyword()
    def Get_PAN_Ruleset_Release_Notes(self, rcid):
        if '-subPA3000' in rcid:
            rcid = rcid.replace('-subPA3000', '')
            small = '-subPA3000'
        else:
            small = ''
        release_number = self.get_release_no_from_git(rcid)
        release_number += small
        ruleset_url = '%s/release-notes%%2FCTU-PAN-ruleset-release-%s-notes.txt/raw?ref=%s&private_token=%s' % (
            self.git_url, release_number, rcid, self.access_token)

        resp = requests.get(ruleset_url, verify=False)
        with open('/tmp/%s-diffs.txt' % rcid, 'w') as f:
            f.write(resp.text)
        added_x = resp.text.find('\nAdded')
        changed_x = resp.text.find('\nChanged')
        removed_x = resp.text.find('\nRemoved')
        rules = re.findall('^\s+\d+\s+VID\d+.*$', resp.text, re.MULTILINE)
        for rule in rules:
            rule_id = re.findall('\d+\s+VID\d+', rule)[0]
            if resp.text.find(rule) < changed_x:
                self.added[rule_id] = rule.lstrip()
            elif resp.text.find(rule) < removed_x:
                self.changed[rule] = rule.lstrip()
            else:
                self.removed[rule] = rule.lstrip()
        return (resp.text)

    @keyword()
    def Validate_PAN_Ruleset(self, rcid):
        import json
        from json import JSONDecoder, dumps
        from hashlib import sha256

        J = JSONDecoder()
        if self.rulesets == None:
            return ('ERROR: no rulesets have been downloaded from GitLab')
        try:
            rssum = sha256(self.rulesets)
            ruleset_sum = rssum.hexdigest()
            logging.debug('downloaded ruleset sum= %s' % ruleset_sum)
        except Exception as error:
            return ('ERROR: unable to compute sha256 sum on ruleset %s: %s' % (rcid, str(error)))

        if '-subPA3000' in rcid:
            rcid = rcid.replace('-subPA3000', '')
            small = '-subPA3000'
        else:
            small = ''
        release_number = self.get_release_no_from_git(rcid)
        release_number += small
        ruleset_url = '%s/release-notes%%2FCTU-PAN-ruleset-release-%s-notes.json/raw?ref=%s&private_token=%s' % (
            self.git_url, release_number, rcid, self.access_token)
        resp = requests.get(ruleset_url, verify=False)
        self.diffs = J.decode(resp.text)
        self.__dict__['ruleset_sha256'] = self.diffs['sha256'] if 'sha256' in self.diffs else 'N/A'
        if self.ruleset_sha256 != 'N/A' and self.ruleset_sha256 != ruleset_sum:
            return ('ERROR: sha5 sums do not match, downloaded=%s, CTU sum = %s' % (ruleset_sum, self.ruleset_sha256))
        logging.debug('response from GitLab: \n%s' % dumps(self.diffs, sort_keys=True, indent=4, separators=(',', ':')))
        return (self.ruleset_sha256)

    @keyword()
    def Get_PAN_Ruleset_Diffs(self, rcid):
        import json
        from json import JSONDecoder, dumps

        J = JSONDecoder()
        if '-subPA3000' in rcid:
            rcid = rcid.replace('-subPA3000', '')
            small = '-subPA3000'
        else:
            small = ''
        release_number = self.get_release_no_from_git(rcid)
        release_number += small
        ruleset_url = '%s/release-notes%%2FCTU-PAN-ruleset-release-%s-notes.json/raw?ref=%s&private_token=%s' % (
            self.git_url, release_number, rcid, self.access_token)

        resp = requests.get(ruleset_url, verify=False)
        self.diffs = J.decode(resp.text)
        self.__dict__['ruleset_sha256'] = self.diffs['sha256'] if 'sha256' in self.diffs else 'N/A'
        self.counts = [len(self.diffs['added']), len(self.diffs['changed']), len(self.diffs['removed'])]
        logging.debug('response from GitLab: \n%s' % dumps(self.diffs, sort_keys=True, indent=4, separators=(',', ':')))
        return (self.counts, self.diffs, self.ruleset_sha256)

    @keyword()
    def Verify_PAN_Ruleset_Diffs(self, rcid=None):
        assert rcid != None, 'no PAN rulesets has been specified'
        if '-subPA3000' in rcid:
            rcid = rcid.replace('-subPA3000', '')
            small = '-subPA3000'
        else:
            small = ''
        release_number = self.get_release_no_from_git(rcid)
        release_number += small
        count, diffs, sha256 = self.Get_PAN_Ruleset_Diffs(rcid)
        rulesets = etree.fromstring(self.Get_PAN_Ruleset_RC(rcid, returnXML=True), PARSER)

        verified = True
        estr = ''
        for rule in diffs['added']:
            rule_found = rulesets.xpath('//threatname[text()="%s"]' % diffs['added'][rule])
            if rule_found == None:
                verified = False
                error = 'added rule: %s is missing from ruleset %s' % (rule, rcid)
                logging.error(error)
                estr += '%s\n' % error
        for rule in diffs['removed']:
            rule_found = rulesets.xpath('//threatname[text()="%s"]' % diffs['added'][rule])
            if rule_found != None:
                verified = False
                error = 'removed rule: %s was found in ruleset %s' % (rule, rcid)
                logging.error(error)
                estr += '%s\n' % error

        for rule in diffs['changed']:
            rule_found = rulesets.xpath('//threatname[text()="%s"]' % diffs['added'][rule])
            if rule_found == None:
                verified = False
                error = 'changed rule: %s is missing from ruleset %s' % (rule, rcid)
                logging.error(error)
                estr += '%s\n' % error
                continue

        return (
            'Ruleset Diffs Verification PASSED' if verified == True else 'Ruleset Diffs Verification FAILED\n%s' % estr)


class Connect:
    @varImport()
    def __init__(self, **evars):
        import paramiko
        import warnings
        from axsess import Password

        if not 'device' in evars:
            self.__dict__['device'] = 'pan'
        self.__dict__.update(evars)
        warnings.simplefilter('ignore')
        paramiko.util.log_to_file('/var/www/cgi-bin/logs/paramiko.log')
        device = evars['device'] if 'device' in evars else 'pan'
        self.ip = evars['%s_IP' % self.device]
        if self.ip == None and '%s_host' % device in evars:
            self.ip = evars['%s_host' % device]
        elif self.ip == None:
            raise AssertionError, '%s...%s' % (device, str(evars))
        self.connection_established = False
        try:
            device_name = evars['%s_name' % device]
        except KeyError:
            device_name = self.ip
        self.sftp_chan = None
        assert len(self.ip) > 0, 'No IP address for device %s' % device
        P = Password(evars['TestEnv'], evars['ATF_User'])
        self.device, user, pword, cert = P.getCredentials(mgmt=self.ip)
        if self.device != device:
            self.device, user, pword, self.cert_path = P.getCredentials(address=self.ip)
        assert pword != None, 'encrypted password for device %s @ %s is missing from the ATF configuration'
        self.error = ''
        try:
            from paramiko.transport import Transport
            from paramiko.hostkeys import HostKeys

            keys = HostKeys()
            keys.load(os.path.expanduser('~/.ssh/known_hosts'))

            logging.debug('creating transport session for %s' % self.ip)
            T = Transport((self.ip, 22))
            logging.debug('starting transport client for %s' % self.ip)
            T.start_client()
            key = T.get_remote_server_key()
            if device == 'isensor':
                logging.debug('attempting to add new nost keys from %s to local known hosts at %s' % (
                    self.ip, os.path.expanduser('~/.ssh/known_hosts')))
                keys.add(self.ip, key.get_name(), key)
                keys.save(os.path.expanduser('~/.ssh/known_hosts'))
        except Exception as estr:
            logging.error('unable to insert isert host key for %s\n%s' % (self.ip, str(estr)))
            raise AssertionError, 'Trap'

        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            keypath = evars['keypath'] if 'keypath' in evars else None
            if keypath == None:
                logging.debug('attempting connection to %s using password' % self.ip)
                self.cnx.connect(self.ip, username=user, password=pword, look_for_keys=False, allow_agent=False)
                logging.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                self.connection_established = True
            else:
                logging.debug('attempting connection to %s using shared key @%s' % (self.ip, keypath))
                try:
                    key = paramiko.RSAKey.from_private_key_file(keypath)
                    self.cnx.connect(self.ip, username=user, pkey=key)
                    logging.debug(
                        "Connection established %s (%s) for user %s using shared key" % (device, self.ip, user))
                    self.connection_established = True
                except:
                    logging.debug(
                        'failed authentication with shared key...attempting connection to %s using password' % self.ip)
                    self.cnx.connect(self.ip, username=user, password=pword)
                    logging.debug("Connection established %s (%s) for user %s" % (device, self.ip, user))
                    self.connection_established = True
        except Exception as error:
            self.error = "Connection failure to device (%s) at %s, user:%s\n%s" % (
                self.device, self.ip, user, str(error) + ',' + pword)
            logging.error(self.error)
            self.connection_established = False
        if self.connection_established == True:
            self.transport = self.cnx.get_transport()
            try:
                self.sftp_client = paramiko.sftp_client.SFTPClient
            except Exception as error:
                print
                str(error)
                trap
        self.user = user
        self.device = device
        self.BUF_SIZE = 65535
        self.rxc = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')

    def cmd(self, command, **kwords):
        shell = self.cnx.invoke_shell('xterm')
        shell.settimeout(30.0)
        response = ''
        logging.debug("Sending command '%s' to %s (%s)" % (command, self.device, self.ip))
        try:
            outp = shell.recv(self.BUF_SIZE)
            logging.debug('remote shell started:\n%s' % outp)
            shell.send('%s\n' % command)
            outp = shell.recv(self.BUF_SIZE)
        except Exception as estr:
            raise AssertionError, str(estr)
        while True:
            try:
                shell.settimeout(3.0)
                outp = shell.recv(self.BUF_SIZE)
                response += outp
            except Exception as estr:
                break
        logging.debug("Rcvd response '%s' from device %s (%s)" % (response, self.device, self.ip))
        response = self.rxc.sub('', response)
        return (response)

    def reconnect(self):
        self.cnx = paramiko.SSHClient()
        self.cnx.load_system_host_keys()
        self.cnx.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.cnx.connect(self.ip, username=self.user, password=self.password)
        except:
            self.error = "Reconnection Failure to %s at address: %s, user:%s" % (self.device, self.ip, self.user)
            logging.error(self.error)
            raise AssertionError, self.error
