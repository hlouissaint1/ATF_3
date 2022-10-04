#! /usr/bin/python
import os
from lxml import etree
import axsess
import logging
from copy import deepcopy
import inspect

DOCROOT = '/var/www/html/htdocs'
PARSER = etree.XMLParser(remove_blank_text=True)

LOGPATH = '/var/www/cgi-bin'
LOG = 'ATF.log'
logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)

default = 'Not defined'
IMPORTVARS = {}


def parse_varfile(varfile_path):
    evars = {}
    try:
        with open(varfile_path, 'r') as f:
            varlist = f.readlines()
            line = 0
            for var in varlist:
                if var[0] == '#':
                    continue
                varparsed = var.strip().replace('--variable ', '').split(':', 1)
                if len(varparsed) < 2:
                    continue
                varname, value = varparsed
                evars[varname] = value
        return (evars)
    except Exception as error:
        return ({'debug2': '%s: %s' % (varfile_path, str(error))})


def parse_session_file(user):
    from axsess import Password
    svars = {}
    try:
        sessions = etree.parse('%s/%s/sessions.xml' % (DOCROOT, user))
    except:
        return (svars)
    session = sessions.find('session')
    if session.attrib['running'] != 'yes':
        return (svars)
    env = session.attrib['env']
    P = Password(env, user)
    sensor = session.find('isensor')
    if sensor != None:
        ip = svars['isensor_IP'] = sensor.attrib['address']
        device, svars['isensor_User'], svars['isensor_Password'], certificate = P.getCredentials(address=ip)
    topo = session.find('topo')
    if topo != None:
        svars['dcim_IP'] = topo.attrib['address']
        bps = topo.find('bps')
        if bps != None:
            svars['bps_Topology'] = bps.attrib['topo']
            ip = svars['bps_IP'] = bps.attrib['address']
            device, svars['bps_User'], svars['bps_Password'], certificate = P.getCredentials(address=ip)
            svars['bps_Firstport'] = bps.attrib['Firstport']
            svars['bps_Secondport'] = bps.attrib['Secondport']
            if bps.attrib['bpgroup'] != 'UNASSIGNED':
                svars['bps_Group'] = bps.attrib['bpgroup']
        ione = topo.find('ione')
        if ione != None:
            svars['ione_Topology'] = ione.attrib['topo']
            ip = svars['ione_IP'] = ione.attrib['address']
            device, svars['ione_User'], svars['ione_Password'], certificate = P.getCredentials(address=ip)
            svars['ione_Ports'] = ione.attrib['ports']
    email = session.find('email')
    if email != None:
        svars['email'] = email.text
    return (svars)


# +++++++++++++++++++++++++++++++++++++

class varImport(object):
    # decorator to import test variables
    def __call__(self, pFunction):
        def var_import(self, environment=None, session_user=None, varfile=None, **opts):
            from axsess import Password

            varname = lambda e, a, v=None: '%s_%s' % (e.tag, a.capitalize() if v == None else v)
            if environment == None:
                if 'TestEnv' in os.environ:
                    environment = os.environ['TestEnv']
            assert str(environment).lower() in ['agile', 'pilot', 'production'], 'unknown test environment %s' % str(
                environment)
            self.environment = os.environ['TestEnv'] = environment.lower()
            # determine the user
            if session_user == None:
                if 'ATF_User' in os.environ:
                    session_user = os.environ['ATF_User']
            assert str(session_user) != None, 'user was not specified'
            self.session_user = os.environ['ATF_User'] = session_user
            self.varfile = varfile
            self.evars = {
                'DOCROOT': DOCROOT,
                'Session_User': self.session_user,
                'TestEnv': environment,
                'ATF_User': session_user,
                'TestEnvironment' : environment,
            }
            self.evars.update(opts)
            varfile = self.evars['VarFile'] = str(varfile)
            logging.debug('varfile = "%s"' % varfile)
            while varfile != None:
                self.varfile = varfile
                if os.path.isfile(varfile):
                    varlist = deepcopy(parse_varfile(varfile))
                    self.evars.update(varlist)
                    break
                break
            if varfile == None and 'VarFile' in os.environ:
                varfile = self.evars['VarFile'] = os.environ['VarFile']
            if varfile != None and os.path.isfile(varfile):
                self.varfile = self.evars['VarFile'] = varfile
                varlist = deepcopy(parse_varfile(varfile))
                self.evars.update(varlist)

            P = Password(self.environment, self.session_user)
            try:
                self.evars['ATF_URL'] = P.common_xml.find('atf').find('url').text
            except:
                self.evars['ATF_URL'] = 'URL missing from ATF admin config file'
                logging.debug(self.evars['ATF_URL'])
            server_file = '%s/%s/%s_servers.xml' % (DOCROOT, self.session_user, self.environment)
            logging.debug('server file is %s' % server_file)
            self.evars['server_file'] = server_file
            try:
                valmap = {
                    'address'           : 'IP',
                    'name'              : 'IP',
                    'host'              : 'IP',
                    'id'                : 'ID',
                    'location'          : None,
                    'atf_user'          : None,
                    'label'             : None,
                    'chassis'           : None,

                }
                server_hosts_xml = etree.parse(server_file)
		device = server_hosts_xml.find('device')
		if device != None:
			for att in device.attrib.keys():
				self.evars['device_%s' % att] = device.attrib[att]
                elements = server_hosts_xml.getroot().xpath('//*[@address]')
                for element in elements:
                    if element.tag == 'alias':
                        continue
                    if 'inactive' in element.attrib and element.attrib['inactive'] == 'yes':
                        continue

                    if len(element.attrib) == 0:
                        continue
                    self.evars.update({'%s_%s' % (element.tag, v.capitalize()) : element.attrib[v] for v in element.keys()})
                    try:
                        self.evars['%s_IP' % element.tag] = self.evars.pop('%s_Address' % element.tag)
                    except KeyError:
                        logging.error('missing address attrib for element: %s in server file %s' % (element.tag, server_fil))
                        pass
                    if element.tag == 'dcim':
                        bps_topo = element.find('bps')
                        if bps_topo != None and 'topo' in bps_topo.attrib:
                            self.evars['bps_Topology'] = bps_topo.attrib['topo']

                        ione_topo = element.find('ione')
                        if ione_topo != None and 'topo' in ione_topo.attrib:
                            self.evars['ione_Topology'] = ione_topo.attrib['topo']
                        self.evars['dcim_Name'] = element.attrib['name'] if 'name' in element.attrib else 'UNASSIGNED'

                    address = element.attrib['address']
                    device, username, password, certificate = P.getCredentials(address=address)
                    if device != None:
                        var = '%s_IP' % device
                        if var in self.evars and self.evars[var] != address:
                            continue
                        if username != None:
                            self.evars['%s_User' % device] = username
                        elif certificate != None:
                            self.evars['%s_Certificate' % device] = certificate
                        else:
                            continue
                        pword = '%s_Password' % device
                        if var in self.evars and pword in self.evars:
                            continue
                        self.evars[var] = element.attrib['address']
                        self.evars[pword] = password
                    for att in element.attrib:
                        if att in valmap:
                            if valmap[att] == None:
                                continue
                            alias = valmap[att]
                        else:
                            alias = None
                        if not varname(element, att) in self.evars:
                            self.evars[varname(element, att, alias)] = element.attrib[att]
            except Exception as error:

                raise AssertionError, str(error)

            # the XML server configuration can be overridden by the decorated function if supplied
            if 'overrides' in opts:
                self.evars.update(opts['overrides'])
                with open('inserted_var.txt', 'w') as f:
                    f.write('overrides inserted: %s' % str(opts['overrides']))

            # if a test has been launched via the REST service/launch engine, the isensor and bps configuration may be different
            # in which case the session file will contain the configuration supplied to the REST service
            # and override the configuration found in the server XML file
            self.evars.update(parse_session_file(self.session_user))
            if 'isensor_IP' in self.evars:
                self.evars['TAF_iSensorMgmtIp'] = self.evars['TAF_iSensorDeviceIndentifier'] = self.evars['isensor_IP']
            if 'REPORTFILE' in os.environ:
                self.evars['REPORTFILE'] = os.environ['REPORTFILE']
            if 'LOGFILE' in os.environ:
                self.evars['LOGFILE'] = os.environ['LOGFILE']
            if 'OUTPUTFILE' in os.environ:
                self.evars['OUTPUTFILE'] = os.environ['OUTPUTFILE']
            for var in self.evars:
		if var in os.environ:
			continue
                # logging.debug('VAR %s assigned value: %s' % (var, self.evars[var]))
                if self.evars[var] != None and self.evars[var] != '':
                    # print var,self.evars[var]
                    os.environ[var] = str(self.evars[var])
                else:
                    os.environ[var] = "UNASSIGNED"
            logging.debug('variables defined...')
            pFunction(self, **self.evars)

        return (var_import)

