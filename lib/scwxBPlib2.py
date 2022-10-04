__author__ = 'gowen'
import os
import sys
from robot.api.deco import keyword
import subprocess
from lxml import etree
from copy import deepcopy
import axsess
import warnings
import logging
from tempfile import mkstemp, NamedTemporaryFile
from atfvars import varImport
from time import time

LOGPATH = '/var/www/cgi-bin/logs'
MODULE = 'scwxBPlib2'
LOG = 'auto_regression.log'
LOCATION = lambda L: '@location="%s" or @location="%s" or @location="ANY"' % (L.capitalize(), L.lower())

if not os.path.exists('%s/%s' % (LOGPATH, LOG)):
    with open('%s/%s' % (LOGPATH, LOG), 'w') as create:
        create.write('created new log')

logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)


def parseTable(rstr):
    logging.debug('scwxBPlib:parseTable - %s' % rstr)
    X = etree.fromstring(rstr)
    outstr = ''
    rows = X.findall('row')
    if len(rows) == 0:
        return (False, '***** No Data Available *****\n')
    txvalue = 0.0
    rxvalue = 0.0
    for row in X.findall('row'):
        pcnt = 0.0
        datastr = ''
        for cell in row.findall('cell'):
            content = cell.find('content')
            if content != None:
                contentvalue = content.text
                if cell.attrib['colId'] == '0':
                    subscript = row.find('subscript[@colId="0"]')
                    if subscript != None:
                        contentvalue += ' %s' % subscript.attrib['subscript']
            else:
                content = cell.find('fcontent')
                if content == None:
                    if cell.attrib.has_key('ncontent'):
                        contentvalue = cell.attrib['ncontent']
                    else:
                        continue
                else:
                    valuenode = content.find('externalForm')
                    if valuenode != None:
                        contentvalue = valuenode.text
                    else:
                        contentvalue = content.attrib['n']

            datastr += '%s,' % contentvalue
            if cell.attrib['colId'] == '1':
                if datastr.find('Transmit') >= 0:
                    txvalue = float(datastr.split(',')[1].lstrip('~'))
                elif datastr.find('Receive') >= 0:
                    rxvalue = float(datastr.split(',')[1].lstrip('~'))
                    if txvalue != 0.0:
                        pcnt = (100.0 * rxvalue) / txvalue
                        datastr = datastr.rstrip(',') + ",%4.3f%c," % (pcnt, r'%')
                        txvalue = 0.0
                        rxvalue = 0.0
                outstr += '%s\n' % datastr.rstrip(',')

    logging.debug('scwxBPlib:parseTable - %s' % outstr)
    return (False, outstr)


class bpsCall(object):
    def __call__(self, p):
        """
            The wrapper opens the input TCL file and inserts the BPS commands to connected to the chassis.
            'cargs' are the arguments passed to the decorated method 'p' which are derived from the command line arguments
            The decorated method 'p' is called which inserts BPS commands specific to that method then, upon return from 'p',
            passes the response from the BPS onto the callback method that is specified in the decorator.
        """

        def wrapper(self, **args):
            """
            retrieves creates the TCL scripts then sends them to the Breaking Point
            """
            bpsh_version_map = {
                'default': '/var/www/cgi-bin/lib/bpsh',
                '172.16.144.20': '/var/www/cgi-bin/lib/bpsh',
                '172.16.192.100': '/var/www/cgi-bin/lib/bpsh-linux-x86',
                #'172.16.192.100': '/var/www/cgi-bin/lib/bpsh324725',

            }
            callback = None
            logging.debug('calling function is %s' % p.__name__)
            assert self.bps_IP != None
            global BPSHPATH
            if self.bps_IP in bpsh_version_map:
                BPSHPATH = bpsh_version_map[self.bps_IP]
            else:
                BPSHPATH = bpsh_version_map['default']
            rawfile = NamedTemporaryFile('wt', delete=False)
            self.error = NamedTemporaryFile('wt', delete=False)
            logging.debug("scwxBPlib: bpsCall:%s" % p.func_name)
            error = False

            with open(self.infile, "w") as F:
                F.write("set cnx [bps::connect %s %s %s]\n" % (self.bps_IP, self.bps_User, self.bps_Password))
                args.update(infd=F)
                self.ifile = F
                callback = p(self)
                F.write("exit\n")
            with open(self.infile, "r") as F:
                logging.debug("scwxBPlib: Sending BPS batch TCL commands (using(%s) : \n----\n%s-----" % (
                    BPSHPATH,
                    F.read().replace(self.bps_Password, '*****'),
                ))

            bpshcmd = ["%s %s" % (BPSHPATH, self.infile)]
            self.perror, errname = mkstemp(prefix='atf.bps', suffix='err')
            self.pout, outname = mkstemp(prefix='atf.bps', suffix='err')
            rval = subprocess.call(bpshcmd, bufsize=-1, shell=True, executable='/bin/bash', stderr=self.perror,
                                   stdout=self.pout)

            if rval == 0:
                with open(outname, 'r') as f:
                    self.response = outstr = f.read()
                    f.seek(0)
                    self.report_xml += f.read()
                    # print '\noutstr=%s\n' % outstr
                    logging.debug("scwxBPlib: bpsh commands executed successfully")
            else:
                with open(errname, 'r') as f:
                    error = True
                    self.response = errstr = f.readline()
                    f.seek(0)
                    self.report_xml += f.read()
                    errbody = f.read()
                logging.debug('%s%s' % (errstr, errbody))
                logging.error('%s%s' % (errstr, errbody))
                os.unlink(errname)
                os.unlink(outname)
                raise AssertionError, 'Breaking Point reported an ERROR (%d): \n %s' % (rval, errstr)
            os.unlink(errname)
            os.unlink(outname)
            with open(rawfile.name, 'r') as f:
                response = f.read()
            logging.debug('...response was: %s' % response[:300])
            if len(response) > 300:
                remainder = len(response) - 300
                if remainder - 100 > 0:
                    logging.debug('...%s' % response[len(response) - 100:])
                else:
                    logging.debug('...%s' % response[len(response) - (remainder / 2):])
            if (callback != None):
                logging.debug('Executing callback function %s' % str(callback))
                resp = callback()
                # self.response = resp
                if resp != None:
                    if isinstance(resp, tuple) == True and resp[0] == False:
                        response = resp[1]
                    else:
                        return

            if error == True:
                return  # exit(1)
            if self.debug_flag == 0:
                try:
                    os.unlink(self.infile)
                except OSError:
                    pass
            elif self.debug_flag > 1:
                logging.debug("scwxBPlib: Breaking Point response\n%s" % response)

        return (wrapper)


class BreakingPoint:
    @varImport()
    def __init__(self, **evars):
        self.tid = ''
        self.xml = ''
        self.__dict__.update(evars)
        self.bpshpath = '/var/www/html/htdocs/lib/bpsh'  # default
        self.bpsPorts = '%s:%s' % (self.bps_Firstport, self.bps_Secondport)
        self.bpsAction = None
        self.bpsReport = None
        self.bpsTest = None
        self.debug_flag = None
        self.sessionID = 'bp.%8.3f' % time()
        self.report_xml = ''
        self.error_string = None
        self.response = ''
        self.debug_flag = 0
        self.infile_fd, self.infile = mkstemp(prefix='bps', suffix='.tcl')
        self.outfile_fd, self.outfile = mkstemp(prefix='bps', suffix='.out')
        self.ifile = None
        self.bpGroup = self.bps_Group
        self.__dict__['TestID'] = '%d.%s' % (int(time()), self.ATF_User)


    @bpsCall()
    def testBPConnections(self):
        logging.debug('bps_Firstport (%s), bps_Secondport (%s), bps_Group (%s)' % (
        self.bps_Firstport,
        self.bps_Secondport,
        self.bps_Group
        ))
        try:
            chassisA = self.bps_Firstport.split(',')[0]
            chassisB = self.bps_Secondport.split(',')[0]
            bpsportA = self.bps_Firstport.split(',')[1]
            bpsportB = self.bps_Secondport.split(',')[1]
        except IndexError:
            raise AssertionError, 'Unable to retrieve BPS port values (%s)' % str(portvals)
        logging.info("scwxBPlib: reserving slot %s, port %s group %s \n" % (chassisA, bpsportA, self.bps_Group))
        self.ifile.write("set chs [$cnx getChassis]\n")
        self.ifile.write("$chs reservePort %s %s -group %s\n" % (chassisA, bpsportA, self.bps_Group))
        self.ifile.write("$chs reservePort %s %s -group %s\n" % (chassisB, bpsportB, self.bps_Group))
        self.ifile.write("$chs unreservePort %s %s\n" % (chassisA, bpsportA))
        self.ifile.write("$chs unreservePort %s %s\n" % (chassisB, bpsportB))
        return (self.logResponse)

    def logResponse(self, **kargs):
        logging.info(self.response)
        return (False, self.response)

    def parseTestResults(self):
        logging.debug("scwxBPlib: parseTestResults toc size is %d" % len(self.response))
        X = etree.fromstring(self.response)
        tid = X.getroottree().getroot().values()[0]
        self.tid = tid
        try:
            runID = tid.split('@')[3]
        except IndexError:
            runID = tid
        result = X.getroottree().getroot().values()[1]
        outstr = "bpsTest=%s\ntestResult=%s\n\n" % (runID, result)
        for tab in X.xpath('//table'):
            tabledata = ''
            error = False
            tabstr = tab.attrib['name']
            try:
                tablename = tabstr.split(':')[1].lstrip(' ')
            except IndexError:
                tablename = tabstr.split(':')[0].lstrip(' ')
            outstr += "\n        %s\n" % tablename
            hdrstr = ''
            for header in tab.xpath('header'):
                hdrstr += '%s,' % header.attrib['name']
                if header.attrib.has_key('units'):
                    hdrstr = '%s (%s)' % (hdrstr.rstrip(','), header.attrib['units'])
            outstr += '%s\n' % hdrstr.rstrip(',')
            error, tabledata = parseTable(etree.tostring(tab))
            if error == True:
                outstr += '\nNo data available\n\n'
                continue
            outstr += tabledata
        if error == True:
            estr = 'Parsing Error while processing BP test results\n' + rstr
        else:
            estr = ''
        logging.debug('scwxBPlib:parseTestResults - %s' % outstr)
        self.response = outstr
        # return(self.logResponse)
        return (False, outstr)


    @bpsCall()
    def getSections(self):
        # logging.debug("scwxBPlib: getSections %d, %s" % (len(self.response), self.response))
        logging.debug("scwxBPlib: getSections toc size is %d" % len(self.response))
        sections = [
            "Frame Data Rate Summary",
            "Frame Latency Summary",
            #"Component Flow Counts",
            #"Ethernet Summary",
            #"Application Summary"
        ]
        X = etree.fromstring(self.response)
        logging.debug("scwxBPlib: getSections successfully parsed TOC")
        tid = X.getroottree().getroot().values()[0]
        result = X.getroottree().getroot().values()[1]
        section_list = []
        for section in sections:
            xpath = '//urlCell[@anchorText="%s"]' % section
            snode = X.xpath(xpath)
            if len(snode) != 0:
                section_list.append(section)

        bpsreq = 'puts "<bpsresults tid=\'%s\' result=\'%s\'>"\n' % (tid, result)
        self.ifile.write(bpsreq)
        for section in section_list:
            self.ifile.write('puts {<datapoint name="Frame Data Rate Summary">}\n')
            bpsreq = 'set rdata [$cnx getReportSectionXML {%s} -title {%s}]\n' % (tid, section)
            self.ifile.write(bpsreq)
            self.ifile.write("puts $rdata\n")
            self.ifile.write('puts {</datapoint>}\n')
        self.ifile.write("puts {</bpsresults>}\n")
        logging.debug("scwxBPlib: getSections successfully processed TOC")
        #return(self.logResponse)
        return (self.parseTestResults)


    @bpsCall()
    def getTestResults(self):
        logging.debug("scwxBPlib: getTOC response length = %d" % (len(self.response)))
        result = self.response.split(',')
        logging.debug("scwxBPlib: getTOC result, %s" % str(result))
        try:
            tid = result[1]
            bpresult = result[0]
        except IndexError:
            tid = result[0]
            bpresult = 'NA'
        except:
            return (False, 'Unrecoverable error due to BP response\n')
        self.tid = tid
        bpcmd = "set toc [$cnx getReportSectionXML {%s} -title {Table of Contents}]\n" % tid.rstrip('\n')
        self.ifile.write(bpcmd)
        bpcmd = 'puts {<toc tid="%s" result="%s">}\n' % (tid.rstrip('\n'), bpresult)
        self.ifile.write(bpcmd)
        self.ifile.write('puts $toc\n')
        self.ifile.write('puts {</toc>}\n')
        return (self.getSections)


    @bpsCall()
    def runTest(self):
        from time import strftime, gmtime

        d = gmtime()
        datestr = strftime("%Y%02m%02dT%02H%02M%02S", d)
        testf = os.path.basename(self.bpsTest)
        tmpTestName = "%s_%s_%s" % (datestr, self.TestID, testf)
        bpstest = os.path.basename(self.bpsTest)
        try:
            k = bpstest.index('.bpt')
            bpstest = bpstest[:k]
        except ValueError:
            pass
        portvals = self.bpsPorts.split(':')
        try:
            chassisA = portvals[0].split(',')[0]
            chassisB = portvals[1].split(',')[0]
            bpsportA = portvals[0].split(',')[1]
            bpsportB = portvals[1].split(',')[1]
        except IndexError:
            raise AssertionError, 'Unable to retrieve BPS port values (%s)' % str(portvals)
        logging.info("scwxBPlib: reserving slot %s, port %s group %s \n" % (chassisA, bpsportA, self.bpGroup))
        logging.info("scwxBPlib: reserving slot %s, port %s group %s \n" % (chassisB, bpsportB, self.bpGroup))
        logging.info("scwxBPlib: running test ID %s (%s)\n" % (tmpTestName, bpstest))
        self.ifile.write("set chs [$cnx getChassis]\n")
        self.ifile.write("$chs reservePort %s %s -group %s\n" % (chassisA, bpsportA, self.bpGroup))
        self.ifile.write("$chs reservePort %s %s -group %s\n" % (chassisB, bpsportB, self.bpGroup))
        self.ifile.write("set test [$cnx createTest -name {%s} -template {%s}]\n" % (tmpTestName, bpstest))
        self.ifile.write("set result [$test run -group %s]\n" % self.bpGroup)
        self.ifile.write("set tid [$test resultId]\n")

        self.ifile.write("puts $result,$tid\n")
        self.ifile.write("$chs unreservePort %s %s\n" % (chassisA, bpsportA))
        self.ifile.write("$chs unreservePort %s %s\n" % (chassisB, bpsportB))
        logging.info('length of response is is: %d' % len(self.response))
        # self.getTestResults()
        return (self.getTestResults)
        #return(self.logResponse)

    ############################################################# Robot Framework keyword

    @keyword
    def Get_Breaking_Point_Group(self):
        return (self.bpGroup)

    @keyword
    def Get_BPS_Port_1(self):
        return (self.bpsPorts.split(':')[0])

    @keyword
    def Get_BPS_Port_2(self):
        return (self.bpsPorts.split(':')[1])

    @keyword
    def Run_Breaking_Point_Traffic(self, bpTest, **kwargs):
	"""
	with open('fakebps.txt','r') as fake:
		self.response = 'Passed,%s' % fake.read()
	return (self.response)
	"""
        if 'append_id' in kwargs:
            append_id = kwargs['append_id']
        else:
            append_id = ''
        self.__dict__['TestID'] = '%s%d.%s' % (append_id, int(time()), self.ATF_User)
        self.bpsTest = bpTest
        rval = self.runTest()
        return (self.response)



