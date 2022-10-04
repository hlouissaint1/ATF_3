#! /usr/bin/python

from tempfile import mkstemp
from subprocess import call
from optparse import OptionParser
from json import JSONDecoder, JSONEncoder, dumps
from time import strftime
from copy import deepcopy

import sys
CERTPATH='/etc/ssl/certs'
CERTFILENAME = 'device.crt'
global options

def launch_status_request_json():
    E = JSONEncoder()
    json = {
        'testrun-report' : {
            'identification' : options.tag,
            'testrun-id': None,
            'testrun-summary-only' : False
            }
        }
    print 'TID=', options.tid
    if options.tid == '':
        with open('testrun.tid', 'r') as tidf:
            options.tid = tidf.read().rstrip()
    json['testrun-report']['testrun-id'] = options.tid
    json['testrun-report']['testrun-summary-only'] = options.summary

    rval = E.encode(json)
    return(rval)


def launch_request_json():
    E = JSONEncoder()
    json = {
        'testrun' : {
            'environment' : options.env,
            'identification' : options.tag,
            'user' : options.user,
            'target-ruleset' : options.ruleset,
            'test-group' : options.group,
            'test-suites' : [],
            'configuration-profile' : {},
            'abort-test' : False,
            'testrun-id' : ''
            }
        }


    if options.tests == None:
        rval = E.encode(json)
        return(rval)


    for tests in options.tests.split(','):
        suite, test = tests.split(':')
        if suite == '*':
            json['testrun']['test-suites'] = []
            break
        if test == '*':
            json['testrun']['test-suites'].append({'suite' : {'name' : suite, 'tests' : []}})
            continue
        suite_exists = False
        for ste in json['testrun']['test-suites']:
            if ste['suite']['name'] == suite:
                ste['suite']['tests'].append(test)
                suite_exists = True
                break
        if suite_exists == False:
            json['testrun']['test-suites'].append({'suite' : {'name' : suite, 'tests' : [test]}})

    if options.config == None:
        
        json['testrun']['configuration-profile'] = { 'name' : '%s.%s' % (options.user,'last.testrun')}
    else:
        json['testrun']['configuration-profile'] = { 'name' : options.config}
    config = json['testrun']['configuration-profile']
    try:
        with open('%s.cfg' % config['name'], 'r') as cfg:
            config = eval(cfg.read())
    except Exception as error:
        config = {} 
    if not 'bps' in config:
        print config
        config['bps'] = {}
        #trap
    if options.bpIP != None:
            config['bps']['address'] = options.bpIP
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
    config['ione'] = {'address' : options.ioneIP, 'ports' : options.ionePorts}
    if options.ioneTopo != None:
        config['ione']['topology'] = options.ioneTopo
    config['dcim'] = {'address' : options.dcimIP, 'name' : options.dcim}
    if options.ip != None:
        config['isensor'] = {"address" : options.ip}


    config['email'] = options.email
    config['name'] = options.update if options.update != None else options.config
    json['testrun']['configuration-profile'] = deepcopy(config)
    with open('%s.cfg' % config['name'], 'w') as cfg:
        cfg.write(str(json['testrun']['configuration-profile']))

    rval = E.encode(json)
    return(rval)
    

def main(args):
    assert options.launch | options.report == True, 'Either the -r or -s options must be specified'
    D = JSONDecoder()
    if options.launch == True:
        json = launch_request_json()
        try:
            djson = D.decode(json)
            print '\noutgoing JSON is good:'
            print dumps(djson, sort_keys=True, indent=4, separators=(',', ':'))
        except Exception as error:
            print str(error)
            print str(json)
            print 'outgoing JSON is malformed'
            exit(1)
    elif options.report == True:
        json = launch_status_request_json()
        try:
            djson = D.decode(json)
            print '\noutgoing JSON is good:'
            print dumps(djson, sort_keys=True, indent=4, separators=(',', ':'))
        except Exception as error:
            print str(error)
            print str(json)
            print 'outgoing JSON is malformed'



    try:
        url = args[1]
    except IndexError:
        url = 'https://x-atl1ngpcsau02.internal.secureworkslab.net:8443/launch'
    if options.interactive == True:
        ready = raw_input('Ready to Post JSON request to server? <y,N>')
    else:
        ready = 'yes'
    if not ready.lower().startswith('y'):
        print "request aborted"
        exit(1)
    if options.abort == False:
        request_file = 'last_launch.request' if 'testrun' in djson else 'last_status.request'
        with open(request_file, 'w') as resp:
            resp.write(str(djson))

    response_file = 'last_launch.response' if 'testrun' in djson else 'last_status.response'
    with open(response_file, 'w') as outfd:
        errfd, errfn = mkstemp(prefix='response', suffix='.err')
        #rcode = call(['curl -v -X POST -d %s %s ' % (dumps(json), url)], shell=True, stdout=outfd, stderr=errfd)
        certstr = '-E %s --capath %s' % (CERTFILENAME, CERTPATH)
        rcode = call(['curl %s -v -X POST -d %s %s ' % (certstr, dumps(json), url)], shell=True, stdout=outfd, stderr=errfd)
        print 'curl %s -v -X POST -d %s %s ' % (certstr, dumps(json), url)
        if rcode != 0:
            print 'cURL return error Code %d' % rcode
            exit(1)
    outfd.close()
    #errfd.close()
    with open(response_file, 'r') as response:
        rjson = response.read()
        try:
            djson = D.decode(rjson)
            print 'Response is well-formed JSON:'
        except:
            print 'Received malformed JSON from server'
            print str(rjson)
            exit(1)
        print dumps(eval(rjson), sort_keys=True, indent=4, separators=(',', ':'))

    response_type = djson.keys()[0]
    if options.report == False: 
        try:
            tid = djson[djson.keys()[0]]['testrun-id']
            with open('testrun.tid\n', 'r') as tidf:
                tids = tidf.readlines()
            with open('testrun.tid\n', 'w') as tidf:
                tids.insert(0,'%s\n' % tid)
                tidf.writelines(tid)
        except Exception as error:
            print str(error)

    
   


if __name__ == '__main__':

    optparser = OptionParser(usage="Usage %s <options> <url> [<request>]" % sys.argv[0])
    optparser.add_option('-r','--run', action='store_true', dest='launch', default=False, help='Request server to launch a test run') 
    optparser.add_option('-s','--status', action='store_true', dest='report', default=False, help='Request server to report the status of a testrun') 
    #optparser.add_option('-a','--abort-testrun', action='store_true', dest='abort', default=False, help='Request server to abort a test run') 
    optparser.add_option('-u','--user', action='store', dest='user', default='admin', help='Request action is for user: <USER>')
    optparser.add_option('-I','--iSensor', action='store', dest='ip', default='172.16.240.244', help='IP address of the iSensor under test')
    #optparser.add_option('-v','--ruleset-version', action='store', dest='ruleset', default='', help='Version of the target ruleset (e.g. 2.9.7.5.501)')
    optparser.add_option('-b','--breaking-point-ip', action='store', dest='bpIP', default=None, help='Use Breaking Point located @ ip-address: <bpIP>')
    optparser.add_option('-T','--bp-topo', action='store', dest='bpTopo', default=None, help='Set up  Breaking Point topology: <BPTOPO>')
    optparser.add_option('-p','--bp-ports', action='store', dest='bpPorts', default=None,
            help='Use Breaking Point port-pair <BPPORTS>, format is: "slot:port1,slot:port2" (e.g. "1,6:1,7"). Ports begin at zero')
    optparser.add_option('-L','--testlist', action='store', dest='tests', default=None,
            help='CSV list of tests making up the test run, e.g. "suite1:test1,suite1:test2,suite2:test1,suite3:*..."')
    optparser.add_option('-G','--bp-group', action='store', dest='bpGroup', default='12', help="Specifies the Breaking Point group")
    optparser.add_option('-g','--testgroup', action='store', dest='group', default='Ruleset Performance', help='The list of tests belong to test group <GROUP>')
    optparser.add_option('-e','--env', action='store', dest='env', default='Pilot', help='Test environment. e.g., (Pilot | Agile | Production). default=Pilot')
    optparser.add_option('-E','--email', action='store', dest='email', default='User', help='Email test status/results to <EMAIL> distribution (default is to email to user)')
    optparser.add_option('-c','--config', action='store', dest='config', default=None, help='Test environment configuration name')
    optparser.add_option('-C','--new-config', action='store', dest='update', default=None, help='New test environment configuration name.')
    optparser.add_option('-k','--ione', action='store', dest='ioneIP', default='172.16.136.11', help='IOne IP address')
    optparser.add_option('-M','--ione-topo', action='store', dest='ioneTopo', default=None, help='IOne topology')
    optparser.add_option('-m','--ione-ports', action='store', dest='ionePorts', default='p1p2:p1p1', help='IOne port pair')
    optparser.add_option('-D','--dcim', action='store', dest='dcim', default='LabManager', help='The DCIM. (default=LabManager)')
    optparser.add_option('-d','--dcim-address', action='store', dest='dcimIP', default='172.16.250.200', help='The DCIM IP address. (default="172.16.250.200")')
    optparser.add_option('--uin', action='store', dest='uin', default=None, help='Target iSensor has UIN:<UIN>')
    optparser.add_option('--tid', action='store', dest='tid', default='', help='Use testrun identifier <TID> supplied by server')
    optparser.add_option('--tag', action='store', dest='tag', default='', help='Use testrun tag <tag> supplied by client')
    optparser.add_option('--summary-only', action='store_true', dest='summary', default=False, help='Inform service to return summary only when using the "-s" option.') 
    optparser.add_option('--pcsms', action='store', dest='pcsms', default=None, help='Send command to CTP back-end PCSMS service')
    optparser.add_option('--output', action='store', dest='outfile', default=None, help='Save json string to <outfile>')
    optparser.add_option('--input', action='store', dest='infile', default=None, help='Use a saved json string from <infile>')
    optparser.add_option('-i','--non-interactive', action='store_false', dest='interactive', default=True, help='Suppress interactive mode')




   
    options, cliargs = optparser.parse_args()
    
    try:
        main(cliargs)
        exit(0)
    except AssertionError as estr:
        print '\nERROR: %s\n' % str(estr)
        call(['%s -h' % sys.argv[0]], shell=True)
        exit(1)


    exit(1)

