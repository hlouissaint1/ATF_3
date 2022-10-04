import os
import sys
from robot.api import logger as logging
from robot.api.deco import keyword
from time import time, sleep, strftime, gmtime
from atfvars import varImport

import logging

LOGPATH = '/var/www/cgi-bin/logs'
MODULE = 'scwxDCIMlib.py'
LOG = 'auto_regression.log'
logging.basicConfig(format='%(asctime)s %(module)s:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)


class LabManager:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        assert self.dcim_IP != None, 'The LabManager IP was not specified or is inactive'
        use_ssl = False
        port = '80'
        self.server = self.dcim_IP
        self.no_release = True
        self.errstr = ''
        if use_ssl not in (True, False, 1, 0):
            use_ssl = False
        self._session_id = None
        self.data = ''
        self.err = None
        self.reserve_id = None
        self.topology = ''
        if not port:
            self.server_port = '443' if use_ssl else '80'
        else:
            port = int(port) & 0xffff
            self.server_port = str(port)
        self.proto = 'https' if use_ssl else 'http'
        self._server = None

    def lmLogin(self, username, password):
        if self.dcim_Name != 'LabManager':
            return ('LabManager is not active in this configuration')
        if self.errstr != '':
            return (self.errstr)
        try:
            (err, data) = self._server.login(username, password)
            if err:
                logging.error("ERROR: Unable to login to Lab Manager (%s,%s)" % (username, password))
                return ('ERROR %s: %s' % (str(err), data))
            else:
                self._session_id = (data,)
                self.no_release = False
                return self._session_id
        except:
            return ('ERROR: No data')

    def rpcCall(m):
        def rpc(self, *args):
            logging.debug('sid,args: %s,%s' % (self._session_id, str(args)))
            args = self._session_id + args
            logging.debug('rpc - args: %s' % (str(args)))
            err, data = getattr(self._server, m.__name__)(*args)
            if err:
                logging.error(str(data))
                self.errstr = "Received ERROR from remote procedure call ({0}) to Lab Manager:\n\t  '{1}'\n".format(
                    m.__name__, str(data))
                self.data = self.errstr + data
            # self.errstr += 'getattr %s (%s)(%s)' % (self._server, m.__name__,str(args))
            else:
                self.data = data
            # self.errstr = 'No Error getattr %s (%s)(%s)' % (self._server, m.__name__,str(args))
            return (self.data)

        return (rpc)

    @rpcCall
    def getServerTime(self):
        logging.info('%s, %s' % (self.data, self.errstr))
        return (self.data)

    @rpcCall
    def scheduleReservation(self, *args):
        logging.info('(%s) - %s, %s' % (str(args), self.data, self.errstr))
        return (self.data)

    @rpcCall
    def cancelReservations(self, id):
        logging.info('(%s) - %s, %s' % (str(args), self.data, self.errstr))
        return (self.data)

    @rpcCall
    def getReservations(self, *args):
        logging.info('(%s) - %s, %s' % (str(args), self.data, self.errstr))
        return (self.data)

    def lmLogout(self):
        try:
            # Only make a logout attempt if we are actually logged in.
            if self._session_id != None:
                (err, data) = self._server.logout(self._session_id)
            else:
                (err, data) = (1, 'not logged in')

        except:
            (err, data) = (1, 'exception caught')
        self._session_id = None
        return (err, data)

    @keyword
    def Release_LabManager_Topology(self, topology=None, **opts):
        if self.dcim_Name != 'LabManager':
            return ('LabManager is not active in this configuration')
        if 'no_release' in opts:
            self.no_release = opts['no_release']
        if self.no_release == True:
            return ('No reserved topology to release')

        if not self.reserve_id:
            return ('ERROR - Attempting to release a Lab Manager topology when no topology has been reserved')
        try:
            self._session_id = self.lmLogin(self.dcim_User, self.dcim_Password)
        except:
            return ('ERROR - Failed to release topology %s: Unable to login to LabManager using %s credentials' % (
                self.topology, self.dcim_User))
        cancel_id = [self.reserve_id, ]
        ack = self.cancelReservations(cancel_id)
        self.lmLogout()
        if ack == False:
            return ('ERROR: failed to release Lab Manager topology "%s": %s' % (self.topology, self.errstr))
        self.reserve_id = None
        return ('Released Lab Manager topology "%s" successfully' % self.topology)

    @keyword
    def Reserve_LabManager_Topology(self, topology, duration='3600'):
        import xmlrpclib

        if self.dcim_Name != 'LabManager':
            return ('LabManager is not active in this configuration')
        if topology.startswith('DirectConnect'):
            estr = 'Direct connections do not requires LabManager reservations'
            logging.info(estr)
            return (estr)
        try:
            server = self.proto + '://' + self.server + ':' + self.server_port + '/scriptserver/'
            self._server = xmlrpclib.ServerProxy(server)
        except:
            self.errstr = "\nERROR:Can't connect to Lab Manager\n\t%s" % self.errstr
        if self.errstr != '':
            return (self.errstr)
        try:
            self._session_id = self.lmLogin(self.dcim_User, self.dcim_Password)
        except Exception as error:
            return (
                    'ERROR - Failed to reserve topology %s: Unable to login to LabManager using %s:%s credentialsi (%s)' % (
                topology, self.dcim_User, self.dcim_Password, str(error)))
        try:
            stime = self.getServerTime()
        except:
            stime = time()
            pass
        topology_path = '//automation/%s' % topology
        result = self.scheduleReservation(topology_path, duration, stime, 'fixed')
        self.topology = topology
        self.reserve_id = result

        self.lmLogout()
        if self.errstr != None:
            if "not available" in self.errstr:
                return (
                        'Failed to reserve topology %s:\n  %s' % (
                    topology, self.errstr.replace('ERROR', 'ERROR:INUSE')))
            elif self.errstr.find("ERROR") >= 0:
                return ('Failed to reserve topology %s:\n  %s' % (topology, self.errstr))

        return ('Reserved topology %s successfully' % topology)

    def Test_BP_Topology(self):
        if self.dcim_Name != 'LabManager':
            return ('LabManager is not active in this configuration')
        assert self.TOPOLOGY != None, 'The Breaking Point topology has not been specified'
        response = self.Reserve_LabManager_Topology(self.TOPOLOGY, '60')
        assert response.find('successfully') > 0, self.errstr
        self.Release_LabManager_Topology()

    def Test_IONE_Topology(self):
        if self.dcim_Name != 'LabManager':
            return ('LabManager is not active in this configuration')
        assert self.ione_Topology != None, 'The IONE topology has not been specified'
        try:
            response = self.Reserve_LabManager_Topology(self.ione_Topology, '60')
            assert response.find('successfully') > 0, self.errstr
        except AssertionError as estr:
            return (str(estr))
        return (None)


class PathFinder:
    @varImport()
    def __init__(self, **evars):
        self.__dict__.update(evars)
        assert self.dcim_IP != None, 'The PathFinder IP was not specified or is inactive'
        self.errstr = ''
        self._session_id = None
        self.data = ''
        self.err = None
        self.topology = ''
        self._server = None
        try:
            self.mcc = self
            self.connect_time = time()
        except:
            raise AssertionError, 'Unable to connect to MCC PathFinder'
        self.port_mapping = None
        self.port_names = {}
        self.mcc = None
        self.channel_1 = self.channel_2 = None
        if 'dcim_Topology' in self.__dict__:
            os.environ['TOPOLOGY'] = self.dcim_Topology

    def mccCall(pf):
        def mcc_session(self, topology=None, **args):
            import mcc

            if topology != None:
                self.__dict__['dcim_Topology'] = topology
                os.environ['TOPOLOGY'] = self.dcim_Topology
            try:
                self.channel_1 = self.dcim_Topology.split(',')[0].split(':')
                self.channel_2 = self.dcim_Topology.split(',')[1].split(':')
            except:
                estr = 'ERROR: malformed topology string found in server configuration'
                logging.error(estr)
                return (estr)
            logging.debug('%s:mcc session started @ %s as user:%s' % (pf.__name__, self.dcim_IP, self.dcim_User))

            try:
                self.mcc = mcc.mcc(ipaddr=self.dcim_IP, username=self.dcim_User, password=self.dcim_Password)
                self.connect_time = time()
            except Exception as estr:
                raise AssertionError, 'ERROR:Unable to connect to MCC PathFinder...%s' % str(estr)
            self.mcc.Lnxnm_strict_on()
            if self.port_mapping == None:
                self.port_mapping = self.mcc.Lnxnm_dump_table_mapping_admin()
            topo_ports = self.channel_1
            topo_ports.extend(self.channel_2)
            self.port_names.update(self.get_port_assigned_names(topo_ports))

            rval = pf(self, topology, **args)

            self.mcc.Lnxnm_sync()
            del self.mcc
            self.mcc = None
            self.port_mapping = None
            self.port_names = {}
            return (rval)

        return (mcc_session)

    def get_port_assigned_names(self, port_name_list):
        port_names = {}
        for port in self.port_mapping:
            port_location = map(lambda s: int(s), port.split('.'))
            pname = self.mcc.Lnxnm_get_nbsCmmcPortName(port_location[0], port_location[1], port_location[2])
            if pname in port_name_list:
                port_names[pname] = port_location
            if len(port_names) == len(port_name_list):  # found them all
                break
        return (port_names)

    def connect_mcc_ports(self, channel):
        chassis1, slot1, port1 = self.port_names[channel[0]]
        chassis2, slot2, port2 = self.port_names[channel[1]]
        try:
            success = self.mcc.Lnxnm_set_map_with(chassis1, slot1, port1, chassis2, slot2, port2)
            assert success == 1, '\nfailed to map %d.%d.%d to %d.%d.%d' % (
                chassis1, slot1, port1, chassis2, slot2, port2)
        except Exception as estr:
            return ('ERROR:\n\t%s' % str(estr))
        return ('\nport %s mapping successful' % (channel))

    def disconnect_mcc_port(self, channel):
        chassis, slot, port = self.port_names[channel]
        try:
            success = self.mcc.Lnxnm_set_map_clear_all(chassis, slot, port)
            assert success == 1, 'failed to clear %d.%d.%d' % (chassis, slot, port)
        except Exception as estr:
            return ('ERROR:\n\t%s' % str(estr))
        return ('\nports "%s" cleared' % (str(channel)))

    @keyword()
    @mccCall
    def Test_PathFinder_Topology(self, topology=None):
        if self.dcim_Name != 'PathFinder':
            return ('PathFinder is not active in this configuration')
        in_use = False
        rstr = ''
        for port in self.port_names:
            location = ''.join('%d.' % d for d in self.port_names[port]).rstrip('.')
            c, s, p = self.port_mapping[location]
            if c + s + p != 0:
                rstr += '\nmcc port %d.%d.%d is in use' % (c, s, p)
                in_use = True
        return (in_use, rstr)

    @keyword()
    @mccCall
    def Reserve_PathFinder_Topology(self, topology=None, **opts):
        if self.dcim_Name != 'PathFinder':
            return ('PathFinder is not active in this configuration')
        if topology.startswith('DirectConnect'):
            estr = 'Direct connections do not requires LabManager reservations'
            logging.info(estr)
            return (estr)
        self.__dict__['dcim_Topology'] = topology
        logging.info('Setting up PathFinder topology: %s' % self.dcim_Topology)
        rstr = ''
        in_use = False
        for port in self.port_names:
            location = ''.join('%d.' % d for d in self.port_names[port]).rstrip('.')
            c, s, p = self.port_mapping[location]
            if c + s + p != 0:
                rstr += '\nmcc port %d.%d.%d is in use' % (c, s, p)
                in_use = True
        ok_to_connect = True  # should be set to False on normal conditions
        if in_use:
            if 'force_connection' in opts and opts['force_connection'] == 'yes':
                rstr += '\n"forced_connection" option is set...dropping previous connections'
                ok_to_connect = True
        else:
            ok_to_connect = True
        if ok_to_connect:
            try:
                self.connect_mcc_ports(self.channel_1)
                rstr += '\nSuccessfully mapped %s to %s' % (self.channel_1[0], self.channel_1[1])
            except Exception as estr:
                rstr += '\nERROR: mapping ports for channel 1 (%s): %s' % (self.channel_1, estr)
                logging.error(rstr)

            try:
                self.connect_mcc_ports(self.channel_2)
                rstr += '\nSuccessfully mapped %s to %s' % (self.channel_2[0], self.channel_2[1])
            except Exception as estr:
                rstr += '\nERROR: mapping ports for channel 2 (%s): %s' % (self.channel_2, estr)
                logging.error(rstr)

            logging.info(rstr)
        else:
            rstr += '\nERROR: specified mcc ports are in use and "force_connection" option is not set'
            logging.error(rstr)
        # the RF script passes in the topology value...This makes it visible to pybot, and other methods within this class
        self.topology = self.__dict__['dcim_Topology'] = os.environ['dcim_Topology'] = topology
        return (rstr)

    @keyword()
    @mccCall
    def Release_PathFinder_Topology(self, topology=None):
        if topology != None:
            self.__dict__['dcim_Topology'] = topology
        if 'dcim_Topology' not in self.__dict__:
            estr = 'ERROR: PathFinder topology is undefined'
            logging.error(estr)
            return (estr)
        if self.channel_1 == None or self.channel_2 == None:
            estr = 'ERROR: channel is undefined...topology may not have been reserved'
            logging.error(estr)
            return (estr)
        rstr = self.disconnect_mcc_port(self.channel_1[0])
        rstr += self.disconnect_mcc_port(self.channel_1[1])
        rstr += self.disconnect_mcc_port(self.channel_2[0])
        rstr += self.disconnect_mcc_port(self.channel_2[1])
        return (rstr)


class Hybrid:
    @varImport()
    def __init__(self, **evars):
        self.hybrid_topology = None
        self.__dict__.update(evars)
        self.path_finder_topo = None
        self.lab_manager_topo = None
        try:
            self.PF = PathFinder(
                self.TestEnv,
                self.ATF_User,
                overrides={
                    'dcim_IP': self.pathfinder_IP,
                    'dcim_Name': 'PathFinder',
                    'dcim_User': self.pathfinder_User,
                    'dcim_Password': self.pathfinder_Password,
                    'dcim_Topology': ''
                }
            )
            self.LM = LabManager(
                self.TestEnv,
                self.ATF_User,
                overrides={
                    'dcim_IP': self.labmanager_IP,
                    'dcim_Name': 'LabManager',
                    'dcim_User': self.labmanager_User,
                    'dcim_Password': self.labmanager_Password,
                    'dcim_Topology': ''
                }
            )
            self.hybrid_config_missing = False
            logging.info('found Hybrid configuration')
        except:
            self.hybrid_config_missing = True
            logging.info('no Hybrid configuration found')

    @keyword()
    def Reserve_Hybrid_Topology(self, topology=None, **opts):
        if self.hybrid_config_missing == True:
            return ('ERROR: keyword suppressed due to missing Hybrid configuration')
        self.hybrid_topology = topology
        topologies = topology.split('+')
        assert len(topologies) == 2, 'ERROR: topologies for both dcim devices must be in configuration'
        self.path_finder_topo = topologies[0]
        self.lab_manager_topo = topologies[1]
        logging.info('reserving PathFinder topology"%s"' % self.path_finder_topo)
        pstr = self.PF.Reserve_PathFinder_Topology(self.path_finder_topo) + '\n'
        logging.debug(pstr)
        if pstr.find('ERROR') >= 0:
            pstr += '\nLabManager topology set-up aborted due to error setting up PathFinder topology'
            return (pstr)
        logging.info('reserving LabManager topology %s' % self.lab_manager_topo)
        lstr = self.LM.Reserve_LabManager_Topology(self.lab_manager_topo)
        logging.debug(lstr)
        if lstr.find('ERROR') >= 0:
            lstr += '\nError reserving LabManager topology: "%s"\n' % self.lab_manager_topo
        return (pstr + lstr)

    @keyword()
    def Release_Hybrid_Topology(self):
        if self.hybrid_config_missing == True:
            return ('ERROR: keyword suppressed due to missing Hybrid configuration')
        logging.info('releasing PathFinder topology "%s"' % self.path_finder_topo)
        pstr = self.PF.Release_PathFinder_Topology(self.path_finder_topo) + '\n'
        logging.debug(pstr)
        if pstr.find('ERROR') < 0:
            pstr += '\nReleased Pathfinder topology "%s" successfully\n' % self.path_finder_topo
        logging.info('releasing LabManager topology %s' % self.lab_manager_topo)
        lstr = self.LM.Release_LabManager_Topology(self.lab_manager_topo) + '\n'
        logging.debug(lstr)
        if lstr.find('ERROR') < 0:
            lstr += '\nReleased LabManager topology "%s" successfully\n' % self.lab_manager_topo

        return (pstr + lstr)
