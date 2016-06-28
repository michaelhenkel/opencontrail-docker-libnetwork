#!/usr/bin/python
import socket
import SocketServer
import sys
import os
import json
import netaddr
import argparse
import yaml
import uuid
import logging
from netaddr import *
from pprint import pprint
from vnc_api import vnc_api
from contrail_vrouter_api.vrouter_api import ContrailVRouterApi
from pyroute2 import IPDB
from uhttplib import UnixHTTPConnection
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer

'''
Class OpenContrail is a superclass providing 
the connection to the OpenContrail Conig API
Input:
  username
  password
  tenant_name
  api_server_host
  api_server_port
Output:
  vnc_client object
  tenant object
'''
class OpenContrail(object):
    def __init__(self):
        self.vnc_client = self.vnc_connect()
        self.tenant = self.vnc_client.project_read(
                fq_name = ['default-domain', tenant])

    def vnc_connect(self):
        vnc_client = vnc_api.VncApi(
            username = admin_user,
            password = admin_password,
            tenant_name = tenant,
            api_server_host=api_server,
            api_server_port=api_port,
            auth_host=keystone_server)
        return vnc_client

'''
Class OpenContrailVN creates and deletes
virtual networks
Input:
  virtual network name
'''
class OpenContrailVN(OpenContrail):
    def __init__(self, vnName):
        super(OpenContrailVN,self).__init__()
        self.vnName = vnName
        self.obj = vnc_api.VirtualNetwork(name = vnName,
                    parent_obj = self.tenant)

    def VNlist(self):
        list = self.vnc_client.virtual_networks_list()['virtual-networks']
        return list

    def VNget(self):
        for item in self.VNlist():
            if (item['fq_name'][1] == self.tenant.name) and \
                    (item['fq_name'][2] == self.vnName):
                return self.vnc_client.virtual_network_read(id = item['uuid'])

    def create(self, v4subnet, v4gateway, v6subnet=None, v6gateway=None, rtList=None):
        try:
            ipam_obj = self.vnc_client.network_ipam_read(fq_name = ['default-domain',
                                                  'default-project', 'default-network-ipam'])
        except Exception as e:
            logging.debug('ERROR: %s' %(str(e)))
            return
        cidr = v4subnet.split('/')
        subnet = vnc_api.SubnetType(ip_prefix = cidr[0],
                ip_prefix_len = int(cidr[1]))

        v4DnsServer = IPNetwork(v4subnet)[-2]

        if v4gateway:
            ipam_subnet = vnc_api.IpamSubnetType(subnet = subnet,
                default_gateway = v4gateway, enable_dhcp = False)
        else:
            ipam_subnet = vnc_api.IpamSubnetType(subnet = subnet, 
                                        dns_server_address = v4DnsServer, enable_dhcp = False)

        if v6subnet:
            v6DnsServer = IPNetwork(v6subnet)[-2]
            v6cidr = v6subnet.split('/')
            v6subnet = vnc_api.SubnetType(ip_prefix = v6cidr[0],
                 ip_prefix_len = int(v6cidr[1]))
            if v6gateway:
                v6gateway = v6gateway.split('/')[0]
                ipam_v6subnet = vnc_api.IpamSubnetType(subnet = v6subnet,
                    default_gateway = v6gateway)
            else:
                ipam_v6subnet = vnc_api.IpamSubnetType(subnet = v6subnet, 
                                dns_server_address = v6DnsServer)
            self.obj.add_network_ipam(ref_obj = ipam_obj,
                   ref_data = vnc_api.VnSubnetsType([ipam_subnet,ipam_v6subnet]))
        else:
            self.obj.add_network_ipam(ref_obj = ipam_obj,
                 ref_data = vnc_api.VnSubnetsType([ipam_subnet]))

        if rtList:
            rtObj = vnc_api.RouteTargetList()
            self.obj.set_route_target_list(rtObj)
            for rt in rtList:
                rtObj.add_route_target('target:%s' %(rt))
        try:
            self.vnc_client.virtual_network_create(self.obj)
        except Exception as e:
            logging.debug('ERROR: %s' %(str(e)))

        '''
        if v6subnet:
            v6cidr = v6subnet.split('/')
            v6subnet = vnc_api.SubnetType(ip_prefix = v6cidr[0],
                 ip_prefix_len = int(v6cidr[1]))
            if v6gateway:
                v6gateway = v6gateway.split('/')[0]
                ipam_v6subnet = vnc_api.IpamSubnetType(subnet = v6subnet,
                    default_gateway = v6gateway)
            else:
                ipam_v6subnet = vnc_api.IpamSubnetType(subnet = v6subnet)
            self.obj.add_network_ipam(ref_obj = ipam_obj,
                   ref_data = vnc_api.VnSubnetsType([ipam_v6subnet]))
            self.vnc_client.virtual_network_update(self.obj)
        '''

    def getGateway(self, vnName):
        vnList = self.vnc_client.virtual_networks_list()['virtual-networks']
        for item in vnList:
            if (item['fq_name'][1] == 'admin') and \
                    (item['fq_name'][2] == vnName):
                vnUUID = self.vnc_client.virtual_network_read(id = item['uuid'])
        ipam_list = vnUUID.get_network_ipam_refs()
        for item in ipam_list:
            subnet_list = item['attr'].get_ipam_subnets()
            for subnet in subnet_list:
                self.gateway = subnet.get_default_gateway()
        return self.gateway

    def delete(self):
        vnObj = self.VNget()
        try:
            logging.debug('delete %s ' % vnObj.uuid)
            self.vnc_client.virtual_network_delete(id = vnObj.uuid)
        except Exception as e:
            logging.debug('ERROR: %s' %(str(e)))


class OpenContrailEndpoint(OpenContrail):
    def __init__(self, endpointID):
        super(OpenContrailEndpoint,self).__init__()
        self._vrouter_client = ContrailVRouterApi(doconnect=True)
        self.epName = endpointID[:8]
        ep = endpointID
        self.epUuid = uuid.UUID("{" + ep[0:8] + "-" + ep[8:12] + "-" + ep[12:16] + "-" + ep[16:20] + "-" + ep[20:32] + "}")

    def getMac(self):
        interfaceName = 'veth' + self.epName
        vm_interface = self.vnc_client.virtual_machine_interface_read(fq_name=['default-domain',self.tenant.name, interfaceName])
        mac = vm_interface.virtual_machine_interface_mac_addresses.mac_address[0]
        return mac

    def delete(self):
        try:
            ipInstance = self.vnc_client.instance_ip_read(fq_name = [self.epName])
        except Exception as e:
            logging.debug("cannot get ip instance %s" %(str(e)))
        try:
            vmInterfaceList = ipInstance.get_virtual_machine_interface_refs()
        except Exception as e:
            logging.debug("cannot get vm Interface list %s" %(str(e)))


        if vmInterfaceList:
            for vmInterface in vmInterfaceList:
                vmInterfaceObj = self.vnc_client.virtual_machine_interface_read(id = vmInterface['uuid'])
                try:
                    ipList = vmInterfaceObj.get_instance_ip_back_refs()
                except Exception as e:
                    logging.debug("cannot get ip list %s" %(str(e)))

                try:
                    vmList = vmInterfaceObj.get_virtual_machine_refs()
                except Exception as e:
                    logging.debug("cannot get vm list %s" %(str(e)))

                if ipList:
                    for ip in ipList:
                        try:
                            self.vnc_client.instance_ip_delete(id = ip['uuid'])
                        except Exception as e:
                            logging.debug("cannot delete instance ip %s" %(str(e)))
                try:
                    self.vnc_client.virtual_machine_interface_delete(id = vmInterface['uuid'])
                    ContrailVRouterApi().delete_port(vmInterface['uuid'])
                except Exception as e:
                    logging.debug("cannot delete virtual machine interface %s" %(str(e)))
                logging.debug("vmList:")
                if vmList:
                    logging.debug("%s"%vmList)
                    for vm in vmList:
                        try:
                            self.vnc_client.virtual_machine_delete(id = vm['uuid'])
                        except Exception as e:
                            logging.debug("cannot delete virtual machine %s" %(str(e)))

    def join(self, networkId, sandboxKey):
	ipInstance = self.vnc_client.instance_ip_read(fq_name = [self.epName])
        vn = OpenContrailVN(networkId).VNget()
	interfaceName = 'veth' + self.epName
        try:
            vmInstance = self.vnc_client.virtual_machine_read(fq_name = [sandboxKey])
        except:
            vmInstance = vnc_api.VirtualMachine(name = sandboxKey)
            self.vnc_client.virtual_machine_create(vmInstance)
        vmInterface = vnc_api.VirtualMachineInterface(name = interfaceName, parent_obj = self.tenant)
	vmInterface.set_virtual_machine(vmInstance)
	vmInterface.set_virtual_network(vn)
        self.vnc_client.virtual_machine_interface_create(vmInterface)
        vmInterface = self.vnc_client.virtual_machine_interface_read(id = vmInterface.uuid)
        ipInstance.set_virtual_machine_interface(vmInterface)
	self.vnc_client.instance_ip_update(ipInstance)
        mac = vmInterface.virtual_machine_interface_mac_addresses.mac_address[0]
        vrouterInterface = interfaceName + 'p0'
        return {'mac':mac,'vmInstanceUuid':vmInstance.uuid,'vmInterfaceUuid':vmInterface.uuid,'vrouterInterface':vrouterInterface,'vmInstanceName':vmInstance.name,'vmProjectId':self.tenant.uuid}

    def vrouterRegister(self, result):
        ContrailVRouterApi().add_port(result['vmInstanceUuid'], result['vmInterfaceUuid'], result['vrouterInterface'], result['mac'], display_name=result['vmInstanceName'],
                 vm_project_id=result['vmProjectId'], port_type='NovaVMPort')

    def create(self, networkId, ipAddress, ipv6Address = None):
        vn = OpenContrailVN(networkId).VNget()
        ip = vnc_api.InstanceIp(name = self.epName, instance_ip_address = ipAddress.split('/')[0])
        ip.set_virtual_network(vn)
        self.vnc_client.instance_ip_create(ip)
        #mac = vm_interface.virtual_machine_interface_mac_addresses.mac_address[0]

class HttpResponse(object):
     def __init__(self, code, contentType, body):

         self.code = "HTTP/1.0 %s OK" % code
         if contentType == 'json':
             self.contentType = 'Content-Type: application/json'
             self.body = json.dumps(body)
         self.response = self.code + '\n'
         self.response += self.contentType + '\n\n'
         self.response += self.body + '\n'
         logging.debug(self.response)

class RequestResponse(object):
    def __init__(self):
        self.scope = ''

    def execRequest(self, action, data):

        if action == 'NetworkDriver.DiscoverNew':
            return HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.DiscoverDelete':
            return HttpResponse(200,'json',{ }).response
        
        if action == 'Plugin.Activate':
            return HttpResponse(200,'json',{ 'Implements': ['NetworkDriver','IPAM'] }).response

        if action == 'NetworkDriver.GetCapabilities':
            return HttpResponse(200,'json',{ 'Scope':scope}).response

        if action == 'IPAM.GetDefaultAddressSpaces':
            requestPool = {}
            return HttpResponse(200,'json',requestPool).response

        if action == 'NetworkDriver.CreateNetwork':
            networkId = data['NetworkID'][:8]
            pool = data['IPv4Data'][0]['Pool']
            gateway = data['IPv4Data'][0]['Gateway'].split('/')[0]
            if len(data['IPv6Data']) > 0:
                v6pool = data['IPv6Data'][0]['Pool']
                v6gateway = data['IPv6Data'][0]['Gateway']
            if 'rt' in data['Options']['com.docker.network.generic']:
                rtList = data['Options']['com.docker.network.generic']['rt'].split(',')
                if len(data['IPv6Data']) > 0:
                    openContrailVN = OpenContrailVN(networkId).create(pool, gateway, v6subnet=v6pool, v6gateway = v6gateway, rtList = rtList)
                else:
                    openContrailVN = OpenContrailVN(networkId).create(pool, gateway, rtList = rtList)
            else:
                if len(data['IPv6Data']) > 0:
                    openContrailVN = OpenContrailVN(networkId).create(pool, gateway, v6subnet=v6pool, v6gateway = v6gateway)
                else:
                    openContrailVN = OpenContrailVN(networkId).create(pool, gateway)
            networkInfo = {}
            networkInfo['NetworkID'] = data['NetworkID']
            return HttpResponse(200,'json',networkInfo).response

        if action == 'NetworkDriver.DeleteNetwork':
            networkId = data['NetworkID'][:8]
            openContrailVN = OpenContrailVN(networkId).delete()
            return HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.CreateEndpoint':
            networkId = data['NetworkID'][:8]
            endpointId = data['EndpointID']
            ipAddress = data['Interface']['Address']
            if data['Interface']['AddressIPv6']:
                ipv6Address = data['Interface']['AddressIPv6']
                OpenContrailEndpoint(endpointId).create(networkId, ipAddress, ipv6Address)
            else:
                OpenContrailEndpoint(endpointId).create(networkId, ipAddress)
            interface = {}
            interface['Interface'] = {} 
            return HttpResponse(200,'json',interface).response

        if action == 'NetworkDriver.DeleteEndpoint':
            endpointId = data['EndpointID']
            OpenContrailEndpoint(endpointId).delete()
            vethIdHost = 'veth' + endpointId[:8] + 'p0'
            ip = IPDB()
            with ip.interfaces[vethIdHost] as veth:
                veth.remove()
            return HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.EndpointOperInfo':
            endpointInfo = {}
            endpointInfo['NetworkID'] = data['NetworkID']
            endpointInfo['EndpointID'] = data['EndpointID']
            return HttpResponse(200,'json',endpointInfo).response

        if action == 'NetworkDriver.Join':
            networkId = data['NetworkID'][:8]
            endpointId = data['EndpointID']
            sandboxKey = data['SandboxKey'].split("/")[5]
            hostId = endpointId[:8]
            vethIdHost = 'veth' + hostId + 'p0'
            vethIdContainer = 'veth' + hostId
            vn = OpenContrailVN(networkId).VNget()
            subnet = vn.network_ipam_refs[0]['attr'].ipam_subnets[0]
            gateway = subnet.default_gateway
            result = OpenContrailEndpoint(endpointId).join(networkId, sandboxKey)
            mac = result['mac']
            ip = IPDB()
            ip.create(ifname=vethIdHost, kind='veth', peer=vethIdContainer).commit()
            with ip.interfaces[vethIdHost] as veth:
                veth.up()
            with ip.interfaces[vethIdContainer] as veth:
                veth.address = mac
            OpenContrailEndpoint(endpointId).vrouterRegister(result)
            joinInfo = {}
            joinInfo['InterfaceName'] = {}
            joinInfo['InterfaceName']['SrcName'] = vethIdContainer
            joinInfo['InterfaceName']['DstPrefix'] = 'eth'
            joinInfo['Gateway'] = gateway
            joinInfo['StaticRoutes'] = []
            #ipAddress = data['Interface']['Address']
            return HttpResponse(200,'json',joinInfo).response
 
        if action == 'NetworkDriver.ProgramExternalConnectivity':
            return HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.RevokeExternalConnectivity':
            return HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.Leave':
            return HttpResponse(200,'json',{ }).response


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if format == 'html':
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write("body")
        elif format == 'json':
            self.request.sendall(json.dumps({'path':self.path}))
        else:
            self.request.sendall("%s\t%s" %('path', self.path))
        return

    def do_POST(self):
        data = ''
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
        if self.data_string != '':
            data = json.loads(self.data_string)
        logging.debug('path: %s' % self.path)
        logging.debug('data: %s' % data)
        result = requestResponse.execRequest(self.path.strip('/'), data)
        self.request.sendall(result)

class UnixHTTPServer(HTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        SocketServer.TCPServer.server_bind(self)
        self.server_name = "foo"
        self.server_port = 0

parser = argparse.ArgumentParser(description='OpenContrail Docker Libnetwork Driver')
parser.add_argument('-f','--file',
                   help='Path to Contrail API Server configuration file')
parser.add_argument('-u','--admin_user',
                   help='Admin user for Contrail API Server')
parser.add_argument('-t','--admin_tenant',
                   help='Admin tenant for Contrail API Server')
parser.add_argument('-p','--admin_password',
                   help='Admin password for Contrail API Server')
parser.add_argument('-a','--api_server',
                   help='Contrail API Server IP/FQDN')
parser.add_argument('-k','--keystone_server',
                   help='Keystone Server IP/FQDN')
parser.add_argument('-x','--api_port',default='8082',
                   help='Contrail API Server port')
parser.add_argument('-y','--tenant',
                   help='Project')
parser.add_argument('-s','--socketpath',default='/run/docker/plugins',
                   help='Project')
parser.add_argument('-g','--scope',
                   help='local or global scope')
parser.add_argument('-d','--debug',default=False,
                   help='Debug switch')

args = parser.parse_args()
admin_user=''
tenant=''
admin_password=''
api_server=''
api_port=''
socket_path=''
scope=''
keystone_server=''
debug = False

if args.file:
    f = open(args.file,'r')
    configFile = f.read().strip()
    configYaml = yaml.load(configFile)
    api_server = configYaml['api_server']
    api_port = configYaml['api_port']
    admin_user = configYaml['admin_user']
    admin_password = configYaml['admin_password']
    tenant = configYaml['admin_tenant']
    keystone_server = configYaml['keystone_server']
    socket_path = configYaml['socketpath']
    scope = configYaml['scope']
    debug = configYaml['DEBUG']

if args.admin_user:
    admin_user = args.admin_user

if args.admin_tenant:
    tenant = args.admin_tenant

if args.admin_password:
    admin_password = args.admin_password

if args.api_server:
    api_server = args.api_server

if args.keystone_server:
    keystone_server = args.keystone_server

if args.api_port:
    api_port = args.api_port

if args.socketpath:
    socket_path = args.socketpath

if args.scope:
    scope = args.scope

if args.debug:
    debug = args.debug

if not scope:
    scope = 'local'

if debug:
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
else:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

if (not admin_user or not tenant 
                  or not admin_password
                  or not api_server
                  or not keystone_server
                  or not api_port
                  or not socket_path):
   print parser.print_help()
   sys.exit()

socket_address = socket_path + '/opencontrail.sock'

if __name__ == "__main__":
    print "Serving on %s" % socket_address
    requestResponse = RequestResponse()
    if not os.path.exists(socket_path):
        os.makedirs(socket_path)
    httpd = UnixHTTPServer(socket_address, Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        os.remove(socket_address)
