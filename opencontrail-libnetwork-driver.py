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
from pprint import pprint
from vnc_api import vnc_api
from contrail_vrouter_api.vrouter_api import ContrailVRouterApi
from opencontrail_vrouter_netns import vrouter_control
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
            api_server_port=api_port)
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

    def create(self, subnet, gateway, rtList=None):
        try:
            ipam_obj = self.vnc_client.network_ipam_read(fq_name = ['default-domain',
                                                  'default-project', 'default-network-ipam'])
        except Exception as e:
            logging.debug('ERROR: %s' %(str(e)))
            return
        cidr = subnet.split('/')
        subnet = vnc_api.SubnetType(ip_prefix = cidr[0],
                ip_prefix_len = int(cidr[1]))
        if gateway:
            ipam_subnet = vnc_api.IpamSubnetType(subnet = subnet,
                default_gateway = gateway)
        else:
            ipam_subnet = vnc_api.IpamSubnetType(subnet = subnet)
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


class OpenContrailVirtualMachineInterface(OpenContrail):
    def __init__(self, vmName):
        super(OpenContrailVirtualMachineInterface,self).__init__()
        self._vrouter_client = ContrailVRouterApi(doconnect=True)
        self.vmName = vmName

    def getMac(self):
        interfaceName = 'veth' + self.vmName
        vm_interface = self.vnc_client.virtual_machine_interface_read(fq_name=[self.vmName, interfaceName])
        mac = vm_interface.virtual_machine_interface_mac_addresses.mac_address[0]
        return mac

    def delete(self):
        interfaceName = 'veth' + self.vmName
        try:
            ip = self.vnc_client.instance_ip_read(fq_name_str = interfaceName)
            if ip:
                self.vnc_client.instance_ip_delete(id=ip.uuid)
        except:
            logging.debug('no instance ip')
        try:
            vm_interface = self.vnc_client.virtual_machine_interface_read(fq_name=[self.vmName, interfaceName])
            if vm_interface:
                ContrailVRouterApi().delete_port(vm_interface.uuid)
                self.vnc_client.virtual_machine_interface_delete(id=vm_interface.uuid)
        except:
            logging.debug('no vm interface')
        try:
            vm = self.vnc_client.virtual_machine_read( fq_name_str = self.vmName)
            if vm:
                self.vnc_client.virtual_machine_delete(id=vm.uuid)
        except:
            logging.debug('no vm')

    def create(self, vnName, ipAddress):
        interfaceName = 'veth' + self.vmName
        '''
        try:
            ip = self.vnc_client.instance_ip_read(fq_name_str = interfaceName)
            if ip:
                self.vnc_client.instance_ip_delete(id=ip.uuid)
        except:
            print 'no ip instance'
        try:
            vm_interface = self.vnc_client.virtual_machine_interface_read(fq_name=[self.vmName, interfaceName])
            if vm_interface:
                self.vnc_client.virtual_machine_interface_delete(id=vm_interface.uuid)
        except:
            print 'no vm interface'
        try:
            vm = self.vnc_client.virtual_machine_read( fq_name_str = self.vmName)
            if vm:
                self.vnc_client.virtual_machine_delete(id=vm.uuid) 
        except:
            print 'no vm'
        '''
        vm_instance = vnc_api.VirtualMachine(name = self.vmName)
        self.vnc_client.virtual_machine_create(vm_instance)
        vm_interface = vnc_api.VirtualMachineInterface(name = interfaceName, parent_obj = vm_instance)
        vn = OpenContrailVN(vnName).VNget()
        vm_interface.set_virtual_network(vn)
        self.vnc_client.virtual_machine_interface_create(vm_interface)
        vm_interface = self.vnc_client.virtual_machine_interface_read(id = vm_interface.uuid)
        ip = vnc_api.InstanceIp(name = interfaceName, instance_ip_address = ipAddress.split('/')[0])
        ip.set_virtual_machine_interface(vm_interface)
        ip.set_virtual_network(vn)
        self.vnc_client.instance_ip_create(ip)
        ip = self.vnc_client.instance_ip_read(id = ip.uuid)
        ipAddress = ip.get_instance_ip_address()
        subnet = vn.network_ipam_refs[0]['attr'].ipam_subnets[0]
        plen = subnet.get_subnet().get_ip_prefix_len()
        gw = subnet.default_gateway
        mac = vm_interface.virtual_machine_interface_mac_addresses.mac_address[0]
        vrouterInterface = interfaceName + 'p0'
        ContrailVRouterApi().add_port(vm_instance.uuid, vm_interface.uuid, vrouterInterface, mac, display_name=vm_instance.name,
                 vm_project_id=self.tenant.uuid, port_type='NovaVMPort')

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
        
        if action == 'Plugin.Activate':
            return HttpResponse(200,'json',{ 'Implements': ['NetworkDriver','IPAM'] }).response

        if action == 'NetworkDriver.GetCapabilities':
            return HttpResponse(200,'json',{ 'Scope':'local'}).response

        if action == 'IPAM.GetDefaultAddressSpaces':
            requestPool = {}
            return HttpResponse(200,'json',requestPool).response

        if action == 'NetworkDriver.CreateNetwork':
            networkId = data['NetworkID']
            pool = data['IPv4Data'][0]['Pool']
            gateway = data['IPv4Data'][0]['Gateway'].split('/')[0]
            if 'rt' in data['Options']['com.docker.network.generic']:
                rtList = data['Options']['com.docker.network.generic']['rt'].split(',')
                openContrailVN = OpenContrailVN(networkId).create(pool, gateway, rtList = rtList)
            else:
                openContrailVN = OpenContrailVN(networkId).create(pool, gateway)
            networkInfo = {}
            networkInfo['NetworkID'] = networkId
            return HttpResponse(200,'json',networkInfo).response

        if action == 'NetworkDriver.DeleteNetwork':
            networkId = data['NetworkID']
            openContrailVN = OpenContrailVN(networkId).delete()
            return HttpResponse(200,'json',{ }).response

        if action == 'NetworkDriver.CreateEndpoint':
            networkId = data['NetworkID']
            endpointId = data['EndpointID']
            ipAddress = data['Interface']['Address']
            hostId = endpointId[:8]
            OpenContrailVirtualMachineInterface(hostId).create(networkId, ipAddress)
            interface = {}
            interface['Interface'] = {} 
            return HttpResponse(200,'json',interface).response

        if action == 'NetworkDriver.DeleteEndpoint':
            endpointId = data['EndpointID']
            hostId = endpointId[:8]
            OpenContrailVirtualMachineInterface(hostId).delete()
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
            networkId = data['NetworkID']
            endpointId = data['EndpointID']
            hostId = endpointId[:8]
            vethIdHost = 'veth' + hostId + 'p0'
            vethIdContainer = 'veth' + hostId
            vn = OpenContrailVN(networkId).VNget()
            subnet = vn.network_ipam_refs[0]['attr'].ipam_subnets[0]
            gateway = subnet.default_gateway
            mac = OpenContrailVirtualMachineInterface(hostId).getMac()
            ip = IPDB()
            ip.create(ifname=vethIdHost, kind='veth', peer=vethIdContainer).commit()
            with ip.interfaces[vethIdHost] as veth:
                veth.up()
            with ip.interfaces[vethIdContainer] as veth:
                veth.address = mac
            joinInfo = {}
            joinInfo['InterfaceName'] = {}
            joinInfo['InterfaceName']['SrcName'] = vethIdContainer
            joinInfo['InterfaceName']['DstPrefix'] = 'eth'
            joinInfo['Gateway'] = gateway
            joinInfo['StaticRoutes'] = []
            return HttpResponse(200,'json',joinInfo).response

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
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
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
parser.add_argument('-x','--api_port',default='8082',
                   help='Contrail API Server port')
parser.add_argument('-y','--tenant',
                   help='Project')
parser.add_argument('-s','--socketpath',default='/run/docker/plugins',
                   help='Project')
parser.add_argument('-d','--debug',default=False,
                   help='Debug switch')

args = parser.parse_args()
admin_user=''
tenant=''
admin_password=''
api_server=''
api_port=''
socket_path=''
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
    socket_path = configYaml['socketpath']
    debug = configYaml['DEBUG']

if args.admin_user:
    admin_user = args.admin_user

if args.admin_tenant:
    tenant = args.admin_tenant

if args.admin_password:
    admin_password = args.admin_password

if args.api_server:
    api_server = args.api_server

if args.api_port:
    api_port = args.api_port

if args.socketpath:
    socket_path = args.socketpath

if args.debug:
    debug = args.debug

if debug:
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
else:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

if (not admin_user or not tenant 
                  or not admin_password
                  or not api_server
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
