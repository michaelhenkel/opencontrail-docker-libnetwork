#!/usr/bin/python
import yaml
import argparse
from vnc_api import vnc_api
from contrail_vrouter_api.vrouter_api import ContrailVRouterApi


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

    def delete(self):
        self.vmName = '7e2b3fa4'
        interfaceName = 'vethca335617'
        try:
            ip = self.vnc_client.instance_ip_read(fq_name_str = interfaceName)
            if ip:
                self.vnc_client.instance_ip_delete(id=ip.uuid)
        except:
            print 'no inst ip'
        try:
            vm_interface = self.vnc_client.virtual_machine_interface_read(fq_name_str = 'default-domain:' + self.tenant.name + ':' + interfaceName)
            if vm_interface:
                ip_list = vm_interface.get_instance_ip_back_refs()
                if ip_list:
                    for ip in ip_list:
                        ip_obj = self.vnc_client.instance_ip_read(id = ip['uuid'])
                        self.vnc_client.instance_ip_delete(id = ip_obj.uuid)
                ContrailVRouterApi().delete_port(vm_interface.uuid)
                self.vnc_client.virtual_machine_interface_delete(id=vm_interface.uuid)
        except:
            print 'no vm int'
        try:
            vm = self.vnc_client.virtual_machine_read( fq_name_str = self.vmName)
            if vm:
                self.vnc_client.virtual_machine_delete(id=vm.uuid)
        except:
            print 'no vm'

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
parser.add_argument('-m','--mode',
                   help='macvlan/veth')
parser.add_argument('-i','--mvint',
                   help='macvlan host interface')
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
    mode = configYaml['mode']
    mvint = configYaml['mvint']
    debug = configYaml['DEBUG']

OpenContrail().delete()
