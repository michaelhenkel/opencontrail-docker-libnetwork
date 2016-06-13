#!/usr/bin/python
import socket
import fcntl
import struct
from vnc_api import vnc_api

api_server='10.87.64.34'
api_port='8082'
admin_user = 'admin'
admin_password = 'contrail123'
admin_tenant = 'admin'
serviceInt = 'eth1'
vnc_client = vnc_api.VncApi(
            username = admin_user,
            password = admin_password,
            tenant_name = admin_tenant,
            auth_host = api_server,
            api_server_host=api_server,
            api_server_port=api_port)
vrName = socket.gethostname()


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])
vrIp = get_ip_address('vhost0')

project = vnc_client.project_read(fq_name_str = 'default-domain:' + admin_tenant)
virtualRouter = vnc_api.VirtualRouter(fq_name = [ 'default-global-system-config',vrName],
                                      name = vrName,
                                      virtual_router_type = [ 'embedded'],
                                      virtual_router_ip_address = vrIp)
virtualRouterObject = vnc_client.virtual_router_create(virtualRouter)
physicalRouter = vnc_api.PhysicalRouter(fq_name_str = 'default-global-system-config:'+vrName,
                                        name = vrName,
                                        physical_router_management_ip = vrIp)
physicalRouter.add_virtual_router(ref_obj = virtualRouter)
physicalRouterObj = vnc_client.physical_router_create(physicalRouter)
phIntObj = vnc_api.PhysicalInterface(name = serviceInt, parent_obj = physicalRouter)
phIntResult = vnc_client.physical_interface_create(phIntObj)
