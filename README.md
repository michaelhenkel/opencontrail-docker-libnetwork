# opencontrail-docker-libnetwork
The OpenContrail docker libnetwork remote plugin allows to use OpenContrail as a SDN  
backend for Docker container.  
Multihost is supported as well as specifying a route target for the created network.  
Usage of the driver:  
```
usage: opencontrail-libnetwork-driver.py [-h] [-f FILE] [-u ADMIN_USER]
                                         [-t ADMIN_TENANT] [-p ADMIN_PASSWORD]
                                         [-a API_SERVER] [-x API_PORT]
                                         [-y TENANT] [-s SOCKETPATH]
                                         [-d DEBUG]

OpenContrail Docker Libnetwork Driver

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to Contrail API Server configuration file
  -u ADMIN_USER, --admin_user ADMIN_USER
                        Admin user for Contrail API Server
  -t ADMIN_TENANT, --admin_tenant ADMIN_TENANT
                        Admin tenant for Contrail API Server
  -p ADMIN_PASSWORD, --admin_password ADMIN_PASSWORD
                        Admin password for Contrail API Server
  -a API_SERVER, --api_server API_SERVER
                        Contrail API Server IP/FQDN
  -x API_PORT, --api_port API_PORT
                        Contrail API Server port
  -y TENANT, --tenant TENANT
                        Project
  -s SOCKETPATH, --socketpath SOCKETPATH
                        Project
  -g SCOPE, --scope SCOPE
                        Local or Global scope
  -d DEBUG, --debug DEBUG
                        Debug switch
```

IPAM support is not implemented yet so Docker will manage IP address assignment.

1. Creating a network:  
 ```
 host1:~# docker network create -d opencontrail \  
               --label rt=64512:100,64512:200 --subnet 192.168.4.0/24 net4
 598c2b9b19dc31bfca2da8f17704363f4701dca8e033f60ff122ee1d23f2acc4
 ```
2. Inspect the network:  

  ```
  host1:~# docker network inspect net4
  {
      "name": "net4",
      "id": "598c2b9b19dc31bfca2da8f17704363f4701dca8e033f60ff122ee1d23f2acc4",
      "scope": "local",
      "driver": "opencontrail",
      "ipam_driver": "default",
      "ipam": [
          {
              "subnet": "192.168.4.0/24",
              "ip_range": "",
              "gateway": "",
              "auxilary_address": {}
          }
      ],
      "containers": {},
      "labels": {
          "rt": "64512:100,64512:200"
      }
  }
  ```

3. The network in OpenContrail:  

  ```
  host1:~# ./config show network \  
             598c2b9b19dc31bfca2da8f17704363f4701dca8e033f60ff122ee1d23f2acc4
  Virtual Network
  Name: [u'default-domain', u'admin', u'598c2b9b19dc31bfca2da8f17704363f4701dca8e033f60ff122ee1d23f2acc4']
  UUID: 63440d42-9578-4734-90e5-18ebb56a115b
  [P] Route targets:
      target:64512:100
      target:64512:200
  [C] Floating IP pools:
  [R] IPAMs:
      default-network-ipam
          subnet: 192.168.4.0/24, gateway: 192.168.4.4
  [R] Policies:
  [R] Route Tables:
  ```

4. creating a Container connected to the network:  

  ```
  host1:~# docker run -itd --name ub6 --net net4 ubuntu:latest
  5c842980d30c185facecbadf17d52f14d7b4c934be1c1134ea740be1d03f8a10
  ```

5. Inspecting the network with the Container attached:  

  ```
  root@docker-exp:~# docker network inspect net4
  {
      "name": "net4",
      "id": "598c2b9b19dc31bfca2da8f17704363f4701dca8e033f60ff122ee1d23f2acc4",
      "scope": "local",
      "driver": "opencontrail",
      "ipam_driver": "default",
      "ipam": [
          {
              "subnet": "192.168.4.0/24",
              "ip_range": "",
              "gateway": "",
              "auxilary_address": {}
          }
      ],
      "containers": {
          "5c842980d30c185facecbadf17d52f14d7b4c934be1c1134ea740be1d03f8a10": {
              "endpoint": "a4cda3d9f8197da6b5458c941fbe7417c600b834ae64dedb41483898350414ee",
              "mac_address": "",
              "ipv4_address": "192.168.4.5/24",
              "ipv6_address": ""
          }
      },
      "labels": {
          "rt": "64512:100,64512:200"
      }
  }
  ```

6. created VIF interface on the host:  

  ```
  host1:~# vif --list
  Vrouter Interface Table
  
  Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3, L2=Layer 2
       D=DHCP, Vp=Vhost Physical, Pr=Promiscuous, Vnt=Native Vlan Tagged
       Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface, Rfl=Receive Filtering Offload, Mon=Interface is Monitored
       Uuf=Unknown Unicast Flood

  vif0/0      OS: eth0
            Type:Physical HWaddr:52:54:00:53:c2:2d IPaddr:0
            Vrf:0 Flags:TcL3L2Vp MTU:1514 Ref:8
            RX packets:15459492  bytes:14749294518 errors:188
            TX packets:5982465  bytes:1282825321 errors:0

  vif0/1      OS: vhost0
            Type:Host HWaddr:52:54:00:53:c2:2d IPaddr:c0a8013a
            Vrf:0 Flags:L3L2 MTU:1514 Ref:3
            RX packets:1084205  bytes:346089648 errors:0
            TX packets:10565980  bytes:8194994288 errors:0

  vif0/2      OS: pkt0
            Type:Agent HWaddr:00:00:5e:00:01:00 IPaddr:0
            Vrf:65535 Flags:L3 MTU:1514 Ref:2
            RX packets:4806870  bytes:1046281396 errors:0
            TX packets:4806139  bytes:748867334 errors:0

  vif0/3      OS: vetha4cda3d9p0
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:0
            Vrf:1 Flags:L3L2D MTU:9160 Ref:6
            RX packets:9  bytes:654 errors:0
            TX packets:2  bytes:84 errors:0

  vif0/4350   OS: pkt3
            Type:Stats HWaddr:00:00:00:00:00:00 IPaddr:0
            Vrf:65535 Flags:L3L2 MTU:9136 Ref:1
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0

  vif0/4351   OS: pkt1
            Type:Stats HWaddr:00:00:00:00:00:00 IPaddr:0
            Vrf:65535 Flags:L3L2 MTU:9136 Ref:1
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
  ```

#Multihost

Libnetwork supports multi-host networking. In order to distribute network information a datastore is needed.  
Consul, etcd and zookeeper are supported datastore backends. 

1. Install consul

  ```
  host1:~# curl -OL https://dl.bintray.com/mitchellh/consul/0.5.2_linux_amd64.zip
  host1:~# unzip 0.5.2_linux_amd64.zip
  host1:~# mv consul /usr/local/bin/
  ```

2. Bootstrap consul

  ```
  host1:~# consul agent -server -bootstrap -data-dir /tmp/consul -bind=<IP> -client=<IP>
  ```

3. Start opencontrail libnetwork remote driver on host1 and host2
  
  ```
  host1:~# opencontrail-libnetwork-driver.py -f opencontrail.conf
  host2:~# opencontrail-libnetwork-driver.py -f opencontrail.conf
  ```

4. Start docker daemon on host1

  ```
  host1:~# docker daemon -H <HOST1_IP>:2376 -H unix:///var/run/docker.sock \  
                    --cluster-store=consul://<CONSUL_IP>:8500 \  
                    --cluster-advertise=<HOST1_IP>:2376
  ```

5. Start docker daemon on host2
  ```
  host2:~# docker daemon -H <HOST2_IP>:2376 -H unix:///var/run/docker.sock \  
                    --cluster-store=consul://<CONSUL_IP>:8500 \  
                    --cluster-advertise=<HOST2_IP>:2376
  ```

6. create a network on host1 OR host2

  ```
  host1:~# docker network create -d opencontrail \  
         --subnet 192.168.10.0/24 \  
         --subnet 2002:1::0/64 \  
         --label rt=64512:100 net2
  ```

7. on the other host the network will become available

  ```
  host2:~# docker network ls
  NETWORK ID          NAME                DRIVER
  9d699b6a6d38        net2                opencontrail
  d4c99652c9e3        bridge              bridge
  6555b914a082        none                null
  a43b74f6c0cd        host                host
  ```

8. run a container on each of the hosts using the same network
  ```
  host1:~# docker run -itd --name ub1 --net net2 ubuntu:latest
  host2:~# docker run -itd --name ub2 --net net2 ubuntu:latest
  ```

9. check IP address assigned to the containers
  ```
  host1:~# docker inspect --format='{{.NetworkSettings.IPAddress}}' ub1
  192.168.11.2

  host2:~# docker inspect --format='{{.NetworkSettings.IPAddress}}' ub2
  192.168.11.3
  ```

10. ping between the containers

  ```
  host1:~# docker exec ub1 ping 192.168.11.3
  PING 192.168.11.3 (192.168.11.3) 56(84) bytes of data.
  64 bytes from 192.168.11.3: icmp_seq=1 ttl=64 time=77.8 ms
  64 bytes from 192.168.11.3: icmp_seq=2 ttl=64 time=24.1 ms
  ```

  


