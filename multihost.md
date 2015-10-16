consul agent -server -bootstrap -data-dir /tmp/consul -bind=192.168.1.58 -client=192.168.1.58

docker daemon -H 192.168.1.58:2376 -H unix:///var/run/docker.sock --cluster-store=consul://192.168.1.58:8500 --cluster-advertise=192.168.1.58:2376

docker daemon -H unix:///var/run/docker.sock -H 192.168.1.57:2376 --cluster-store=consul://192.168.1.58:8500 --cluster-advertise=192.168.1.57:2376
