#!/bin/bash


# This script configures the node as a intake node which will recieve loadbalanced syslogs from
# the A10. This node is responsible for passing the syslogs to a redis broker on which
# the indexing nodes will process the logs that will be sent to elasticsearch cluster

set -e
# Setup logging
# Logs stderr and stdout to separate files.
mkdir /opt/collegis/software/logstash java elasticsearch kibana redis
exec 2> >(tee "/opt/collegis/software/logstash/install_Logstash-ELK-ES-Cluster-broker-node.err")
exec 1> >(tee "/opt/collegis/software/logstash/install_Logstash-ELK-ES-Cluster-broker-node.log")

# Setting colors for output
red="$(tput setaf 1)"
yellow="$(tput bold ; tput setaf 3)"
NC="$(tput sgr0)"

# Capture your FQDN Domain Name and IP Address
echo "${yellow}Capturing your hostname${NC}"
yourhostname=$(hostname)
echo "${yellow}Capturing your domain name${NC}"
yourdomainname=$(dnsdomainname)
echo "${yellow}Capturing your FQDN${NC}"
yourfqdn=$(hostname -f)
echo "${yellow}Detecting IP Address${NC}"
IPADDY="$(ifconfig | grep -A 1 'eth0' | tail -1 | cut -d ':' -f 2 | cut -d ' ' -f 1)"
echo "Your hostname is currently ${red}$yourhostname${NC}"
echo "Your domain name is currently ${red}$yourdomainname${NC}"
echo "Your FQDN is currently ${red}$yourfqdn${NC}"
echo "Detected IP Address is ${red}$IPADDY${NC}"
sleep 10

##################### Logstash Broker Setup ###########################################

# repo setup
tee -a /etc/yum.repos.d/elk-stack.repo <<EOF
[logstash-1.4]
name=logstash repository for 1.4.x packages
baseurl=http://packages.elasticsearch.org/logstash/1.4/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1

[elasticsearch-1.0]
name=Elasticsearch repository for 1.0.x packages
baseurl=http://packages.elasticsearch.org/elasticsearch/1.0/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
EOF

# Register server with satellite
curl http://il1satsvr01.deltakedu.corp/pub/bootstrap/bootstrap-server.sh | /bin/bash
rhn-channel --add --channel=clone-epel_rhel6x_x86_64 -u dustin.liddick -p bviad3kq
rhn-channel --add --channel=rhel-x86_64-server-6-rhscl-1 -u dustin.liddick -p bviad3kq

# update box
yum -y --nogpgcheck update

### Install Redis ###
cd /opt/collegis/redis
wget http://download.redis.io/redis-stable.tar.gz
tar xvzf redis-stable.tar.gz
cd redis-stable
make
make install
# if there are issues with make/make install cd to `deps`
cd deps
make hiredis jemalloc linenoise lua
cd ..
make install

#The following will be need to be done by hand
cd utils && ./install_server.sh

# check if redis is working proper
redis-cli ping # result should yield `pong`

# bind redis to your public interface so that other servers can connect to it
vi /etc/redis/redis.conf
bind 127.0.0.1 to 0.0.0.0
service redis_6379 restart
### Install Redis Complete ###
