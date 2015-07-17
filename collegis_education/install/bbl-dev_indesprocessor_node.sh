#!/bin/bash

#Provided by @mrlesmithjr at EveryThingShouldBeVirtual.com
#Modified by Dustin Liddick for CollegisEducation
# This script configures the node as a processor node which will filter syslogs
# comming from the redis broker. This node is responsible for the heavy lifting;
# applying grok filters to the syslogs which will then be sent to the
# elasticsearch cluster

# This script configures the node as a logstash indexer, Elasticsearch client
# node in logstash-cluster

############
# PRE-WORK #
############
set -e
# Setup logging
# Logs stderr and stdout to separate files.
mkdir -p /opt/collegis/software/logstash
exec 2> >(tee "/opt/collegis/software/logstash/install_index_node.err")
exec 1> >(tee "/opt/collegis/software/logstash/install_index_node.log")

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

echo ""
echo ""
echo "${red}checking see status of hostname adition${NC}"
cat /etc/hosts
echo ""
echo ""
echo "now sleeping after satelite hostfile addition for 10s"
sleep 10


rhn-channel --add --channel=clone-epel_rhel6x_x86_64 -u dustin.liddick -p bviad3kq
echo "satalitte server configureation done"
echo ""
sleep 4

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

# Install Oracle Java 8
echo "Installing Oracle Java 8"
mkdir /opt/collegis/software/java
cd /opt/collegis/software/java
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u20-b26/jdk-8u20-linux-x64.tar.gz"
tar -zxvf jdk-8u20-linux-x64.tar.gz
update-alternatives --install /usr/bin/java java /opt/collegis/software/java/jdk1.8.0_20/bin/java 2

##########################
# Logstash Indexer Setup #
##########################


##################### Logstash Front-End Setup #################################

# Install Logstash
yum install -y --nogpgcheck logstash

# Enable logstash start on bootup
chkconfig logstash on

# Update elasticsearch-template for logstash
mv /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json.orig

# Restart logstash service
service logstash restart

# Logrotate job for logstash
tee -a /etc/logrotate.d/logstash <<EOF
/var/log/logstash.log {
        monthly
        rotate 12
        compress
        delaycompress
        missingok
        notifempty
        create 644 root root
}
EOF


# All Done
echo "${yellow}Installation has completed!!${NC}"
echo -e "${yellow}To connect to kibana web-frontend connect to:${NC}"
echo -e "${red}http://elkstack.deltakedu.corp${NC}"
echo ""
echo "${yellow}CollegisEducation.com${NC}"
echo "${yellow}Dustin Liddick${NC}"
echo "${yellow}Enjoy!!!${NC}"
