#!/bin/bash

# This is the Elastic Search Cluster setup. This cluster recieves logs that are
# sent from the indexing nodes. This script will setup an elasticsearch node as
# a dedicated ES data node only...no logstash instances

set -e
# Setup logging
# Logs stderr and stdout to separate files.
mkdir -p /opt/collegis/software/logstash
exec 2> >(tee "/opt/collegis/software/logstash/install_data_node.err")
exec 1> >(tee "/opt/collegis/software/logstash/install_data_node.log")

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
sleep 15


############################### Logstash - Elasticsearch cluster Setup ##################################

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

############################### Logstash - Elasticsearch cluster Setup ##################################
# Register server with satellite
rhn-channel --add --channel=clone-epel_rhel6x_x86_64 -u dustin.liddick -p bviad3kq

# Install Oracle Java 8
echo "Installing Oracle Java 8"
mkdir /opt/collegis/software/java
cd /opt/collegis/software/java
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u20-b26/jdk-8u20-linux-x64.tar.gz"
tar -zxvf jdk-8u20-linux-x64.tar.gz
update-alternatives --install /usr/bin/java java /opt/collegis/software/java/jdk1.8.0_20/bin/java 2

# Install Elasticsearch
yum install -y --nogpgcheck elasticsearch

# Configuring Elasticsearch
echo "### Below is added using install script ###" >> /etc/elasticsearch/elasticsearch.yml
echo "cluster.name: es_cluster" >> /etc/elasticsearch/elasticsearch.yml
echo "node.name: $yourhostname" >> /etc/elasticsearch/elasticsearch.yml
echo "node.master: false" >> /etc/elasticsearch/elasticsearch.yml
echo "node.data: true" >> /etc/elasticsearch/elasticsearch.yml
echo "index.number_of_shards: 5" >> /etc/elasticsearch/elasticsearch.yml
echo "index.number_of_replicas: 1" >> /etc/elasticsearch/elasticsearch.yml
echo "bootstrap.mlockall: true" >> /etc/elasticsearch/elasticsearch.yml
echo "##### Uncomment below instead of using multicast and update with your actual ES Master/Data nodenames #####" >> /etc/elasticsearch/elasticsearch.yml
echo 'discovery.zen.ping.unicast.hosts: ["ceelkes-ob-1p", "ceelkes-ob-2p", "elkes-ob-3p"]' >> /etc/elasticsearch/elasticsearch.yml
echo "#discovery.zen.ping.multicast.enabled: false" >> /etc/elasticsearch/elasticsearch.yml
echo "#### Prevent split brain ES Cluster n/2+1 ####" >> /etc/elasticsearch/elasticsearch.yml
echo "#discovery.zen.minimum_master_nodes: 1" >> /etc/elasticsearch/elasticsearch.yml

# Making changes to /etc/security/limits.conf to allow more open files for elasticsearch
mv /etc/security/limits.conf /etc/security/limits.bak
grep -Ev "# End of file" /etc/security/limits.bak > /etc/security/limits.conf
echo "elasticsearch soft nofile 65536" >> /etc/security/limits.conf
echo "elasticsearch hard nofile 65536" >> /etc/security/limits.conf
echo "elasticsearch - memlock unlimited" >> /etc/security/limits.conf
echo "# End of file" >> /etc/security/limits.conf

# Modify elasticsearch service for ulimit -l unlimited to allow mlockall to work correctly
sed -i -e 's|^#ES_HEAP_SIZE=2g|ES_HEAP_SIZE=6g|' /etc/init.d/elasticsearch
sed -i -e 's|^#MAX_LOCKED_MEMORY=|MAX_LOCKED_MEMORY=unlimited|' /etc/init.d/elasticsearch

# Set Elasticsearch to start on boot
chkconfig elasticsearch on

# Restart Elasticsearch service
service elasticsearch restart

# Install ElasticHQ Plugin to view Elasticsearch Cluster Details http://elastichq.org
# To view these stats connect to http://logstashFQDNorIP:9200/_plugin/HQ/
/usr/share/elasticsearch/bin/plugin -install royrusso/elasticsearch-HQ

# Install elasticsearch Marvel Plugin Details http://www.elasticsearch.org/overview/marvel/
# To view these stats connect to http://logstashFQDNorIP:9200/_plugin/marvel
#/usr/share/elasticsearch/bin/plugin -i elasticsearch/marvel/latest

# Install other elasticsearch plugins
# To view paramedic connect to http://logstashFQDNorIP:9200/_plugin/paramedic/index.html
/usr/share/elasticsearch/bin/plugin -install karmi/elasticsearch-paramedic
# To view elasticsearch head connect to http://logstashFQDNorIP:9200/_plugin/head/index.html
/usr/share/elasticsearch/bin/plugin -install mobz/elasticsearch-head

# Install elasticsearch curator http://www.elasticsearch.org/blog/curator-tending-your-time-series-indices/
yum install -y --nogpgcheck python-pip
pip install elasticsearch-curator

# Create /etc/cron.daily/elasticsearch_curator Cron Job and send output to logstash tagged as curator
tee -a /etc/cron.daily/elasticsearch_curator <<EOF
#!/bin/sh
curator delete --older-than 6 2>&1
curator close --older-than 5 2>&1
curator bloom --older-than 2 2>&1
curator optimize --older-than 2 2>&1

# Cleanup Marvel plugin indices
curator delete --older-than 60 -p .marvel- 2>&1
curator close --older-than 7 -p .marvel- 2>&1
curator bloom --older-than 2 -p .marvel- 2>&1
curator optimize --older-than 2 -p .marvel- 2>&1

# Email report
#recipients="emailAdressToReceiveReport"
#subject="Daily Elasticsearch Curator Job Report"
#cat /var/log/elasticsearch_curator.log | mail -s $subject $recipients
EOF

# Make elasticsearch_curator executable
chmod +x /etc/cron.daily/elasticsearch_curator

# Logrotate job for elasticsearch_curator
tee -a /etc/logrotate.d/elasticsearch_curator <<EOF
/var/log/elasticsearch_curator.log {
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
echo "Installation has completed!!"
echo "Now continue on and setup your ELK Frontend logstash processing nodes"
echo "${yellow}CollegisEducation.com${NC}"
echo "${yellow}Dustin Liddick${NC}"
echo "${yellow}Enjoy!!!${NC}"
