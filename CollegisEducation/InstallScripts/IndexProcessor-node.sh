#!/bin/bash

#Provided by @mrlesmithjr at EveryThingShouldBeVirtual.com
#Modified by Dustin Liddick for RHEL

# This script configures the node as a logstash processor, Elasticsearch client node in logstash-cluster

set -e
# Setup logging
# Logs stderr and stdout to separate files.
exec 2> >(tee "/opt/collegis/software/logstash/install_Logstash-ELK-ES-Cluster-client-node.err")
exec > >(tee "/opt/collegis/software/logstash/install_Logstash-ELK-ES-Cluster-client-node.log")

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

############################### Logstash - Elasticsearch cluster Setup ##################################
# Install Pre-Reqs
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
echo "cluster.name: logstash-cluster" >> /etc/elasticsearch/elasticsearch.yml
echo "node.name: $yourhostname" >> /etc/elasticsearch/elasticsearch.yml
echo "node.master: false" >> /etc/elasticsearch/elasticsearch.yml
echo "node.data: false" >> /etc/elasticsearch/elasticsearch.yml
echo "index.number_of_shards: 5" >> /etc/elasticsearch/elasticsearch.yml
echo "index.number_of_replicas: 1" >> /etc/elasticsearch/elasticsearch.yml
echo "bootstrap.mlockall: true" >> /etc/elasticsearch/elasticsearch.yml
echo "##### Uncomment below instead of using multicast and update with your actual ES Master/Data nodenames #####" >> /etc/elasticsearch/elasticsearch.yml
echo '#discovery.zen.ping.unicast.hosts: ["elkes-ob-1p", "elkes-ob-2p", "elkes-ob-3p"]' >> /etc/elasticsearch/elasticsearch.yml
echo "#discovery.zen.ping.multicast.enabled: false" >> /etc/elasticsearch/elasticsearch.yml

# Making changes to /etc/security/limits.conf to allow more open files for elasticsearch
mv /etc/security/limits.conf /etc/security/limits.bak
grep -Ev "# End of file" /etc/security/limits.bak > /etc/security/limits.conf
echo "elasticsearch soft nofile 65536" >> /etc/security/limits.conf
echo "elasticsearch hard nofile 65536" >> /etc/security/limits.conf
echo "elasticsearch - memlock unlimited" >> /etc/security/limits.conf
echo "# End of file" >> /etc/security/limits.conf

# Modify elasticsearch service for ulimit -l unlimited to allow mlockall to work correctly
#sed -i -e 's|^#ES_HEAP_SIZE=1g|ES_HEAP_SIZE=1g|' /etc/init.d/elasticsearch
#sed -i -e 's|^#MAX_LOCKED_MEMORY=|MAX_LOCKED_MEMORY=unlimited|' /etc/init.d/elasticsearch

# Set Elasticsearch to start on boot
chkconfig elasticsearch on

# Restart Elasticsearch service
service elasticsearch restart

# Install ElasticHQ Plugin to view Elasticsearch Cluster Details http://elastichq.org
# To view these stats connect to http://logstashFQDNorIP:9200/_plugin/HQ/
/usr/share/elasticsearch/bin/plugin -install royrusso/elasticsearch-HQ

# Install elasticsearch Marvel Plugin Details http://www.elasticsearch.org/overview/marvel/
# To view these stats connect to http://logstashFQDNorIP:9200/_plugin/marvel
/usr/share/elasticsearch/bin/plugin -i elasticsearch/marvel/latest

# Install other elasticsearch plugins
# To view paramedic connect to http://logstashFQDNorIP:9200/_plugin/paramedic/index.html
/usr/share/elasticsearch/bin/plugin -install karmi/elasticsearch-paramedic
# To view elasticsearch head connect to http://logstashFQDNorIP:9200/_plugin/head/index.html
/usr/share/elasticsearch/bin/plugin -install mobz/elasticsearch-head

# Install elasticsearch curator http://www.elasticsearch.org/blog/curator-tending-your-time-series-indices/
#apt-get -y install python-pip
#pip install elasticsearch-curator

# Create /etc/cron.daily/elasticsearch_curator Cron Job
#tee -a /etc/cron.daily/elasticsearch_curator <<EOF
#!/bin/sh
#/usr/local/bin/curator --host 127.0.0.1 delete --older-than 90
#/usr/local/bin/curator --host 127.0.0.1 close --older-than 30
#/usr/local/bin/curator --host 127.0.0.1 bloom --older-than 2
#/usr/local/bin/curator --host 127.0.0.1 optimize --older-than 2

# Email report
#recipients="emailAdressToReceiveReport"
#subject="Daily Elasticsearch Curator Job Report"
#cat /var/log/elasticsearch_curator.log | mail -s $subject $recipients
#EOF

# Make elasticsearch_curator executable
#chmod +x /etc/cron.daily/elasticsearch_curator

# Logrotate job for elasticsearch_curator
#tee -a /etc/logrotate.d/elasticsearch_curator <<EOF
#/var/log/elasticsearch_curator.log {
#        monthly
#        rotate 12
#        compress
#        delaycompress
#        missingok
#        notifempty
#        create 644 root root
#}
#EOF


##################### Logstash Front-End Setup ###########################################

# Install Redis-Server
yum install -y gcc
mkdir /opt/collegis/software/redis
wget http://download.redis.io/redis-stable.tar.gz
tar xvzf redis-stable.tar.gz
cd redis-stable/deps
make hiredis jemalloc linenoise lua
cd ..
make
make install
cd deps
make hiredis jemalloc linenoise lua
cd ..
make install
cd utils && ./install_server.sh

# Configure Redis-Server to listen on all interfaces
sed -i -e 's|bind 127.0.0.1|bind 0.0.0.0|' /etc/redis/6379.conf
service redis_6379 restart

# Install Logstash
yum install -y --nogpgcheck logstash
/opt/logstash/bin/plugin install contrib



# Enable logstash start on bootup
chkconfig logstash on

echo "Setting up logstash for different host type filtering"
echo "Your domain name:"
echo "(example - yourcompany.com)"
echo -n "Enter your domain name and press enter: "
read yourdomainname
echo "You entered ${red}$yourdomainname${NC}"
echo "Now enter your PFSense Firewall hostname if you use it ${red}(DO NOT include your domain name)${NC}"
echo "If you do not use PFSense Firewall enter ${red}pfsense${NC}"
echo -n "Enter PFSense Hostname: "
read pfsensehostname
echo "You entered ${red}$pfsensehostname${NC}"
echo "Now enter your Citrix Netscaler naming scheme if you use it ${red}(DO NOT include your domain name)${NC}"
echo "For example....Your Netscaler's are named nsvpx01, nsvpx02....Only enter nsvpx for the naming scheme"
echo "If you do not use Citrix Netscaler's enter ${red}netscaler${NC}"
echo -n "Enter Citrix Netscaler Naming scheme: "
read netscalernaming
echo "You entered ${red}$netscalernaming${NC}"

# Create Logstash configuration file
tee -a /etc/logstash/conf.d/logstash.conf <<EOF
input {
        redis {
                host => "127.0.0.1"
                data_type => "list"
                key => "logstash"
        }
}
filter {
        if [type] == "syslog" {
                mutate {
                        remove_tag => "Ready"
                }
        }
}
# First layer of normal syslog parsing
filter {
        if "syslog" in [tags] {
                grok {
                        match => { "message" => "<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
                        add_field => [ "received_at", "%{@timestamp}" ]
                        add_field => [ "received_from", "%{host}" ]
                }
                syslog_pri { }
                date {
                        match => [ "syslog_timestamp", "MMM d HH:mm:ss", "MMM dd HH:mm:ss" ]
                }
                if !("_grokparsefailure" in [tags]) {
                        mutate {
                                replace => [ "host", "%{syslog_hostname}" ]
                                replace => [ "@source_host", "%{syslog_hostname}" ]
                                replace => [ "@message", "%{syslog_message}" ]
                        }
                }
                if [syslog_hostname] =~ /.*?($netscalernaming).*?($yourdomainname)?/ {
                        mutate {
                                add_tag => [ "Netscaler" ]
                        }
                }
                if [syslog_hostname] =~ /.*?($pfsensehostname).*?($yourdomainname)?/ {
                        mutate {
                                add_tag => [ "PFSense" ]
                        }
                }
        }
}
# Setting up IPTables firewall parsing
filter {
        if "syslog" in [tags] {
                if "IPTables" in [message] {
                        grok {
                                match => { "message" => "%{IPTABLES}" }
                                patterns_dir => [ "/opt/logstash/patterns" ]
                        }
                        mutate {
                                add_tag => [ "IPTABLES" ]
                        }
                        geoip {
                                source => "src_ip"
                                target => "geoip"
                                add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                                add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                        }
                        mutate {
                                convert => [ "[geoip][coordinates]", "float" ]
                        }
                }
        }
}
# Setting up IPTables actions
filter {
        if "IPTABLES" in [tags] {
                grok {
                        match => [
                                "message", "IPTables-%{WORD:iptables_action}"
                        ]
                }
                grok {
                        match => [
                                "message", "PROTO=%{WORD:iptables_proto}"
                        ]
                }
                mutate {
                        remove_field => [ "proto" ]
                }
                mutate {
                        rename => [ "iptables_proto", "proto" ]
                }
        }
}
# Setting up HAProxy parsing
filter {
        if "syslog" in [tags] {
                if [syslog_program] == "haproxy" {
                        grok {
                                break_on_match => false
                                match => [
                                        "message", "%{HAPROXYHTTP}",
                                        "message", "%{HAPROXYTCP}"
                                ]
                                add_tag => [ "HAProxy" ]
                        }
                        geoip {
                                source => "client_ip"
                                target => "geoip"
                                add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                                add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                        }
                        mutate {
                                convert => [ "[geoip][coordinates]", "float" ]
                                replace => [ "host", "%{@source_host}" ]
                                rename => [ "http_status_code", "response" ]
                                rename => [ "http_request", "request" ]
                                rename => [ "client_ip", "src_ip" ]
                        }
                }
        }
}
# Setting up KeepAliveD parsing
filter {
        if "syslog" in [tags] {
                if [syslog_program] =~ /Keepalived/ {
                        mutate {
                                add_tag => [ "KeepAliveD" ]
                        }
                }
        }
}
# Filtering for SSH logins either failed or successful
filter {
        if "syslog" in [tags] {
                if [syslog_program] == "sshd" {
                        if "Failed password" in [message] {
                                grok {
                                        break_on_match => false
                                        match => [
                                                "message", "invalid user %{DATA:UserName} from %{IP:src_ip}",
                                                "message", "for %{DATA:UserName} from %{IP:src_ip}"
                                        ]
                                }
                                mutate {
                                        add_tag => [ "SSH_Failed_Login" ]
                                }
                        }
                        if "Accepted password" in [message] {
                                grok {
                                        match => [
                                                "message", "for %{DATA:UserName} from %{IP:src_ip}"
                                        ]
                                }
                                mutate {
                                        add_tag => [ "SSH_Successful_Login" ]
                                }
                        }
                        geoip {
                                source => "src_ip"
                                target => "geoip"
                                add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                                add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                        }
                        mutate {
                                convert => [ "[geoip][coordinates]", "float" ]
                        }
                }
        }
}
# Setting up VMware ESX(i) log parsing
filter {
        if "VMware" in [tags] {
                multiline {
                        pattern => "-->"
                        what => "previous"
                }
                grok {
                        break_on_match => true
                        match => [
                                "message", "<%{POSINT:syslog_pri}>%{TIMESTAMP_ISO8601:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{SYSLOGPROG:syslog_program}: (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) \[%{DATA:message_service_info}]\ (?<syslog_message>(%{GREEDYDATA})))",
                                "message", "<%{POSINT:syslog_pri}>%{TIMESTAMP_ISO8601:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{SYSLOGPROG:syslog_program}: (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) (?<syslog_message>(%{GREEDYDATA})))",
                                "message", "<%{POSINT:syslog_pri}>%{TIMESTAMP_ISO8601:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{SYSLOGPROG:syslog_program}: %{GREEDYDATA:syslog_message}"
                        ]
                }
                syslog_pri { }
                date {
                        match => [ "syslog_timestamp", "YYYY-MM-ddHH:mm:ss,SSS" ]
                        timezone => "UTC"
                }
                mutate {
                        replace => [ "@source_host", "%{syslog_hostname}" ]
                }
                mutate {
                        replace => [ "@message", "%{syslog_message}" ]
                }
                if "Device naa" in [message] {
                        grok {
                                break_on_match => false
                                match => [
                                        "message", "Device naa.%{WORD:device_naa} performance has %{WORD:device_status}%{GREEDYDATA} of %{INT:datastore_latency_from}%{GREEDYDATA} to %{INT:datastore_latency_to}",
                                        "message", "Device naa.%{WORD:device_naa} performance has %{WORD:device_status}%{GREEDYDATA} from %{INT:datastore_latency_from}%{GREEDYDATA} to %{INT:datastore_latency_to}"
                                ]
                        }
                }
                if "connectivity issues" in [message] {
                        grok {
                                match => [
                                        "message", "Hostd: %{GREEDYDATA} : %{DATA:device_access} to volume %{DATA:device_id} %{DATA:datastore} (following|due to)"
                                ]
                        }
                }
                if "WARNING" in [message] {
                        grok {
                                match => [
                                        "message", "WARNING: %{GREEDYDATA:vmware_warning_msg}"
                                ]
                        }
                }
        }
}
# Setting up VMware vCenter parsing
filter {
        if "vCenter" in [tags] {
                grok {
                        break_on_match => true
                        match => [
                                "message", "<%{INT:syslog_pri}>%{SYSLOGTIMESTAMP} %{IPORHOST:syslog_hostname} %{TIMESTAMP_ISO8601:syslog_timestamp} (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) \[%{DATA:message_service_info}]\ (?<syslog_message>(%{GREEDYDATA})))",
                                "message", "<%{INT:syslog_pri}>%{SYSLOGTIMESTAMP} %{IPORHOST:syslog_hostname} %{TIMESTAMP_ISO8601:syslog_timestamp} (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) (?<syslog_message>(%{GREEDYDATA})))",
                                "message", "<%{INT:syslog_pri}>%{SYSLOGTIMESTAMP} %{IPORHOST:syslog_hostname} %{TIMESTAMP_ISO8601:syslog_timestamp} %{GREEDYDATA:syslog_message}"
                        ]
                }
                syslog_pri { }
                date {
                        match => [ "syslog_timestamp", "YYYY-MM-ddHH:mm:ss,SSS" ]
                        timezone => "UTC"
                }
                mutate {
                        replace => [ "@source_host", "%{syslog_hostname}" ]
                        replace => [ "@message", "%{syslog_message}" ]
                }
        }
}
# Setting up PFsense Firewall parsing
filter {
    if "PFSense" in [tags] {
        grok {
            add_tag => [ "firewall" ]
            match => [ "message", "<(?<evtid>.*)>(?<datetime>(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]) (?:2[0123]|[01]?[0-9]):(?:[0-5][0-9]):(?:[0-5][0-9])) (?<prog>.*?): (?<msg>.*)" ]
        }
        mutate {
            gsub => ["datetime","  "," "]
        }
        date {
            match => [ "datetime", "MMM dd HH:mm:ss" ]
        }
        mutate {
            replace => [ "message", "%{msg}" ]
        }
        mutate {
            remove_field => [ "msg", "datetime", "prog" ]
        }
    }
    if [syslog_program] =~ /^pf$/ {
        mutate {
            add_tag => [ "packetfilter" ]
        }
        multiline {
            pattern => "^\s+|^\t\s+"
            what => "previous"
        }
        mutate {
            remove_field => [ "msg", "datetime" ]
            remove_tag => [ "multiline" ]
        }
        grok {
            match => [ "message", "rule (?<rule>.*)\(.*\): (?<action>pass|block) .* on (?<iface>.*): .* proto (?<proto>TCP|UDP|IGMP|ICMP) .*\n\s*(?<src_ip>(\d+\.\d+\.\d+\.\d+))\.?(?<src_port>(\d*)) [<|>] (?<dst_ip>(\d+\.\d+\.\d+\.\d+))\.?(?<dst_port>(\d*)):" ]
        }
    }
    if [syslog_program] =~ /^dhcpd$/ {
        if [message] =~ /^DHCPACK|^DHCPREQUEST|^DHCPOFFER/ {
            grok {
                match => [ "message", "(?<action>.*) (on|for|to) (?<src_ip>[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]) .*(?<mac_address>[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]).* via (?<iface>.*)" ]
            }
        }
        if [message] =~ /^DHCPDISCOVER/ {
            grok {
                match => [ "message", "(?<action>.*) from (?<mac_address>[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]).* via (?<iface>.*)" ]
            }
        }
        if [message] =~ /^DHCPINFORM/ {
            grok {
                match => [ "message", "(?<action>.*) from (?<src_ip>.*).* via (?<iface>.*)" ]
            }
        }
   }
   if "_grokparsefailure" in [tags] {
        drop { }
   }
}
filter {
        if "PFSense" in [tags] {
                mutate {
                        replace => [ "@source_host", "%{syslog_hostname}" ]
                        replace => [ "@message", "%{syslog_message}" ]
                }
        }
}
# Setting up Citrix Netscaler parsing
filter {
        if "Netscaler" in [tags] {
                grok {
                        break_on_match => true
                        match => [
                                "message", "<%{POSINT:syslog_pri}> %{DATE_US}:%{TIME} GMT %{SYSLOGHOST:syslog_hostname} %{GREEDYDATA:netscaler_message} : %{DATA} %{INT:netscaler_spcbid} - %{DATA} %{IP:clientip} - %{DATA} %{INT:netscaler_client_port} - %{DATA} %{IP:netscaler_vserver_ip} - %{DATA} %{INT:netscaler_vserver_port} %{GREEDYDATA:netscaler_message} - %{DATA} %{WORD:netscaler_session_type}",
                                "message", "<%{POSINT:syslog_pri}> %{DATE_US}:%{TIME} GMT %{SYSLOGHOST:syslog_hostname} %{GREEDYDATA:netscaler_message}"
                        ]
                }
                syslog_pri { }
                geoip {
                        source => "clientip"
                        target => "geoip"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                mutate {
                        add_field => [ "src_ip", "%{clientip}" ]
                        convert => [ "[geoip][coordinates]", "float" ]
                        replace => [ "@source_host", "%{host}" ]
                        replace => [ "@message", "%{netscaler_message}" ]
                }
        }
}
# Setting up Apache web server parsing
filter {
        if [type] == "apache" {
                grok {
                        pattern => "%{COMBINEDAPACHELOG}"
                }
                geoip {
                        source => "clientip"
                        target => "geoip"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                mutate {
                        add_field => [ "src_ip", "%{clientip}" ]
                        convert => [ "[geoip][coordinates]", "float" ]
                        replace => [ "@source_host", "%{host}" ]
                        replace => [ "@message", "%{message}" ]
                        rename => [ "verb" , "method" ]
                }
                grok {
                        match => [
                                "message", "%{DATA:apache_vhost} "
                        ]
                }
        }
}
# Setting up Nginx web server parsing
filter {
        if [type] =~ "nginx" {
                grok {
                        pattern => "%{COMBINEDAPACHELOG}"
                }
                geoip {
                        source => "clientip"
                        target => "geoip"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                mutate {
                        add_field => [ "src_ip", "%{clientip}" ]
                        convert => [ "[geoip][coordinates]", "float" ]
                        replace => [ "@source_host", "%{host}" ]
                        replace => [ "@message", "%{message}" ]
                        rename => [ "verb" , "method" ]
                }
                grok {
                        match => [
                                "message", "%{DATA:apache_vhost} "
                        ]
                }
        }
}
# Setting up Nginx errors parsing
filter {
        if [type] == "nginx-error" {
                grok {
                        match => [
                                "message", "(?<timestamp>%{YEAR}[./-]%{MONTHNUM}[./-]%{MONTHDAY}[- ]%{TIME}) \[%{LOGLEVEL:severity}\] %{POSINT:pid}#%{NUMBER}: %{GREEDYDATA:errormessage}(?:, client: (?<clientip>%{IP}|%{HOSTNAME}))(?:, server: %{IPORHOST:server})(?:, request: %{QS:request}) ??(?:, host: %{QS:host})",
                                "message", "(?<timestamp>%{YEAR}[./-]%{MONTHNUM}[./-]%{MONTHDAY}[- ]%{TIME}) \[%{LOGLEVEL:severity}\] %{POSINT:pid}#%{NUMBER}: %{GREEDYDATA:errormessage}(?:, client: (?<clientip>%{IP}|%{HOSTNAME}))(?:, server: %{IPORHOST:server})(?:, request: %{QS:request})(?:, upstream: %{QS:upstream})(?:;, host: %{QS:host})(?:, referrer: \"%{URI:referrer})"
                        ]
                }
        }
}
# Windows Eventlogs....Use NXLOG for client side logging
filter {
        if [type] == "eventlog" {
                mutate {
                        lowercase => [ "EventType", "FileName", "Hostname", "Severity" ]
                }
                mutate {
                        rename => [ "Hostname", "@source_host" ]
                }
                date {
                        match => [ "EventReceivedTime", "UNIX" ]
                }
                mutate {
                        rename => [ "Message", "@message" ]
                        rename => [ "Severity", "eventlog_severity" ]
                        rename => [ "SeverityValue", "eventlog_severity_code" ]
                        rename => [ "Channel", "eventlog_channel" ]
                        rename => [ "SourceName", "eventlog_program" ]
                        rename => [ "SourceModuleName", "nxlog_input" ]
                        rename => [ "Category", "eventlog_category" ]
                        rename => [ "EventID", "eventlog_id" ]
                        rename => [ "RecordNumber", "eventlog_record_number" ]
                        rename => [ "ProcessID", "eventlog_pid" ]
                }
        }
}
# Microsoft IIS logging....Use NXLOG for client side logging
filter {
        if [type] == "iis" {
                if [message] =~ "^#" {
                                drop {}
                }
                grok {
                        match => [
                                "message", "%{TIMESTAMP_ISO8601:logtime} %{IPORHOST:hostname} %{URIPROTO:cs_method} %{URIPATH:cs_stem} (?:%{NOTSPACE:cs_query}|-) %{NUMBER:src_port} %{NOTSPACE:cs_username} %{IP:clientip} %{NOTSPACE:cs_useragent} %{NUMBER:sc_status} %{NUMBER:sc_subresponse} %{NUMBER:sc_win32_status} %{NUMBER:timetaken}"
                        ]
                }
                date {
                        match => [ "logtime", "YYYY-MM-dd HH:mm:ss" ]
                        timezone => "UTC"
                }
                geoip {
                        source => "clientip"
                        target => "geoip"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                dns {
                        reverse => [ "hostname" ]
                        action => "replace"
                }
                mutate {
                        add_field => [ "src_ip", "%{clientip}" ]
                        convert => [ "[geoip][coordinates]", "float" ]
                        replace => [ "@source_host", "%{hostname}" ]
                        replace => [ "@message", "%{message}" ]
                        rename => [ "cs_method", "method" ]
                        rename => [ "cs_stem", "request" ]
                        rename => [ "cs_useragent", "agent" ]
                        rename => [ "cs_username", "username" ]
                        rename => [ "sc_status", "response" ]
                        rename => [ "timetaken", "time_request" ]
                }
        }
}
filter {
    if [type] == "mysql-slowquery" {
                multiline {
                        what => previous
                        pattern => "^\s"
                }
                grok { pattern => "^%{NUMBER:date} *%{NOTSPACE:time}" }
                mutate { replace => [ "time", "%{date} %{time}" ] }
                date {
                        match => [ "YYMMdd H:mm:ss", "YYMMdd HH:mm:ss" ]
                }
                mutate { remove => [ "time", "date" ] }
                split { }
        }
}
# Create @source_host_ip field for all devices for IP Tracking used along with src_ip and dst_ip fields
filter {
        if ![source_host_ip] {
                mutate {
                        add_field => [ "source_host_ip", "%{@source_host}" ]
                }
                dns {
                        resolve => [ "source_host_ip" ]
                        action => "replace"
                }
                mutate {
                        rename => [ "source_host_ip", "@source_host_ip" ]
                }
        }
}
# The below filter section will be used to remove unnecessary fields to keep ES memory cache from filling up with useless data
# The below filter section will be where you would want to comment certain types or tags out if trying to isolate a logging issue
filter {
        if [type] == "apache" {
                mutate {
                        remove_field => [ "clientip", "host", "timestamp" ]
                }
        }
        if [type] == "eventlog" {
                mutate {
                        remove => [ "SourceModuleType", "EventTimeWritten", "EventTime", "EventReceivedTime", "EventType" ]
                }
        }
        if "HAProxy" in [tags] {
                mutate {
                        remove_field => [ "accept_date", "haproxy_hour", "haproxy_milliseconds", "haproxy_minute", "haproxy_month", "haproxy_monthday", "haproxy_second", "haproxy_time", "haproxy_year", "pid", "program", "syslog_server" ]
                }
        }
        if [type] == "iis" {
                mutate {
                        remove_field => [ "clientip", "host", "hostname", "logtime" ]
                }
        }
        if [type] =~ "nginx" {
                mutate {
                        remove_field => [ "clientip", "host", "timestamp" ]
                }
        }
        if "Netscaler" in [tags] {
                mutate {
                        remove_field => [ "clientip" ]
                }
        }
        if [type] == "syslog" {
                mutate {
                        remove_field => [ "host", "received_at", "received_from", "syslog_hostname", "syslog_message", "syslog_timestamp" ]
                }
        }
        if [type] == "VMware" {
                mutate {
                        remove_field => [ "host", "program", "syslog_hostname", "syslog_message", "syslog_timestamp" ]
                }
        }
        if [type] == "vCenter" {
                mutate {
                        remove_field => [ "host", "message-body", "program", "syslog_hostname", "syslog_message", "syslog_timestamp" ]
                }
        }
}

#### Multicast discovery mode ####
# Send output to the ES cluster logstash-cluster using a predefined template
# The following settings will be used during the initial setup which will be used for using multicast ES nodes
# When changing to unicast discovery mode you need to comment out the following section and configure the unicast discovery mode in the next section
output {
        elasticsearch {
                cluster => "logstash-cluster"
                flush_size => 1
                manage_template => true
                template => "/opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json"
        }
}
EOF

# Update elasticsearch-template for logstash
mv /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json.orig
tee -a /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json <<EOF
{
  "template" : "logstash-*",
  "settings" : {
    "index.refresh_interval" : "5s"
  },
  "mappings" : {
    "_default_" : {
       "_all" : {"enabled" : true},
       "dynamic_templates" : [ {
         "string_fields" : {
           "match" : "*",
           "match_mapping_type" : "string",
           "mapping" : {
             "type" : "string", "index" : "analyzed", "omit_norms" : true,
               "fields" : {
                 "raw" : {"type": "string", "index" : "not_analyzed", "ignore_above" : 256}
               }
           }
         }
       } ],
       "properties" : {
         "@version": { "type": "string", "index": "not_analyzed" },
         "geoip"  : {
           "type" : "object",
             "dynamic": true,
             "path": "full",
             "properties" : {
               "location" : { "type" : "geo_point" }
             }
         },
        "actconn": { "type": "long", "index": "not_analyzed" },
        "backend_queue": { "type": "long", "index": "not_analyzed" },
        "beconn": { "type": "long", "index": "not_analyzed" },
        "bytes": { "type": "long", "index": "not_analyzed" },
        "bytes_read": { "type": "long", "index": "not_analyzed" },
        "datastore_latency_from": { "type": "long", "index": "not_analyzed" },
        "datastore_latency_to": { "type": "long", "index": "not_analyzed" },
        "feconn": { "type": "long", "index": "not_analyzed" },
        "response_time": { "type": "long", "index": "not_analyzed" },
        "retries": { "type": "long", "index": "not_analyzed" },
        "srv_queue": { "type": "long", "index": "not_analyzed" },
        "srvconn": { "type": "long", "index": "not_analyzed" },
        "time_backend_connect": { "type": "long", "index": "not_analyzed" },
        "time_backend_response": { "type": "long", "index": "not_analyzed" },
        "time_duration": { "type": "long", "index": "not_analyzed" },
        "time_queue": { "type": "long", "index": "not_analyzed" },
        "time_request": { "type": "long", "index": "not_analyzed" }
       }
    }
  }
}
EOF

# Create IPTables Grok pattern
tee -a /opt/logstash/patterns/IPTABLES <<EOF
NETFILTERMAC %{COMMONMAC:dst_mac}:%{COMMONMAC:src_mac}:%{ETHTYPE:ethtype}
ETHTYPE (?:(?:[A-Fa-f0-9]{2}):(?:[A-Fa-f0-9]{2}))
IPTABLES1 (?:IN=%{WORD:in_device} OUT=(%{WORD:out_device})? MAC=%{NETFILTERMAC} SRC=%{IP:src_ip} DST=%{IP:dst_ip}.*(TTL=%{INT:ttl})?.*PROTO=%{WORD:proto}?.*SPT=%{INT:src_port}?.*DPT=%{INT:dst_port}?.*)
IPTABLES2 (?:IN=%{WORD:in_device} OUT=(%{WORD:out_device})? MAC=%{NETFILTERMAC} SRC=%{IP:src_ip} DST=%{IP:dst_ip}.*(TTL=%{INT:ttl})?.*PROTO=%{INT:proto}?.*)
IPTABLES (?:%{IPTABLES1}|%{IPTABLES2})
EOF

# Restart logstash service
service logstash restart

# Install Apache HTTP
yum install -y --nogpgcheck httpd

# Install and configure Kibana3 frontend
cd /opt/collegis/software
mkdir kibana
cd kibana
curl -O https://download.elasticsearch.org/kibana/kibana/kibana-3.0.1.tar.gz
tar -xvf kibana-3.0.1.tar.gz
sed -i -e 's|elasticsearch: "http://"+window.location.hostname+":9200",|elasticsearch: "http://+window.location.hostname+:80",|' /opt/collegis/software/kibana/kibana-3.0.1/config.js
mkdir -p /var/www/kibana3
cp -R /opt/collegis/software/kibana/kibana-3.0.1/* /var/www/kibana3/
tee -a /etc/httpd/conf.d/kibana3.conf <<EOF
<VirtualHost indexer01.deltakedu.corp:80>
  ServerName indexer01

  DocumentRoot /var/www/kibana3
  <Directory /var/www/kibana3>
    Allow from all
    Options -Multiviews
  </Directory>

  LogLevel debug
  ErrorLog /var/log/httpd/error_log
  CustomLog /var/log/httpd/access_log combined

  # Set global proxy timeouts
  <Proxy http://127.0.0.1:9200>
    ProxySet connectiontimeout=5 timeout=90
  </Proxy>

  # Proxy for _aliases and .*/_search
  <LocationMatch "^/(_nodes|_aliases|.*/_aliases|_search|.*/_search|_mapping|.*/_mapping)$">
    ProxyPassMatch http://127.0.0.1:9200/$1
    ProxyPassReverse http://127.0.0.1:9200/$1
  </LocationMatch>

  # Proxy for kibana-int/{dashboard,temp} stuff (if you don't want auth on /, then you will want these to be protected)
  <LocationMatch "^/(kibana-int/dashboard/|kibana-int/temp)(.*)$">
    ProxyPassMatch http://127.0.0.1:9200/$1$2
    ProxyPassReverse http://127.0.0.1:9200/$1$2
  </LocationMatch>

  <Location />
    AuthType Basic
    AuthBasicProvider file
    AuthName "Restricted"
    AuthUserFile /etc/httpd/conf.d/kibana-htpasswd
    Require valid-user
  </Location>
</VirtualHost>
EOF
service httpd restart

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
echo "Installation has completed!!"
echo -e "To connect to cluster connect to ${red}http://indexer01/kibana${NC}"
echo -e "To connect to individual host use the info below"
echo -e "Connect to ${red}http://$yourfqdn/kibana${NC} or ${red}http://$IPADDY/kibana${NC}"
echo "${yellow}CollegisEducation.com${NC}"
echo "${yellow}Dustin Liddick${NC}"
echo "${yellow}Enjoy!!!${NC}"
