#!/bin/bash

#Provided by @mrlesmithjr at EveryThingShouldBeVirtual.com
#Modified by Dustin Liddick for CollegisEducation

# This script configures the node as a logstash indexer, Elasticsearch client node in logstash-cluster

############
# PRE-WORK #
############
set -e
# Setup logging directories
mkdir -p /opt/collegis/software/logstash/install
# Logs stderr and stdout to separate files.
exec 2> >(tee "/opt/collegis/software/logstash/install/install_Logstash-ELK-ES-Cluster-client-node.err")
exec 1> >(tee "/opt/collegis/software/logstash/install/install_Logstash-ELK-ES-Cluster-client-node.log")

# Setting colors for output
red="$(tput setaf 1)"
yellow="$(tput bold ; tput setaf 3)"
NC="$(tput sgr0)"

###########
# END PRE #
###########


#################
# START INSTALL #
#################
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
# Pre-Reqs
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
# install python
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
                host => "172.16.7.232"
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
# Filtering for SSH logins either failed or successful
#filter {
#        if "syslog" in [tags] {
#                if [syslog_program] == "sshd" {
#                        if "Failed password" in [message] {
#                                grok {
#                                        break_on_match => false
#                                        match => [
#                                                "message", "invalid user %{DATA:UserName} from %{IP:src_ip}",
#                                                "message", "for %{DATA:UserName} from %{IP:src_ip}"
#                                        ]
#                                }
#                                mutate {
#                                        add_tag => [ "SSH_Failed_Login" ]
#                                }
#                        }
#                        if "Accepted password" in [message] {
#                                grok {
#                                        match => [
#                                                "message", "for %{DATA:UserName} from %{IP:src_ip}"
#                                        ]
#                                }
#                                mutate {
#                                        add_tag => [ "SSH_Successful_Login" ]
#                                }
#                        }
#                        geoip {
#                                source => "src_ip"
#                                target => "geoip"
#                                add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
#                                add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
#                        }
#                        mutate {
#                                convert => [ "[geoip][coordinates]", "float" ]
#                        }
#                }
#        }
#}
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

# Restart logstash service
service logstash restart

# Install Apache HTTP
yum install -y --nogpgcheck httpd


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
