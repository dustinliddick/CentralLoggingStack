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
mkdir -p /opt/collegis/software/logstash java
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

echo "adding new database to satelite server"
curl http://il1satsvr01.deltakedu.corp/pub/scripts/install/plain/AddSatelliteServerToHostFile.sh | /bin/bash
sleep 5
echo ""
echo ""
echo "${red}checking see status of hostname adition${NC}"
cat /etc/hosts
echo ""
echo ""
echo "now sleeping after satelite hostfile addition for 10s"
sleep 10
########################################################################################################################################################
##                    ##################################################################################################################################
## PRE-INSTALL STEPS  ##################################################################################################################################
##                    ##################################################################################################################################
########################################################################################################################################################
# Register Server to satellite server
curl http://il1satsvr01.deltakedu.corp/pub/bootstrap/bootstrap-server.sh | /bin/bash

# Modify subscription channels for server in satellite
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
#/opt/logstash/bin/plugin install contrib

# Enable logstash start on bootup
chkconfig logstash on

# Create Logstash configuration file
tee -a /etc/logstash/conf.d/logstash.conf <<EOF
#########
# INPUT #
#########
input {
        redis {
                host => "10.38.2.61"
                data_type => "list"
                key => "logstash"
                threads => 4
        }
}
########################
# FILTERING / TAGGING  #
########################
filter {
        if [type] == "syslog" {
                mutate {
                        add_tag => [ "RedHat" ]
                }
        }
        if [type] == "firewall" {
                        mutate {
                                        add_tag => [ "cisco-asa" ]
                        }
        }
        if [type] == "VMware" {
                mutate {
                        add_tag => "VMware"
                }
        }
        if [type] == "vCenter" {
                mutate {
                        add_tag => "vCenter"
                }
        }
        if [type] == "eventlog" {
                mutate {
                        add_tag => [ "WindowsEventLog" ]
                }
        }
        if [type] == "apache" {
                mutate {
                       add_tag => [ "apache" ]
                }
        }
        if [type] == "iis" {
                mutate {
                        add_tag => [ "IIS" ]
                }
        }
}
############################################
# First layer of normal log parsing #
############################################

##########
# SYSLOG #
##########
filter {
        if [type] == "RedHat" {
                grok {
                        match => [ "message", "<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" ]
                        add_field => [ "received_at", "%{@timestamp}" ]
                        add_field => [ "received_from", "%{host}" ]
                }
                dns {
                        reverse => [ "hostname" ]
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
        }
}
############
# EventLog #
############
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
#############
# Cisco ASA #
#############
filter {
                if "cisco-asa" in [tags] {
                                grok {
                                        patterns_dir => "/opt/logstash/patterns"
                                        break_on_match => false
                                match => [ "message", "%{CISCO_TAGGED_SYSLOG}"
                                        ]
                                }
                                grok {
                                        match => [
                                        "message", "%{CISCOFW106001}",
                                        "message", "%{CISCOFW106006_106007_106010}",
                                        "message", "%{CISCOFW106014}",
                                        "message", "%{CISCOFW106015}",
                                        "message", "%{CISCOFW106021}",
                                        "message", "%{CISCOFW106023}",
                                        "message", "%{CISCOFW106100}",
                                        "message", "%{CISCOFW110002}",
                                        "message", "%{CISCOFW302010}",
                                        "message", "%{CISCOFW302013_302014_302015_302016}",
                                        "message", "%{CISCOFW302020_302021}",
                                        "message", "%{CISCOFW305011}",
                                        "message", "%{CISCOFW313001_313004_313008}",
                                        "message", "%{CISCOFW313005}",
                                        "message", "%{CISCOFW402117}",
                                        "message", "%{CISCOFW402119}",
                                        "message", "%{CISCOFW419001}",
                                        "message", "%{CISCOFW419002}",
                                        "message", "%{CISCOFW500004}",
                                        "message", "%{CISCOFW602303_602304}",
                                        "message", "%{CISCOFW710001_710002_710003_710005_710006}",
                                        "message", "%{CISCOFW713172}",
                                        "message", "%{CISCOFW733100}"
                                        ]
                                }
                                geoip {
                                        #type => "stingray"
                                        add_tag => [ "geoip" ]
                                        source => "src_ip"
                                        database => "/opt/logstash/vendor/geoip/GeoLiteCity.dat"
                                }
}
                                mutate {
                                        tags => [ "geoip" ]
                                                # 'coords' will be kept, 'tmplat' is temporary.
                                                # Both of these new fields are strings.
                                        add_field => [ "coords", "%{geoip.longitude}",
                                                "tmplat", "%{geoip.latitude}" ]
                                }
                                mutate {
                                        tags => [ "geoip" ]
                                                # Merge 'tmplat' into 'coords'
                                        merge => [ "coords", "tmplat" ]
                                }
                                mutate {
                                        tags => [ "geoip" ]
                                                # Convert our new array of strings back to float
                                                convert => [ "coords", "float" ]
                                                # Delete our temporary latitude field
                                        remove => [ "tmplat" ]
                                }
#Takes the 4-tuple of source address, destination address, destination port, and protocol and does a SHA1 hash to fingerprint the flow.  This is a useful
#way to be able to do top N terms queries on flows, not just on one field.
        if "cisco-asa" in [tags] and [src_ip] and [dst_ip] {
      fingerprint {
        concatenate_sources => true
        method => "SHA1"
        key => "logstash"
        source => [ "src_ip", "dst_ip", "dst_port", "protocol" ]
      }
    }
        if [geoip][city_name] == "" { mutate { remove_field => "[geoip][city_name]" } }
        if [geoip][continent_code] == "" { mutate { remove_field => "[geoip][continent_code]" } }
        if [geoip][country_code2] == "" { mutate { remove_field => "[geoip][country_code2]" } }
        if [geoip][country_code3] == "" { mutate { remove_field => "[geoip][country_code3]" } }
        if [geoip][country_name] == "" { mutate { remove_field => "[geoip][country_name]" } }
        if [geoip][latitude] == "" { mutate { remove_field => "[geoip][latitude]" } }
        if [geoip][longitude] == "" { mutate { remove_field => "[geoip][longitude]" } }
        if [geoip][postal_code] == "" { mutate { remove_field => "[geoip][postal_code]" } }
        if [geoip][region_name] == "" { mutate { remove_field => "[geoip][region_name]" } }
        if [geoip][time_zone] == "" { mutate { remove_field => "[geoip][time_zone]" } }
# Parse the date
                                date {
                                        match => ["timestamp",
                                                                "MMM dd HH:mm:ss",
                                                                "MMM d HH:mm:ss",
                                                                "MMM dd yyyy HH:mm:ss",
                                                                "MMM d yyyy HH:mm:ss"
                                                                ]
                                }
                        }
############################
# Second pass at filtering #
############################
## RHEL login filter ##
#filter {
#               if [tag] == "RedHat" {
#                               grok {
#                                               type => "syslog"
#                                               match => "message", "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host_target} sshd\[%{BASE10NUM}\]: Failed password for invalid user %{USERNAME:username} from %{IP:src_ip} port %{BASE10NUM:port} ssh2"
#                                               add_tag => "ssh_brute_force_attack"
#                                       }
#                               grok {
#                                               type => "syslog"
#                                               match => "message", "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host_target} sudo: pam_unix\(sudo:auth\): authentication failure; logname=%{USERNAME:logname} uid=%{BASE10NUM:uid} euid=%{BASE10NUM:euid} tty=%{TTY:tty} ruser=%{USERNAME:ruser} rhost=(?:%{HOSTNAME:remote_host}|\s*) user=%{USERNAME:user}"
#                                               add_tag => "sudo_auth_failure"
#                                       }
#                               grok {
#                                               type => "syslog"
#                                               match => "message", "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host_target} sshd\[%{BASE10NUM}\]: Failed password for %{USERNAME:username} from %{IP:src_ip} port %{BASE10NUM:port} ssh2"
#                                               add_tag => "ssh_failed_login"
#                                       }
#                               grok {
#                                               type => "syslog"
#                                               match => "messge", "%{SYSLOGTIMESTAMP:timestamp} %{HOSTNAME:host_target} sshd\[%{BASE10NUM}\]: Accepted password for %{USERNAME:username} from %{IP:src_ip} port %{BASE10NUM:port} ssh2"
#                                               add_tag => "ssh_sucessful_login"
#                                       }
#                       }
#       }
############################
# Nagios Filter for alerts #
############################

##############################################################
# Microsoft IIS logging....Use NXLOG for client side logging #
##############################################################


###################################################################################################################################
# The below filter section will be used to remove unnecessary fields to keep ES memory cache from filling up with useless data    #
# The below filter section will be where you would want to comment certain types or tags out if trying to isolate a logging issue #
###################################################################################################################################


######################################################################################################################################################
#### Multicast discovery mode ####                                                                                                                   #
# Send output to the ES cluster logstash-cluster using a predefined template                                                                         #
# The following settings will be used during the initial setup which will be used for using multicast ES nodes                                       #
# When changing to unicast discovery mode you need to comment out the following section and configure the unicast discovery mode in the next section #
######################################################################################################################################################

output {
        elasticsearch {
                cluster => "dev_es_cluster"
                host => "ceelkes-ob-1d"
                port => "9300"
                protocol => "node"
                flush_size => 1
                workers => 12
                manage_template => true
                template => "/opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json"
        }
EOF

# Update elasticsearch-template for logstash
mv /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json.orig
tee -a /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json <<EOF
{
  "template" : "logstash-*",
  "settings" : {
    "index.refresh_interval" : "5s"
    "index.number_of_shards" : 5,
        "index.number_of_replicas" : 1,
        "index.query.default_field" : "@message",
        "index.routing.allocation.total_shards_per_node" : 3,
        "index.auto_expand_replicas": false
  },
  "mappings" : {
    "_default_": {
            "_all": { "enabled": false },
            "_source": { "compress": false },
            "dynamic_templates": [
                {
                    "fields_template" : {
                        "mapping": { "type": "string", "index": "not_analyzed" },
                        "path_match": "@fields.*"
                    }
                },
                {
                    "tags_template" : {
                        "mapping": { "type": "string", "index": "not_analyzed" },
                        "path_match": "@tags.*"
                    }
                }
            ],
         "properties" : {
         "@version": { "type": "string", "index": "not_analyzed" },
         "@fields": { "type": "object", "dynamic": true, "path": "full" },
         "@source" : { "type" : "string", "index" : "not_analyzed" },
         "@source_host" : { "type" : "string", "index" : "not_analyzed" },
         "@source_path" : { "type" : "string", "index" : "not_analyzed" },
         "@timestamp" : { "type" : "date", "index" : "not_analyzed" },
         "@type" : { "type" : "string", "index" : "not_analyzed" },
         "@message" : { "type" : "string", "analyzer" : "whitespace" }
             }
        }
    }
}
view raw
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
