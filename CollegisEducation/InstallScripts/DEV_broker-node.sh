#!/bin/bash


# This script configures the node as a redis broker sending to logstash on backend processors

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

##################### Logstash Front-End Broker Setup ###########################################

# Install Logstash
yum install --nogpgcheck -y logstash

# Enable logstash start on bootup
chkconfig logstash on

# Create Logstash configuration file
tee -a /etc/logstash/conf.d/logstash.conf <<EOF
input {
        tcp {
                type => "syslog"
                port => "5544"
        }
}
input {
        tcp {
                type => "firewall"
                port => "5545"
        }
}
input {
        tcp {
                type => "VMware"
                port => "1514"
        }
}
input {
        tcp {
                type => "vCenter"
                port => "1515"
        }
}
input {
        tcp {
                type => "Netscaler"
                port => "1517"
        }
}
input {
        tcp {
                type => "eventlog"
                port => "3515"
                format => "json"
        }
}
input {
        tcp {
                type => "iis"
                port => "3525"
                codec => "json_lines"
        }
}
output {
  redis {
  host => "elkindex-ob-1p"
  data_type => "list"
  key => "logstash"
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

# Create Cisco Grok pattern
tee -a /opt/logstash/patterns/IPTABLES <<EOF
# NetScreen firewall logs
NETSCREENSESSIONLOG %{SYSLOGTIMESTAMP:date} %{IPORHOST:device} %{IPORHOST}: NetScreen device_id=%{WORD:device_id}%{DATA}: start_time=%{QUOTEDSTRING:start_time} duration=%{INT:duration} policy_id=%{INT:policy_id} service=%{DATA:service} proto=%{INT:proto} src zone=%{WORD:src_zone} dst zone=%{WORD:dst_zone} action=%{WORD:action} sent=%{INT:sent} rcvd=%{INT:rcvd} src=%{IPORHOST:src_ip} dst=%{IPORHOST:dst_ip} src_port=%{INT:src_port} dst_port=%{INT:dst_port} src-xlated ip=%{IPORHOST:src_xlated_ip} port=%{INT:src_xlated_port} dst-xlated ip=%{IPORHOST:dst_xlated_ip} port=%{INT:dst_xlated_port} session_id=%{INT:session_id} reason=%{GREEDYDATA:reason}

#== Cisco ASA ==
CISCO_TAGGED_SYSLOG ^<%{POSINT:syslog_pri}>%{CISCOTIMESTAMP:timestamp}( %{SYSLOGHOST:sysloghost})?: %%{CISCOTAG:ciscotag}:
CISCOTIMESTAMP %{MONTH} +%{MONTHDAY}(?: %{YEAR})? %{TIME}
CISCOTAG [A-Z0-9]+-%{INT}-(?:[A-Z0-9_]+)
# Common Particles
CISCO_ACTION Built|Teardown|Deny|Denied|denied|requested|permitted|denied by ACL|discarded|est-allowed|Dropping|created|deleted
CISCO_REASON Duplicate TCP SYN|Failed to locate egress interface|Invalid transport field|No matching connection|DNS Response|DNS Query|(?:%{WORD}\s*)*
CISCO_DIRECTION Inbound|inbound|Outbound|outbound
CISCO_INTERVAL first hit|%{INT}-second interval
CISCO_XLATE_TYPE static|dynamic
# ASA-2-106001
CISCOFW106001 %{CISCO_DIRECTION:direction} %{WORD:protocol} connection %{CISCO_ACTION:action} from %{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port} flags %{GREEDYDATA:tcp_flags} on interface %{GREEDYDATA:interface}
# ASA-2-106006, ASA-2-106007, ASA-2-106010
CISCOFW106006_106007_106010 %{CISCO_ACTION:action} %{CISCO_DIRECTION:direction} %{WORD:protocol} (?:from|src) %{IP:src_ip}/%{INT:src_port}(\(%{DATA:src_fwuser}\))? (?:to|dst) %{IP:dst_ip}/%{INT:dst_port}(\(%{DATA:dst_fwuser}\))? (?:on interface %{DATA:interface}|due to %{CISCO_REASON:reason})
# ASA-3-106014
CISCOFW106014 %{CISCO_ACTION:action} %{CISCO_DIRECTION:direction} %{WORD:protocol} src %{DATA:src_interface}:%{IP:src_ip}(\(%{DATA:src_fwuser}\))? dst %{DATA:dst_interface}:%{IP:dst_ip}(\(%{DATA:dst_fwuser}\))? \(type %{INT:icmp_type}, code %{INT:icmp_code}\)
# ASA-6-106015
CISCOFW106015 %{CISCO_ACTION:action} %{WORD:protocol} \(%{DATA:policy_id}\) from %{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port} flags %{DATA:tcp_flags}  on interface %{GREEDYDATA:interface}
# ASA-1-106021
CISCOFW106021 %{CISCO_ACTION:action} %{WORD:protocol} reverse path check from %{IP:src_ip} to %{IP:dst_ip} on interface %{GREEDYDATA:interface}
# ASA-4-106023
CISCOFW106023 %{CISCO_ACTION:action} %{WORD:protocol} src %{DATA:src_interface}:%{IP:src_ip}(/%{INT:src_port})?(\(%{DATA:src_fwuser}\))? dst %{DATA:dst_interface}:%{IP:dst_ip}(/%{INT:dst_port})?(\(%{DATA:dst_fwuser}\))?( \(type %{INT:icmp_type}, code %{INT:icmp_code}\))? by access-group %{DATA:policy_id} \[%{DATA:hashcode1}, %{DATA:hashcode2}\]
# ASA-5-106100
CISCOFW106100 access-list %{WORD:policy_id} %{CISCO_ACTION:action} %{WORD:protocol} %{DATA:src_interface}/%{IP:src_ip}\(%{INT:src_port}\)(\(%{DATA:src_fwuser}\))? -> %{DATA:dst_interface}/%{IP:dst_ip}\(%{INT:dst_port}\)(\(%{DATA:src_fwuser}\))? hit-cnt %{INT:hit_count} %{CISCO_INTERVAL:interval} \[%{DATA:hashcode1}, %{DATA:hashcode2}\]
# ASA-6-110002
CISCOFW110002 %{CISCO_REASON:reason} for %{WORD:protocol} from %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port}
# ASA-6-302010
CISCOFW302010 %{INT:connection_count} in use, %{INT:connection_count_max} most used
# ASA-6-302013, ASA-6-302014, ASA-6-302015, ASA-6-302016
CISCOFW302013_302014_302015_302016 %{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection %{INT:connection_id} for %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port}( \(%{IP:src_mapped_ip}/%{INT:src_mapped_port}\))?(\(%{DATA:src_fwuser}\))? to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}( \(%{IP:dst_mapped_ip}/%{INT:dst_mapped_port}\))?(\(%{DATA:dst_fwuser}\))?( duration %{TIME:duration} bytes %{INT:bytes})?(?: %{CISCO_REASON:reason})?( \(%{DATA:user}\))?
# ASA-6-302020, ASA-6-302021
CISCOFW302020_302021 %{CISCO_ACTION:action}(?: %{CISCO_DIRECTION:direction})? %{WORD:protocol} connection for faddr %{IP:dst_ip}/%{INT:icmp_seq_num}(?:\(%{DATA:fwuser}\))? gaddr %{IP:src_xlated_ip}/%{INT:icmp_code_xlated} laddr %{IP:src_ip}/%{INT:icmp_code}( \(%{DATA:user}\))?
# ASA-6-305011
CISCOFW305011 %{CISCO_ACTION:action} %{CISCO_XLATE_TYPE:xlate_type} %{WORD:protocol} translation from %{DATA:src_interface}:%{IP:src_ip}(/%{INT:src_port})?(\(%{DATA:src_fwuser}\))? to %{DATA:src_xlated_interface}:%{IP:src_xlated_ip}/%{DATA:src_xlated_port}
# ASA-3-313001, ASA-3-313004, ASA-3-313008
CISCOFW313001_313004_313008 %{CISCO_ACTION:action} %{WORD:protocol} type=%{INT:icmp_type}, code=%{INT:icmp_code} from %{IP:src_ip} on interface %{DATA:interface}( to %{IP:dst_ip})?
# ASA-4-313005
CISCOFW313005 %{CISCO_REASON:reason} for %{WORD:protocol} error message: %{WORD:err_protocol} src %{DATA:err_src_interface}:%{IP:err_src_ip}(\(%{DATA:err_src_fwuser}\))? dst %{DATA:err_dst_interface}:%{IP:err_dst_ip}(\(%{DATA:err_dst_fwuser}\))? \(type %{INT:err_icmp_type}, code %{INT:err_icmp_code}\) on %{DATA:interface} interface\.  Original IP payload: %{WORD:protocol} src %{IP:orig_src_ip}/%{INT:orig_src_port}(\(%{DATA:orig_src_fwuser}\))? dst %{IP:orig_dst_ip}/%{INT:orig_dst_port}(\(%{DATA:orig_dst_fwuser}\))?
# ASA-4-402117
CISCOFW402117 %{WORD:protocol}: Received a non-IPSec packet \(protocol= %{WORD:orig_protocol}\) from %{IP:src_ip} to %{IP:dst_ip}
# ASA-4-402119
CISCOFW402119 %{WORD:protocol}: Received an %{WORD:orig_protocol} packet \(SPI= %{DATA:spi}, sequence number= %{DATA:seq_num}\) from %{IP:src_ip} \(user= %{DATA:user}\) to %{IP:dst_ip} that failed anti-replay checking
# ASA-4-419001
CISCOFW419001 %{CISCO_ACTION:action} %{WORD:protocol} packet from %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}, reason: %{GREEDYDATA:reason}
# ASA-4-419002
CISCOFW419002 %{CISCO_REASON:reason} from %{DATA:src_interface}:%{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port} with different initial sequence number
# ASA-4-500004
CISCOFW500004 %{CISCO_REASON:reason} for protocol=%{WORD:protocol}, from %{IP:src_ip}/%{INT:src_port} to %{IP:dst_ip}/%{INT:dst_port}
# ASA-6-602303, ASA-6-602304
CISCOFW602303_602304 %{WORD:protocol}: An %{CISCO_DIRECTION:direction} %{GREEDYDATA:tunnel_type} SA \(SPI= %{DATA:spi}\) between %{IP:src_ip} and %{IP:dst_ip} \(user= %{DATA:user}\) has been %{CISCO_ACTION:action}
# ASA-7-710001, ASA-7-710002, ASA-7-710003, ASA-7-710005, ASA-7-710006
CISCOFW710001_710002_710003_710005_710006 %{WORD:protocol} (?:request|access) %{CISCO_ACTION:action} from %{IP:src_ip}/%{INT:src_port} to %{DATA:dst_interface}:%{IP:dst_ip}/%{INT:dst_port}
# ASA-6-713172
CISCOFW713172 Group = %{GREEDYDATA:group}, IP = %{IP:src_ip}, Automatic NAT Detection Status:\s+Remote end\s*%{DATA:is_remote_natted}\s*behind a NAT device\s+This\s+end\s*%{DATA:is_local_natted}\s*behind a NAT device
# ASA-4-733100
CISCOFW733100 \[\s*%{DATA:drop_type}\s*\] drop %{DATA:drop_rate_id} exceeded. Current burst rate is %{INT:drop_rate_current_burst} per second, max configured rate is %{INT:drop_rate_max_burst}; Current average rate is %{INT:drop_rate_current_avg} per second, max configured rate is %{INT:drop_rate_max_avg}; Cumulative total count is %{INT:drop_total_count}
#== End Cisco ASA ==
EOF

# Restart logstash service
service logstash restart

# Logrotate job for logstash
#tee -a /etc/logrotate.d/logstash <<EOF
#/var/log/logstash.log {
#        monthly
#        rotate 12
#        compress
#        delaycompress
#        missingok
#        notifempty
#        create 644 root root
#}
#EOF

# All Done
echo "Installation has completed!!"
echo -e "To connect to cluster connect to ${red}http://logstash/kibana${NC}"
echo -e "To connect to individual host use the info below"
echo -e "Connect to ${red}http://$yourfqdn/kibana${NC} or ${red}http://$IPADDY/kibana${NC}"
echo "${yellow}CollegiseEdcuation.com${NC}"
echo "${yellow}Dustin Liddick${NC}"
echo "${yellow}Enjoy!!!${NC}"
