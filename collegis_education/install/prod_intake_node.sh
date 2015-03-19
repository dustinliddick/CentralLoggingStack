#!/bin/bash


# This script configures the node as a intake node which will recieve
# loadbalanced syslogs from the A10. This node is responsible for passing the
# syslogs on to a redis broker on which the indexing nodes will pull and
# process the logs that will be sent to elasticsearch cluster.

set -e
# Setup logging
# Logs stderr and stdout to separate files.
mkdir /opt/collegis/software/logstash java
exec 2> >(tee "/opt/collegis/software/logstash/install_intake_node.err")
exec 1> >(tee "/opt/collegis/software/logstash/install_intake_node.log")

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


# Install Oracle Java 8
echo "Installing Oracle Java 8"
mkdir /opt/collegis/software/java
cd /opt/collegis/software/java
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u20-b26/jdk-8u20-linux-x64.tar.gz"
tar -zxvf jdk-8u20-linux-x64.tar.gz
update-alternatives --install /usr/bin/java java /opt/collegis/software/java/jdk1.8.0_20/bin/java 2

###########
# END PRE #
###########

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
  host => "ceelkred-ob-1p"
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
echo "Installation has completed!!"
echo -e "To connect to cluster connect to ${red}http://logstash/kibana${NC}"
echo -e "To connect to individual host use the info below"
echo -e "Connect to ${red}http://$yourfqdn/kibana${NC} or ${red}http://$IPADDY/kibana${NC}"
echo "${yellow}CollegiseEdcuation.com${NC}"
echo "${yellow}Dustin Liddick${NC}"
echo "${yellow}Enjoy!!!${NC}"
