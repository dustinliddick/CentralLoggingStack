#!/bin/bash

# Preform ES 1.4 update to 1.5 and install Shield for security

# Setup logging
set -e

# Logs stderr and stdout to separate files.
#mkdir -p /opt/collegis/software/elasticsearch
exec 2> >(tee "/home/dustin.liddick/rolling_update.err")
exec 1> >(tee "/home/dustin.liddick/elasticsearch/rolling_update.log")

# Setting colors for output
red="$(tput setaf 1)"
yellow="$(tput bold ; tput setaf 3)"
NC="$(tput sgr0)"

# Download and install the Public Signing Key
rpm --import https://packages.elasticsearch.org/GPG-KEY-elasticsearch
sleep 5
echo "GPG key import done...Preparing ES 1.5 Repository"
sleep 5

# Move old elk repo and create new for application
mv /etc/yum.repos.d/elasticsearch.repo /etc/yum.repos.d/elasticsearch_repo-1.4.old
cat <<EOF> /etc/yum.repos.d/elasticsearch_1.5.repo
[elasticsearch-1.5]
name=Elasticsearch repository for 1.5.x packages
baseurl=http://packages.elasticsearch.org/elasticsearch/1.5/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
EOF

curl -XPUT localhost:9200/_cluster/settings -d '{"transient" : {"cluster.routing.allocation.enable" : "none"}}'
slep 3
curl -XPOST 'http://localhost:9200/_cluster/nodes/_local/_shutdown'
echo "Please confirm that all shards are correctly reallocated"
sleep 30
clear

# Update ES to new version
echo "updating elasticsearch now"
sleep 3
yum install -y elasticsearch

# Start the Shield install
/usr/share/elasticsearch/bin/plugin -i elasticsearch/shield/latest



# Message Authentication
#  verifies that a message has not been tampered with; ystem key is a symmetric
#  key, the same key must be on every node in the cluster. Copy the key to
#  every node in the cluster after generating it.
/usr/share/elasticsearch/bin/shield/syskeygen
scp /usr/share/elasticsearch/config/shield/system_key
