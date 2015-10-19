#!/bin/bash

# Preform ES 1.4 update to 1.5 and install Shield for security

# Setup logging
set -e


# Start the Shield install
cd /usr/share/elasticsearch
/usr/share/elasticsearch/bin/plugin -i elasticsearch/shield/latest


#Add a user called es_admin and assign the admin role
bin/shield/esusers useradd es_admin -r admin


#Add a user called es_logstash and assign the logstash role
bin/shield/esusers useradd es_logstash -p c0llegis123 -r logstash,transport_client

# Message Authentication
#  verifies that a message has not been tampered with; ystem key is a symmetric
#  key, the same key must be on every node in the cluster. Copy the key to
#  every node in the cluster after generating it.
#/usr/share/elasticsearch/bin/shield/syskeygen
#scp /usr/share/elasticsearch/config/shield/system_key
