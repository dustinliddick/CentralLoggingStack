#!/bin/bash

set -e
# Setup logging directories
mkdir -p /opt/collegis/software/logstash/install
# Logs stderr and stdout to separate files.
exec 2> >(tee "/opt/collegis/software/logstash/install/install_Logstash-ELK-ES-Cluster-client-node.err")
exec 1> >(tee "/opt/collegis/software/logstash/install/install_Logstash-ELK-ES-Cluster-client-node.log")

# Register server with satellite
curl http://il1satsvr01.deltakedu.corp/pub/bootstrap/bootstrap-server.sh | /bin/bash
rhn-channel --add --channel=clone-epel_rhel6x_x86_64 -u dustin.liddick -p bviad3kq
rhn-channel --add --channel=rhel-x86_64-server-6-rhscl-1 -u dustin.liddick -p bviad3kq

# update box
yum -y --nogpgcheck update

# install apache24
yum -y install httpd24

### Install Kibana ###
cd /opt/collegis/software
mkdir kibana
cd kibana
curl -O https://download.elasticsearch.org/kibana/kibana/kibana-3.0.1.tar.gz
tar -xvf kibana-3.0.1.tar.gz
vi /opt/collegis/software/kibana-3.0.1/config.js
tee -a /opt/collegis/software/kibana-3.0.1/config.js <<EOF
/** @scratch /configuration/config.js/1
 *
 * == Configuration
 * config.js is where you will find the core Kibana configuration. This file contains parameter that
 * must be set before kibana is run for the first time.
 */
define(['settings'],
function (Settings) {


  /** @scratch /configuration/config.js/2
   *
   * === Parameters
   */
  return new Settings({

    /** @scratch /configuration/config.js/5
     *
     * ==== elasticsearch
     *
     * The URL to your elasticsearch server. You almost certainly don't
     * want +http://localhost:9200+ here. Even if Kibana and Elasticsearch are on
     * the same host. By default this will attempt to reach ES at the same host you have
     * kibana installed on. You probably want to set it to the FQDN of your
     * elasticsearch host
     *
     * Note: this can also be an object if you want to pass options to the http client. For example:
     *
     *  +elasticsearch: {server: "http://localhost:9200", withCredentials: true}+
     *
     */
    elasticsearch: "http://10.8.31.50:9200",

    /** @scratch /configuration/config.js/5
     *
     * ==== default_route
     *
     * This is the default landing page when you don't specify a dashboard to load. You can specify
     * files, scripts or saved dashboards here. For example, if you had saved a dashboard called
     * `WebLogs' to elasticsearch you might use:
     *
     * default_route: '/dashboard/elasticsearch/WebLogs',
     */
    default_route     : '/dashboard/file/default.json',

    /** @scratch /configuration/config.js/5
     *
     * ==== kibana-int
     *
     * The default ES index to use for storing Kibana specific object
     * such as stored dashboards
     */
    kibana_index: "kibana-int",

    /** @scratch /configuration/config.js/5
     *
     * ==== panel_name
     *
     * An array of panel modules available. Panels will only be loaded when they are defined in the
     * dashboard, but this list is used in the "add panel" interface.
     */
    panel_names: [
      'histogram',
      'map',
      'goal',
      'table',
      'filtering',
      'timepicker',
      'text',
      'hits',
      'column',
      'trends',
      'bettermap',
      'query',
      'terms',
      'stats',
      'sparklines'
    ]
  });
});
EOF


# We will be using Apache to serve our Kibana installation, so let's move the files
# into an appropriate location. Create a directory with the following command:
mkdir -p /var/www/kibana3

# Copy the Kibana files into your newly-created directory:
cp -R /op/collegis/software/kibana-3.0.1/* /opt/rh/httpd23/root/var/www/kibana3/


cd /opt/collegis/software/kibana/
wget https://assets.digitalocean.com/articles/logstash/kibana3.conf
vi kibana3.conf

# Edit virtual host file and change FQDN to server FQDN;
# change `root` to where we installed Kibana
# copy it to your Apache configuration configuration
cp /opt/collegis/software/kibana/kibana3.conf /opt/rh/httpd24/root/etc/httpd/conf.d/

# Generate loging to access Kibana
htpasswd -c /etc/httpd/conf.d/kibana-htpasswd `username`

# Restart Apache to put changes into effect
service httpd24-httpd restart
chkconfig httpd24-httpd on
## Install Apache HTTP Complete ###
