## Install Readme ##
yum install -nogpgcheck install git
mkdir /opt/collegis/software/
cd /opt/collegis/software/
git clone https://github.com/dustinliddick/elk.git
chmod +x /opt/collegis/software/elk/collegis_education/install/*.sh

## Steps ##
Determin the node that you are setting up in the stack, run that install node
shell script. If you are expanding horizontally, adjust the needed script to
change the host name and then run.

## Notes ##
Issue I have ran into is with DNS names in the conf.js file for Kibana. I had
been using DNS names and when I went to try and load the dashboard, it wouldnt
find anything. I changed to IP address and all started to work.
