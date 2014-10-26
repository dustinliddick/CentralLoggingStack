## Install Readme ##
yum install -nogpgcheck install git
mkdir /opt/collegis/software/ELK
cd /opt/collegis/software/ELK
git clone https://github.com/dustinliddick/CentralLoggingStack.git
chmod +x /opt/collegis/software/ELK/CentralLoggingStack/CollegisEducation/InstallScripts/*.sh

## Steps ##
If you are setting up a stack, run the MasterData node shell script first, then followed
by the indexer then broker in that order. If you are expanding horizontally, adjust the needed
script to change the host name and then run.

## Notes ##
Issue I have ran into is with DNS names in the conf.js file for Kibana. I had been using DNS names and when I went to try and load the dashboard, it wouldnt find anything. I changed to IP address and all started to work.