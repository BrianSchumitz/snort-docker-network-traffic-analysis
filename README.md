# Malware Detection with Snort

## Introduction

#### Contributors
* Megan Steinmasel
* Brian Schumitz

#### Project Goals
* See how Snort IDS works in detecting malware from a web server.
* See if the project triggers any rules from various rulesets and logs them.

#### Project Overview
* We were given this project to continue from the REU 2023 students. We followed the instructions on how to run the project outlined [here](https://github.com/MSUSEL/reu-2023-snort). The previous result that the REU 2023 students achieved was a Snort alert that triggered a ping. The REU 2023 students noted that logging alerts with custom Snort rules worked best for them the best, so that is what we did moving forward.
* The REU 2023 students created individual docker containers for each web server and mp4 malware file. The way the project runs is outlined below in the section **Running the Project**.

#### Tools
* Snort 3.1.65.0
* Docker 20.10.21
* Wireshark 3.6.2



## Environment Setup

#### Snort Configuration
* Navigate to */usr/local/etc/snort/snort_defaults.lua*
  * *snort_defaults.lua* defines the external defaults for Snort
  * Open *snort_defaults.lua* in a text editor with sudo privileges and make the following changes:
    * Set the *$RULE_PATH* variable to */usr/local/etc/rules*
* Navigate to */usr/local/etc/snort/snort.lua*
  * *snort.lua* is the configuration file for Snort
  * Open *snort.lua* in a text editor with sudo privileges and make the following changes:
    * In Section 1:
      * Set the *$HOME_NET* variable to *‘172.17.0.1’*
        * *172.17.0.1* is the network of the docker0 network
      * Keep the *$EXTERNAL_NET* variable to *‘any’*
    * In Section 5:
      * Add the rulesets that Snort will traverse: 
        * *variables = default_variables, rules = [[ include $RULE_PATH/snort3-community.rules include $RULE_PATH/local.rules include $RULE_PATH/test.rules ]]*
    * In Section 7:
      * Uncomment the line below to print Snort alerts in a one-line format to the *alert_fast.txt* output file
        * *alert_fast ={file = true, packet = false, limit = 10}*

#### Creating Docker Containers and Web Server
* Download the file, Dockerfile, and the folder 'web-server' into a directory (name this directory 'benign')
* Open a terminal window into this directory 
* Add the benign video to the 'html' folder
* With docker installed, run the following command in the terminal window:
  * *docker build -t malware:SHA-256 .*
    * Replace *SHA-256* with a given malware signature 
    * Do not forget the '.' because it is part of the command



## Snort

#### Snort Rules
* Snort rulesets are found in */usr/local/etc/rules*
* The Snort community ruleset was installed from the official Snort website
* The rulesets in the */usr/local/etc/rules* include:
    * *local.rules*
    * *snort3-community-rules*
    * *test.rules*
* *test.rules* are the additional rules that we (Megan and Brian) created
* Snort ruleset configuration is outlined in Section 5 of the Snort configuration

#### Log File
* The log file is located in */logs/alert_fast.txt*
* The log file configuration is outlined in Section 7 of the Snort configuration 



## Running the Project

#### Methodology
* Open a new terminal window:
  * To list the current running docker container:
    * *docker ps -a*
  * To remove any running docker containers:
    * *docker rm 7b7*
      * Where *7b7* is the first three letters of the docker ID
  * Run the docker container with:
    * *docker run -d -p 8000:80 -name website malicious:SHA-256*
      * Where *SHA-256* is the malware signature
* Open another terminal window:
  * Start listening with Wireshark with the following command:
    * *sudo wireshark*
* Open another terminal window:
  * Run Snort with the following command:
     * *sudo snort -c /usr/local/etc/snort/snort.lua -l /home/snort-froup/logs*
* Go to localhost 8000 and press the download button
* Check the log file


## New Additions

#### Description
* These new additions were created by Megan Steinmasel and Brian Schumitz. The goal in adding these additions is to see if we could create new Snort rules that detect the malware from the web server.

#### Additions
* Ruleset
    * We added our own ruleset named *test.rules* (found in */usr/local/etc/rules*) and added our own rules that we generated through [Snorpy](http://snorpy.cyb3rs3c.net/). We also added some rules by [ELITEWOLF](https://github.com/nsacyber/ELITEWOLF). 
* Configuration
  * In Section 5 of the snort.lua configuration file, we included the new rule path to the *test.rules*:
    * *variables = default_variables, rules = [[ include $RULE_PATH/snort3-community.rules include $RULE_PATH/local.rules include $RULE_PATH/test.rules ]]*


## Conclusion

#### Results
* We re-ran the project with our new *test.rules* ruleset and that resulted in an alert from the following rule:
    * *alert tcp any any -> $HOME_NET any (msg: “MALWARE TRAFFIC”; content: “SHA-256”; sid: 10001; rev: 1;)*
      * *SHA-256* being the malware signature
* This rule used content matching to detect malware from the web server and logged the alert in *alert_fast.txt*.

#### Discussion
* What Worked
    * The REU 2023 students noted in their documentation that logging alerts with custom rules worked for them, so that is the approach we took and we successfully logged an alert that content matched the malware. Therefore, content matching with custom Snort rules worked.
* What Did Not Work
    * We had differing results based on how we spun up the docker containers. When using 'docker run', the malware would not fully download onto the computer but the content matching Snort alert would trigger. When using 'docker-compose up', the malware would be downloaded onto the computer but the Snort alert would not trigger. Given this, the REU 2023 students noted in their documentation that the project is supposed to run using docker run.
