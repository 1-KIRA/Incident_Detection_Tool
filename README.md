# Security Incident Automation  (SIDA) tool

With the increasing prevalence of cybercrime worldwide, organizations face a higher risk of falling victim to a range of cybersecurity threats that can pose significant dangers to their operations. To combat this, the Security Incident Automation tool (SIDA) Tool has been developed, which leverages log event correlation techniques to analyze logs and detect security incidents. The tool then displays the results in a user-friendly dashboard, helping organizations to quickly identify any incidents that have occurred within their IT infrastructure. Built using Python Programming Language and ELK stack, the ASID Tool can help organizations uncover weaknesses in their IT infrastructure, allowing them to take proactive steps to improve their cybersecurity defenses.


# Installation Requirements

Download ELK stack from here
Elasticsearch: https://www.elastic.co/downloads/elasticsearch

Kibana: https://www.elastic.co/downloads/kibana

Logstash: https://www.elastic.co/downloads/logstash

Filebeat: https://www.elastic.co/downloads/beats/filebeat

Python3: https://www.python.org/downloads/

Configure ELK stack, filebeat and winlogbeat.

# Installation of tool
1. Clone the repository.
2.  Install requirements.txt by using pip install -r /path/to/requirements.txt
3. Edit index names in main.py

# Note: 
If you want to edit rules you can only edit the values present in rules.yaml 
