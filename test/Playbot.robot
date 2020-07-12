*** Settings ***
Library  /Users/abhaybhargav/Documents/code/python/Playbot/threat_playbook/Playbot.py  test-projet  newwebapp2  threatplaybook=http://138.197.204.163:81

*** Variables ***
${URL}  localhost
${BANDIT}  /Users/abhaybhargav/Documents/code/python/RoboBandit/test/bandit.json
${NODE}  /Users/abhaybhargav/Documents/code/appsecng/devsecops/report.json
${ZAP}  /Users/abhaybhargav/Downloads/zap-report.json

*** Test Cases ***
Login User
    login  admin@admin.com  supersecret

# # Push Bandit
# #     manage bandit results  ${BANDIT}

# Push Node
#     manage nodejsscan results  ${NODE}

# Push Zap
#     manage zap results  ${ZAP}  ${URL}

Push NPMAudit
    manage npmaudit results  npm_audit.json