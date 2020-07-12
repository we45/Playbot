import os
from robot.api import logger
import json
from sys import exit
import requests
from base64 import b64encode
# import xmltodict


class Playbot(object):
    ROBOT_LIBRARY_SCOPE = 'GLOBAL'
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

    def __init__(self, project, target, threatplaybook='http://localhost:9000'):
        """
        Initialize Threatplaybook API Connection
        :param project: Project Name
        :param target: Target Name
        :param threatplaybook: URL of ThreatPlaybook API Server. [default: http://localhost:9000]
        """
        self.threatplaybook = threatplaybook
        self.project = project
        self.target = target
        logger.info(msg=project)

    def login(self, email, password):
        try:
            url = '{}/api/login'.format(self.threatplaybook)
            resp = requests.post(
                url=url, json={"email": email, "password": password})
            if resp.status_code == 200:
                response = resp.json()
                if response.get('success'):
                    self.token = response.get('data').get('token')
                    logger.info(msg='Login Success: {}'.format(
                        response.get("token")))
                elif response.get('error'):
                    raise Exception("Invalid response while attempting to login: {}".format(
                        response.get('error')))
                else:
                    raise Exception(
                        "Invalid response while attempting to login")
            else:
                logger.warn(msg='Error while logging in')
                raise Exception("Invalid response while attempting to login")
        except BaseException as be:
            logger.error(be)
            raise Exception("Exception while attempting to login")

    def create_project(self):
        url = "{}/api/project/create".format(self.threatplaybook)
        project_req = requests.post(url, json={"name": self.project}, headers={
                                    "Authorization": self.token})
        if project_req.status_code != 200:
            logger.error(project_req.json())
            return Exception("Unable to create Project")
        logger.info("Successfully created project: '{}'".format(self.project))

    def create_target(self, target_url):
        url = "{}/api/target/create".format(self.threatplaybook)
        target_create_query = requests.post(url, headers={"Authorization": self.token}, json={
            "name": self.target,
            "url": target_url,
            "project": self.project
        })
        if target_create_query.status_code != 200:
            logger.error(target_create_query.json())
            raise Exception("Unable to create target")

        logger.info("Succesfully created target: '{}'".format(self.target))

    def create_scan(self, tool):
        url = "{}/api/scan/create".format(self.threatplaybook)
        create_scan = requests.post(url, headers={"Authorization": self.token}, json={
            "tool": tool,
            "target": self.target
        })
        if create_scan.status_code != 200:
            logger.error(create_scan.json())
            raise Exception("Unable to create {} scan".format(tool))

        return create_scan.json()

    def manage_bandit_results(self, result_file):
        results = json.load(open(result_file, 'r'))
        if results:
            create_scan_query = self.create_scan("bandit")
            if 'data' in create_scan_query:
                scan = create_scan_query.get('data').get('name')
                severity_dict = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
                url = "{}/api/vulnerability/create".format(self.threatplaybook)
                for vul_result in results.get('results', []):
                    vul_dict = {
                        'name': str(vul_result.get('test_name', '')),
                        'description': str(vul_result.get('issue_text', '')),
                        'scan': scan,
                        'cwe': int(vul_result.get('cwe', 0)),
                        'severity': int(severity_dict.get(vul_result.get('issue_severity', 'MEDIUM'))),
                    }

                    if 'observation' in vul_result:
                        vul_dict['observation'] = vul_dict.get('observation')
                    if 'remediation' in vul_result:
                        vul_dict['remediation'] = vul_dict.get('remediation')
                    if 'line_number' in vul_result and 'filename' in vul_result:
                        vul_dict['evidences'] = [{
                            'line_num': vul_result.get('line_number'),
                            'url': vul_result.get('filename'),
                            'log': b64encode(vul_result.get('code').encode()).decode()
                        }]

                    response = requests.post(url, json=vul_dict, headers={
                                             "Authorization": self.token})
                    if response.status_code != 200:
                        raise Exception("Unable to create vulnerability")
            else:
                logger.error("Unable to obtain scan name")
        else:
            logger.warn(msg="Could not fetch results from file")
            exit(1)

    def manage_nodejsscan_results(self, result_file):
        results = json.load(open(result_file, 'r'))
        url = "{}/api/vulnerability/create".format(self.threatplaybook)
        if results:
            create_scan_query = self.create_scan("nodejsscan")

            if 'nodejs' in results:
                if 'data' in create_scan_query:
                    scan = create_scan_query.get('data').get('name')
                    sast = results.get('nodejs')
                    for vname, vdict in sast.items():
                        vul_dict = {
                            "name": vname,
                            "scan": scan,
                            "description": vdict.get('metadata').get('description')
                        }
                        cwe = str(vdict.get('metadata').get(
                            'cwe')).split(":")[0].split("-")[1]
                        evidences = []
                        files = vdict.get('files')
                        for single_file in files:
                            single_evid = {
                                "url": single_file.get("file_path"),
                                "line_number": single_file.get('match_lines')[0],
                                "log": b64encode(single_file.get('match_string').encode()).decode()
                            }
                            evidences.append(single_evid)
                        vul_dict['cwe'] = int(cwe)
                        vul_dict['evidences'] = evidences
                        response = requests.post(url, json=vul_dict, headers={
                            "Authorization": self.token})
                        if response.status_code != 200:
                            raise Exception(
                                "Unable to add Vulnerability from NodeJSScan")

    def manage_npmaudit_results(self, result_file):
        severity_dict = {'moderate': 2, 'low': 1, 'critical': 3, 'high': 3}
        url = "{}/api/vulnerability/create".format(self.threatplaybook)
        with open(result_file, 'r') as jfile:
            results = json.loads(jfile.read())
        if results:
            create_scan_query = self.create_scan("npmaudit")
            if 'data' in create_scan_query:
                scan = create_scan_query.get('data').get('name')
                if 'advisories' not in results:
                    logger.info("No Advisories in report")
                    pass
                else:
                    for sl, vul_result in results.get('advisories').items():
                        vul_dict = {
                            'name': vul_result.get('title'),
                            'description': vul_result.get('overview', ''),
                            'scan': scan,
                            'cwe': int(vul_result.get('cwe').split('-')[1], 0),
                            'severity': int(severity_dict.get(vul_result.get('severity', 'low'))),
                        }
                        
                        evidences = []
                        for finding in vul_result.get('findings'):
                            evid = {
                                "param": finding.get('version', '0.0'),
                                "url": ":".join(finding.get('paths'))
                            }
                            evidences.append(evid)
                        vul_dict['evidences'] = evidences
                        resp = requests.post(url, json=vul_dict, headers={
                                             "Authorization": self.token})
                        if resp.status_code != 200:
                            raise Exception(
                                "Unable to create NPM Audit Finding")

            else:
                logger.error("Unable to create scan for NPM Audit")

    def manage_zap_results(self, result_file, target_url):
        results = json.load(open(result_file, 'r'))
        url = "{}/api/vulnerability/create".format(self.threatplaybook)
        if results:
            create_scan_query = self.create_scan('zap')
            if 'data' in create_scan_query:
                scan = create_scan_query.get('data').get('name')
                if scan:
                    alerts = None
                    pre_alerts = results['Report']['Sites']
                    if isinstance(pre_alerts, list):
                        for pre in pre_alerts:
                            if target_url in pre['Host']:
                                alerts = pre
                    if isinstance(pre_alerts, dict):
                        alerts = pre_alerts
                    alerts = alerts['Alerts']['AlertItem']
                    if alerts:
                        if isinstance(alerts, dict):
                            alerts = [alerts]
                        if isinstance(alerts, list):
                            for vul_result in alerts:
                                severity_dict = {
                                    'High': 3, 'Medium': 2, 'Low': 1}
                                vul_dict = {
                                    'name': vul_result.get('Alert'),
                                    'tool': 'zap',
                                    'description': vul_result.get('Desc'),
                                    'scan': scan,
                                    'cwe': int(vul_result.get('CWEID')),
                                    'severity': int(severity_dict.get(vul_result.get('RiskDesc'), 0)),
                                    'remediation': vul_result.get('Solution', "")
                                }
                                if 'Item' in vul_result:
                                    vul_dict['evidences'] = []
                                if isinstance(vul_result['Item'], dict):
                                    vul_result['Item'] = [vul_result['Item']]
                                for item in vul_result['Item']:
                                    evidence = {
                                        'url': item.get('URI'),
                                        'param': item.get('Param'),
                                        'log': b64encode('RequestHeader: {}  RequestBody: {}  ResponseHeader: {}'.format(
                                            item.get('RequestHeader', ''),
                                            item.get('RequestBody', ''),
                                            item.get('ResponseHeader', '')).encode('UTF-8')).decode(),
                                        'attack': item.get('Attack', "")
                                    }
                                    vul_dict['evidences'].append(evidence)
                                response = requests.post(url, json=vul_dict, headers={
                                    "Authorization": self.token})

                                if response.status_code != 200:
                                    raise Exception(
                                        "Unable to add result to Database for OWASP ZAP")

    def create_new_scan(self, tool):
        url = "{}/api/scan/create".format(self.threatplaybook)
        create_scan = requests.post(url, headers={"Authorization": self.token}, json={
            "tool": tool,
            "target": self.target
        })
        if create_scan.status_code != 200:
            logger.error(create_scan.json())
            raise Exception("Unable to create {} scan".format(tool))

        return create_scan.get('data').get('name')

    def create_new_vulnerability(self, vul_dict):
        url = "{}/api/vulnerability/create".format(self.threatplaybook)
        if 'scan' not in vul_dict and 'name' not in vul_dict:
            raise Exception("Mandatory fields 'scan' and 'name' not in Result")

        vul_push = {
            "scan": vul_dict.get('scan'),
            "name": vul_dict.get('name'),
            "cwe": vul_dict.get('cwe', 0),
            "severity": int(vul_dict.get('severity', 0)),
        }

        if 'description' in vul_dict:
            vul_push['description'] = vul_dict.get('description')

        if 'observation' in vul_dict:
            vul_push['observation'] = vul_dict.get('observation')

        if 'remediation' in vul_dict:
            vul_push['remediation'] = vul_dict.get('remediation')

        evid = []
        if 'evidences' in vul_dict:
            if not isinstance(vul_dict.get('evidences'), list):
                raise Exception("Evidences have to be list definition")
            else:
                for single_evid in vul_dict.get('evidences'):
                    svid = {
                        "url": single_evid.get('url', ''),
                    }
                    if 'param' in single_evid:
                        svid['param'] = single_evid.get('param')

                    if 'log' in single_evid:
                        svid["log"] = b64encode(
                            single_evid.get('log').encode()).decode()

                    evid.append(svid)
        if evid:
            vul_push['evidences'] = evid

        resp = requests.post(url, json=vul_push, headers={
                             "Authorization": self.token})
        if resp.status_code != 200:
            logger.error(resp.content())

        logger.info("Successfully pushed Vulnerability Data")

    # def manage_nmap_results(self, result_file):
    #     with open(result_file, 'r') as xfile:
    #         content = xfile.read()
    #     xdict = json.loads(json.dumps(xmltodict.parse(content, process_namespaces=False)))
    #     url = "{}/api/vulnerability/create".format(self.threatplaybook)
    #     if xdict:
    #         create_scan_query = self.create_scan('nmap')
    #         if 'data' in create_scan_query:
    #             scan = create_scan_query.get('data').get('name')
    #             if scan:
    #                 ports = xdict.get('nmaprun').get('host').get('ports').get('port')
    #                 if ports and isinstance(ports, list):
    #                     for single in ports:
    #                         if 'script' in single and single.get('script'):
    #                             for ss in single.get('script'):
    #                                 vul_dict = {
    #                                     "name": ss.get("@id"),
    #                                     "cwe": 16,
    #                                     "scan": scan,
    #                                     "severity": 1
    #                                 }
    #                                 evidences = [{
    #                                     "url": "{}/{}".format(single.get('@protocol'), single.get('@portid'))
    #                                 }]
    #                                 if 'elem' in ss and isinstance(ss.get('elem'), dict):
    #                                     evidences[0]['log'] = b64encode(ss.get('elem').get('#text').encode()).decode()
    #                                 elif 'elem' in ss:
    #                                     evidences[0]['log'] = b64encode(ss.get('elem').encode()).decode()
                                    
    #                                 vul_dict['evidences'] = evidences
    #                                 logger.warn(vul_dict)
    #                                 resp = requests.post(url, json=vul_dict, headers={"Authorization": self.token})
                                    
    #                                 if resp.status_code != 200:
    #                                     logger.error(resp.json())
                                    

    #             else:
    #                 raise Exception("Unable to create scan for nmap")    
