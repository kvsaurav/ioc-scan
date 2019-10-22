# !/usr/bin/env python

import requests
import json
import time

"""
    Reference:
        https://github.com/PayloadSecurity/VxAPI
        https://www.hybrid-analysis.com/docs/api/v2#/
"""


class HybridAnalysisConnector(object):

    def __init__(self, **kwargs):

        self.api_key = 'atgfp8i970f7394bpqfm6sv31e17c459iwzm1k616f7d72dez10arjmdf802dd09'
        self.timestamp = {'_timestamp': int(time.time())}

    # action used for quick url scan
    def action_quick_scan_url(self, url, **kwargs):
        
        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/quick-scan/\
                           url-for-analysis'
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'User-Agent': 'Falcon Sandbox'}
            # post_data = {"scan_type": "all", "url": url,
            #              "no_share_third_party": "true",
            #              "allow_community_access": "true"}
            post_data = {"url": url}
            response = requests.post(endpoint_url, data=post_data,
                                     params=self.timestamp, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for quick scan file
    def action_quick_scan_file(self, filepath, **kwargs):
        
        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/quick-scan/\
                            file'
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'User-Agent': 'Falcon Sandbox'}
            file = {"file": open(filepath, "rb")}
            post_data = {"scan_type": "all",
                         "no_share_third_party": "true",
                         "allow_community_access": "true"}
            response = requests.post(endpoint_url, files=file, data=post_data,
                                     params=self.timestamp, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for quick scan file from url
    def action_quick_scan_file_from_url(self, url, file_type, **kwargs):
        
        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/quick-scan/\
                            url-to-file'
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'Content-Type': 'application/x-www-form-urlencoded',
                       'User-Agent': 'Falcon Sandbox'}
            post_data = {"scan_type": "all", "url": url, "type": file_type,
                         "no_share_third_party": "true",
                         "allow_community_access": "true"}
            response = requests.post(endpoint_url, data=post_data,
                                     params=self.timestamp, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for check hash reputation
    def action_search_hash(self, hash1, **kwargs):

        try:
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'Content-Type': 'application/x-www-form-urlencoded',
                       'User-Agent': 'Falcon Sandbox'}
            # post_data = {"scan_type": "all", "hash": hash1,
            #              "no_share_third_party": "true",
            #              "allow_community_access": "true"}
            post_data = {"hash": hash1}
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/search/hash'

            response = requests.post(endpoint_url, data=post_data,
                                     params=self.timestamp, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for submit file to sandbox
    def action_sandbox_submit_file(self, filepath, **kwargs):
        
        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/submit/file'
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'User-Agent': 'Falcon Sandbox'}
            file = {"file": open(filepath, "rb")}
            post_data = {"scan_type": "all",
                         "no_share_third_party": "true",
                         "allow_community_access": "true",
                         "environment_id": "120"}
            # post_data = {"scan_type": "all", "environment_id": "120"}
            response = requests.post(endpoint_url, files=file, data=post_data,
                                     params=self.timestamp, headers=headers,
                                     )
            if response.status_code == 200 or response.status_code == 201:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for submit file from url
    def action_sandbox_submit_file_from_url(self, url, **kwargs):

        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/submit/\
                            url-to-file'
            headers = {"Accept": "application/json", "api-key": self.api_key,
                       "Content-Type": 'application/x-www-form-urlencoded',
                       "User-Agent": "Falcon Sandbox"}
            post_data = {"scan_type": "all", "url": url,
                         "no_share_third_party": "true",
                         "allow_community_access": "true",
                         "environment_id": "120"}
            response = requests.post(endpoint_url, data=post_data,
                                     params=self.timestamp, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for submit url
    def action_sandbox_submit_url(self, url, **kwargs):
        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/submit/\
                            url-for-analysis'
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'Content-Type': 'application/x-www-form-urlencoded',
                       'User-Agent': 'Falcon Sandbox'}
            post_data = {"scan_type": "all", "url": url,
                         "no_share_third_party": "true",
                         "allow_community_access": "true",
                         "environment_id": "120"}
            response = requests.post(endpoint_url, data=post_data,
                                     params=self.timestamp, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for submit hash for url
    def action_sandbox_submit_hash_for_url(self, url, **kwargs):

        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/submit/\
                            hash-for-url'
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'Content-Type': 'application/x-www-form-urlencoded',
                       'User-Agent': 'Falcon Sandbox'}
            post_data = {"url": url}
            response = requests.post(endpoint_url, data=post_data,
                                     params=self.timestamp, headers=headers)
            if response.status_code == 200 or response.status_code == 201:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for get report status
    def action_sandbox_report_status(self, job_id, **kwargs):

        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/report/'\
                           + job_id + '/state'
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'User-Agent': 'Falcon Sandbox'}
            response = requests.get(endpoint_url, headers=headers)
            if response.status_code == 200:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for report summary
    def action_sandbox_report_summary(self, job_id, **kwargs):

        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/report/'\
                           + job_id + '/summary'
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'User-Agent': 'Falcon Sandbox'}
            response = requests.get(endpoint_url, params=self.timestamp,
                                    headers=headers)
            if response.status_code == 200:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for fetching various type of report
    # need premium api for access this action
    def action_sandbox_report_get_type(self, job_id, report_type, **kwargs):

        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/report/'\
                           + job_id + '/file/json'
            headers = {'Accept': 'application/'+report_type,
                       'api-key': self.api_key, 'User-Agent': 'Falcon Sandbox'}
            response = requests.get(endpoint_url, headers=headers)
            if response.status_code == 200:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e), 'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

    # action used for fetch screenshots
    # need premium api for access this action
    def action_sandbox_report_get_screenshot(self, job_id, **kwargs):
        
        try:
            endpoint_url = 'https://www.hybrid-analysis.com/api/v2/report/'\
                           + job_id + '/screenshots'
            headers = {'Accept': 'application/json', 'api-key': self.api_key,
                       'User-Agent': 'Falcon Sandbox'}
            response = requests.get(endpoint_url, params=self.timestamp,
                                    headers=headers)
            if response.status_code == 200:
                try:
                    return {'result': response.json(),
                            'execution_status': 'SUCCESS'}
                except Exception as e:
                    return {'result': str(e),
                            'execution_status': 'ERROR'}
            else:
                return {'result': response.json(), 'execution_status': 'ERROR'}
        except Exception as e:
            return {'result': str(e), 'execution_status': 'ERROR'}

# hybrid= HybridAnalysisConnector().action_search_hash("95673b0f968c0f55b32204361940d184")
# print hybrid