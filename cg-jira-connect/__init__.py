import logging
import os
import requests
from requests.auth import HTTPBasicAuth
import json
import dateutil.parser
import azure.functions as func

#Set Jira parameters
jira_project_id=os.getenv('JIRA_PROJECT_ID')
jira_issue_type_id=os.getenv('JIRA_ISSUE_TYPE_ID')
jira_api_endpoint_url = os.getenv('JIRA_API_ENDPOINT_URL')
jira_api_token = os.getenv('JIRA_API_TOKEN')
jira_api_email_address = os.getenv('JIRA_API_EMAIL')
jira_auth = HTTPBasicAuth(jira_api_email_address, jira_api_token)

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('CloudGuard Jira Connector HTTP trigger function processed a request.')
    logging.info('Code version : 24082020-1445 - Initial release')
    try:
        source_message = req.get_json()
        logging.info(f'Finding alert message content is - {source_message}')
        if source_message:
            #Set CloudGuard findings parameters
            cg_finding_name = source_message.get('rule', {}).get('name')
            cg_finding_description = source_message.get('rule', {}).get('description')
            cg_finding_entity_name = source_message.get('entity', {}).get('name')
            cg_finding_bundle_name = source_message.get('bundle', {}).get('name')
            cg_finding_date_time = source_message.get('reportTime')
            cg_finding_alert_id = source_message.get('findingKey')
            cg_formatted_date_time = dateutil.parser.parse(cg_finding_date_time)
            cg_alert_timestamp = cg_formatted_date_time.ctime()

            logging.info(f'Building Jira issue ticket...')
            # Set header parameters for Jira HTTP POST
            jira_request_headers = {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            }

            jira_payload = json.dumps( {
              #"update": {},
              "fields": {
                "project": {"id": jira_project_id}, 
                "summary": "CloudGuard Finding : " + cg_finding_name,
                "description": {
                                "version": 1,
                                "type": "doc",
                                "content": [
                                    {
                                    "type": "rule"
                                    },
                                    {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                        "type": "text",
                                        "text": "Entity name - " + cg_finding_entity_name + "\n" + "Finding description - " + cg_finding_description \
                                            + "\n" + "Compliance bundle - " + cg_finding_bundle_name \
                                            + "\n" + "Finding date and time - " + cg_alert_timestamp \
                                            + "\n" + "Alert ID - " + cg_finding_alert_id + "\n"
                                    }
                                ]
                            },
                            {
                            "type": "rule"
                            },
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": "View latest CloudGuard alerts",
                                        "marks": [
                                            {
                                                "type": "strong",
                                                "type": "link",
                                                "attrs": {"href":"http://https://secure.dome9.com/v2/alerts/findings"},
                                                
                                            }    
                                        ]
                                    }
                                ]
                            }
                        ]
                    },  
                "issuetype": {"name": "Task"},
                "labels": ["CloudGuard-Finding"]
              }
            }
            )
            r= requests.request(
              "POST",
              jira_api_endpoint_url,
              data=jira_payload,
              headers=jira_request_headers,
              auth=jira_auth
            )

            logging.info(json.dumps(json.loads(r.text), sort_keys=True, indent=4, separators=(",", ": ")))
            msg="Operation complete - Teams message successful"
            logging.info(f'{msg}')
            return func.HttpResponse(status_code=200)

    except Exception as e:
                        logging.info(f'Bad request. {e}')
                        return func.HttpResponse(status_code=400)

