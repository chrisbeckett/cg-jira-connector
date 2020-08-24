import os
import requests
from requests.auth import HTTPBasicAuth
import json
import dateutil.parser
import logging

cg_payload = {
  "status": "Passed",
  "policy": {
    "name": "Webhook.site",
    "description": "Dump payload into webhook site for analysis"
  },
  "findingKey": "984nTOedS7X4/2iVaKMZsQ",
  "bundle": {
    "name": "Azure SQL rules",
    "description": "",
    "id": 169225
  },
  "reportTime": "2020-08-13T10:03:49.482Z",
  "rule": {
    "name": "Azure SQL Server should not be accessible from the internet",
    "ruleId": "",
    "description": "Azure SQL Server PaaS should not be reachable from the internet",
    "remediation": "",
    "complianceTags": "AUTO: sql_disable_public_access",
    "logicHash": "4pA9+gpS5Ek/Nc41MrpM9A",
    "severity": "High"
  },
  "account": {
    "id": "e584d070-3c5a-4a7c-8cf9-c063c5c67ee3",
    "name": "Azure-Prod",
    "vendor": "Azure",
    "dome9CloudAccountId": "0bd33263-9978-45fb-b2b8-3df69b721a3e",
    "organizationalUnitId": "00000000-0000-0000-0000-000000000000",
    "organizationalUnitPath": ""
  },
  "region": "North Europe",
  "entity": {
    "administratorLogin": "chris",
    "fullyQualifiedDomainName": "chrisbesql.database.windows.net",
    "state": "Ready",
    "version": "12.0",
    "resourceGroup": {
      "locks": None,
      "id": "/subscriptions/e584d070-3c5a-4a7c-8cf9-c063c5c67ee3/resourceGroups/rg-sqlpaas",
      "type": "ResourceGroup",
      "name": "rg-sqlpaas",
      "dome9Id": "7|0bd33263-9978-45fb-b2b8-3df69b721a3e|resourcegroup|rg-sqlpaas",
      "accountNumber": "e584d070-3c5a-4a7c-8cf9-c063c5c67ee3",
      "region": "northeurope",
      "source": "db",
      "tags": [],
      "externalFindings": None
    },
    "databases": [
      "tinypaasdb"
    ],
    "elasticPools": [],
    "adAdministrators": [
      {
        "id": "/subscriptions/e584d070-3c5a-4a7c-8cf9-c063c5c67ee3/resourceGroups/rg-sqlpaas/providers/Microsoft.Sql/servers/chrisbesql/administrators/ActiveDirectory",
        "name": "ActiveDirectory",
        "login": "sqladmin@chrisbecheckpoint.onmicrosoft.com",
        "sid": "8ad08680-7436-4795-ba0b-224a3cc1e0a1",
        "tenantId": "42cd311b-d944-41a2-a0e9-32d934f3d0ca"
      }
    ],
    "serverKeys": [
      {
        "id": "/subscriptions/e584d070-3c5a-4a7c-8cf9-c063c5c67ee3/resourceGroups/rg-sqlpaas/providers/Microsoft.Sql/servers/chrisbesql/keys/ServiceManaged",
        "name": "ServiceManaged",
        "creationDate": None,
        "serverKeyType": "ServiceManaged",
        "subregion": None,
        "thumbprint": None,
        "uri": None
      }
    ],
    "encryptionProtectors": [
      {
        "id": "/subscriptions/e584d070-3c5a-4a7c-8cf9-c063c5c67ee3/resourceGroups/rg-sqlpaas/providers/Microsoft.Sql/servers/chrisbesql/encryptionProtector/current",
        "name": "current",
        "serverKey": {
          "id": "/subscriptions/e584d070-3c5a-4a7c-8cf9-c063c5c67ee3/resourceGroups/rg-sqlpaas/providers/Microsoft.Sql/servers/chrisbesql/keys/ServiceManaged",
          "name": "ServiceManaged",
          "creationDate": None,
          "serverKeyType": "ServiceManaged",
          "subregion": None,
          "thumbprint": None,
          "uri": None
        }
      }
    ],
    "failOverGroups": [],
    "firewallRules": [],
    "vnetRules": [],
    "denyPublicNetworkAccess": 'False',
    "isAzurePubliclyAccessable": 'False',
    "isPublic": 'False',
    "locks": [],
    "id": "/subscriptions/e584d070-3c5a-4a7c-8cf9-c063c5c67ee3/resourceGroups/rg-sqlpaas/providers/Microsoft.Sql/servers/chrisbesql",
    "type": "SQLServer",
    "name": "chrisbesql",
    "dome9Id": "7|0bd33263-9978-45fb-b2b8-3df69b721a3e|resourcegroup|rg-sqlpaas|sqlserver|chrisbesql",
    "accountNumber": "e584d070-3c5a-4a7c-8cf9-c063c5c67ee3",
    "region": "northeurope",
    "source": "db",
    "tags": [],
    "externalFindings": None
  },
  "remediationActions": []
}

jira_project_id='10000'
jira_issue_type_id='10002'
jira_api_endpoint_url = 'https://cbeckett.atlassian.net/rest/api/3/issue/'
jira_api_token = '6tYZyyhSYO4ZCK2xifd9A759'
jira_api_email_address = 'chrisbeckett999@googlemail.com'
jira_auth = HTTPBasicAuth("chrisbeckett999@googlemail.com", "6tYZyyhSYO4ZCK2xifd9A759")


cg_finding_name = cg_payload.get('rule', {}).get('name')
cg_finding_description = cg_payload.get('rule', {}).get('description')
cg_finding_entity_name = cg_payload.get('entity', {}).get('name')
cg_finding_bundle_name = cg_payload.get('bundle', {}).get('name')
cg_finding_date_time = cg_payload.get('reportTime')
cg_finding_alert_id = cg_payload.get('findingKey')
cg_formatted_date_time = dateutil.parser.parse(cg_finding_date_time)
cg_alert_timestamp = cg_formatted_date_time.ctime()

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
                        "type": "paragraph",
                        "content": [
                            {
                            "type": "text",
                            "text": "Entity Name - ",
                            "marks": [
                                {
                                "type": "strong"
                                }
                            ],
                            "text": cg_finding_entity_name
                            }
                        ]
                        },
                        {
                        "type": "paragraph",
                        "content": [
                            {
                            "type": "text",
                            "text": "Finding Description - ",
                            "marks": [
                                {
                                "type": "strong"
                                }
                            ]
                            }
                        ]
                        },
                        {
                        "type": "paragraph",
                        "content": [
                            {
                            "type": "text",
                            "text": "Compliance Bundle - ",
                            "marks": [
                                {
                                "type": "strong"
                                }
                            ]
                            }
                        ]
                        },
                        {
                        "type": "paragraph",
                        "content": [
                            {
                            "type": "text",
                            "text": "Finding Date/Time - ",
                            "marks": [
                                {
                                "type": "strong"
                                }
                            ]
                            }
                        ]
                        },
                        {
                        "type": "paragraph",
                        "content": [
                            {
                            "type": "text",
                            "text": "Alert ID - ",
                            "marks": [
                                {
                                "type": "strong"
                                }
                            ]
                            }
                        ]
                        },
                        {
                        "type": "paragraph",
                        "content": []
                        }
                    ]
                    },
    "issuetype": {"name": "Task"},
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

print(json.dumps(json.loads(r.text), sort_keys=True, indent=4, separators=(",", ": ")))