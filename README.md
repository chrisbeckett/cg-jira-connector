# CloudGuard Jira Connector

## What does it do?

This connector runs as an Azure Function and provides a webhook URL for CloudGuard (formerly Dome9) to send alerts to. This provides simple connectivity to Jira as it sends alert information as issues into a Jira project.

![alt text](https://github.com/chrisbeckett/cg-jira-connector/blob/master/jira-cg-screenshot.png "Jira screenshot")

## How does it work?

CloudGuard runs regular compliance checks ("Continuous Compliance") and any *new* findings are sent as alerts to destinations determined by the compliance policy. In this case, you add a notification configuration and add the webhook URL of the Azure Function as the destination. This sends a JSON payload with the finding details and the Azure Function turns this information into a Jira project issue as a task and sends it to Jira using a REST API call secured by an API key.

![alt text](https://github.com/chrisbeckett/cg-jira-connector/blob/master/Teams%20Connector%20Architecture.png "Architecture overview")

## What do I need to get started?

* A CloudGuard tenant (duh)
* An onboarded cloud account or two
* Continuous Compliance configured
* A Jira account (you sign up for free at Atlassian.net)
* A Jira project ID to send alerts to
* An account in Jira to use to create issue tickets, an API secret and appropriate permissions 
* Python 3.7 or higher
* Git

## Obtaining the code

Run **git clone https://github.com/chrisbeckett/cg-jira-connector.git**

## Jira pre-requisites

- Create a user in Jira for CloudGuard to create tickets (a service account, if you will). Give it a sensible name like "CloudGuard" or something equally as witty
- The documentation for this is at https://confluence.atlassian.com/adminjiraserver/create-edit-or-remove-a-user-938847025.html
- Login as the CloudGuard service account user and create an API token, giving it a sensible name. Write this value down, it's not repeated!
- API tokens are minted at https://id.atlassian.com/manage-profile/security/api-tokens
- Find the Jira Project ID and make a note of the value (https://confluence.atlassian.com/jirakb/how-to-get-project-id-from-the-jira-user-interface-827341414.html)
- Find the Jira Issue Type ID and make a note of the value (https://confluence.atlassian.com/jirakb/finding-the-id-for-issue-types-646186508.html)

## Deploying the Azure Function

Click the "Deploy to Azure" button and fill out the deployment form
- Both the **Azure Function** name and the **Storage Account** name **must be globally unique or deployment will fail (if a new storage account is created)**
- Once the ARM template deployment is complete, open a command prompt and navigate to the **cg-jira-connector** folder
- Install the Azure Functions command line tools (*https://docs.microsoft.com/en-us/azure/azure-functions/functions-run-local?tabs=windows%2Ccsharp%2Cbash*)
- Run **func init**
- Run **func azure functionapp publish *functname*** where the functname is your function name from the "**Deploy to Azure**" workflow
- When this is complete, you will need the HTTP trigger URL (Function overview, "Get Function URL" button)
- When you create the notification in CloudGuard, set the function trigger URL as the Endpoint URL in the "Send to HTTP Endpoint", click "Test" to make sure it is working 
- Create/configure a Compliance Policy and add the HTTP Endpoint you defined earlier as the notification target
- To test the integration, go into Compliance Policies, find the appopriate ruleset and click the "Send All Alerts" icon on the right hand side (up arrow icon), select Notification Type as Webhook and Notification as the Teams Connector Webhook URL from Azure Functions

[![Deploy to Azure](https://azuredeploy.net/deploybutton.png)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fchrisbeckett%2Fcg-jira-connector%2Fmaster%2Fdeployment-template.json)

## Limitations

This release does not support any custom fields or the Jira Service Desk application. This may come in future releases, and then again, it may not. I might also create a CloudFormation for AWS Lambda deployment, it depends how many people complain about it!

