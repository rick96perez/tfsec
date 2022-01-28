import json
import requests
import os
import re
import boto3

raw_data = {}
annotations = []
comments = []
BITBUCKET_USER = os.getenv("BITBUCKET_USERNAME")
BITBUCKET_PASS = os.getenv("BITBUCKET_PASSWORD")
COMMIT_HASH = os.getenv("CODEBUILD_RESOLVED_SOURCE_VERSION")
REPO_INFO = os.getenv("CODEBUILD_SOURCE_REPO_URL")

pattern_text = r'(https:\/\/)(?P<user>\w+)(@bitbucket\.org)\/(?P<organization>\w+)\/(?P<project>.+)\.git'
pattern = re.compile(pattern_text)
match = pattern.match(REPO_INFO)

ORG = match.group('organization')
USER = match.group('user')
PROJECT = match.group('project')

def getSSMParameter(parameter_name, WithDecryption=False):
    client = boto3.client("ssm")
    response = client.get_parameter(Name=parameter_name, WithDecryption=WithDecryption)
    return response["Parameter"]["Value"]

BITBUCKET_USER = getSSMParameter("BITBUCKET_USERNAME")
BITBUCKET_PASS = getSSMParameter("BITBUCKET_PASSWORD", WithDecryption=True)

def parseResults(json_filename):
    y = json.load(open(json_filename))
    for result in y["results"]:
        raw_data[result["external_id"]] = result


def createReport(organization,project,commit_hash,report_name):
    url = f"https://api.bitbucket.org/2.0/repositories/{organization}/{project}/commit/{commit_hash}/reports/{report_name}"
    data = {
        "title": report_name,
        "details": "TFSec Analysis report for Terraform Code.",
        "report_type": "SECURITY",
        "reporter": "AWS CodeBuild",
        "link": "http://www.mysystem.com/reports/001",
        "result": "FAILED",
        "data": [
            {
                "title": "Duration (seconds)",
                "type": "DURATION",
                "value": 0
            },
            {
                "title": "Safe to merge?",
                "type": "BOOLEAN",
                "value": False
            }
        ]
    }
    x = requests.put(url,auth=(BITBUCKET_USER,BITBUCKET_PASS),headers={"Content-Type":"application/json"}, json = data)
    print(x.status_code)
    if x.status_code > 202:
        print(x.text)
    return report_name


def uploadAnnotations(organization,project,commit_hash,report_name):
    url = f"https://api.bitbucket.org/2.0/repositories/{organization}/{project}/commit/{commit_hash}/reports/{report_name}/annotations"
    x = requests.post(url,auth=(BITBUCKET_USER,BITBUCKET_PASS),headers={"Content-Type":"application/json"},data = json.dumps(annotations))
    print(x.status_code)
    if x.status_code > 202:
        print(x.text)


print("Parsing results from TFSec JSON FILE: tfsec.json")
parseResults("tfsec.json")

for key, value in raw_data.items():
    result = {
        "external_id": key,
        "title": value["title"],
        "annotation_type": value["annotation_type"],
        "summary": value["summary"],
        "severity": value["severity"],
        "path": value["path"],
        "line": value["line"]
    }
    annotations.append(result)

report_name = "TFSec: Terraform Security Analysis"

createReport(ORG,PROJECT,COMMIT_HASH,report_name)
uploadAnnotations(ORG,PROJECT,COMMIT_HASH,report_name)