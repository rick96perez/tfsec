import json
import requests

raw_data = {}

annotations = []
comments = []
BITBUCKET_USER = "rperezfo"
BITBUCKET_PASS = "mf6mP6v7BhGsJgKUvDa5"

def parseResults(json_filename):
    y = json.load(open(json_filename))
    for result in y["results"]:
        raw_data[result["external_id"]] = result


parseResults("test.json")
# print(raw_data)
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
                "value": 14
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
    


org = "PSDevMain"
proj = "niceincontact-terraform"
commit = "bfac4a5e4d8fff26f57037f7298641ff21c65cf9"

report_name = "Python Test Report 2"
createReport(org,proj,commit,report_name)
uploadAnnotations(org,proj,commit,report_name)