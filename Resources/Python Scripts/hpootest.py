import requests, json, time, urllib3, sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "https://ootest.nml.com:8443/oo/rest/v2/executions"
basic_auth = "dWNwX3VzZXI6dWNwdXNlckAzMjE="

hostName = sys.argv[1]
mode = sys.argv[2]

def getToken():
    session = requests.Session()
    session.headers.update({'Connection': 'keep-alive', 'authorization':"Basic %s" % basic_auth})
    params = {'X-CSRF-TOKEN': 'Fetch'}

    response = session.get(url, params=params, verify=False)
    token = response.headers['X-CSRF-TOKEN']
    rawcookie = response.headers['Set-Cookie'].split(',')[1].strip().split(';')[0]

    return session, token, rawcookie

def setMaintenanceMode(session, hostName, mode, token, rawcookie):
    payload = """
    {\n
        \"flowUuid\": \"0b373ebc-f2be-40c4-b417-0bdb13c3ca14\",\n
        \"runName\": \"ucp_maintenanceMode\",\n
        \"logLevel\": \"STANDARD\",\n
        \"inputs\": {\n
            \"Nodelist\": \"%s\",\n
            \"MaintenanceMode\": \"%s\",\n
            \"IM_CM_Entry\": \"UCP:server deletion\",\n
            \"SuccessEmailTo\": \"etm-ovo-admin-offs@northwesternmutual.com\",\n
            \"FailureEmailTo\": \"etm-ovo-admin-offs@northwesternmutual.com\"\n
        }\n
    }
    """ % (hostName, mode)

    setcookie = "X-CSRF-TOKEN: %s Set-Cookie: %s;" % (token, rawcookie)

    headers = {
        'content-type': "application/json",
        'authorization': "Basic %s" % basic_auth,
        'Cookie': setcookie
    }

    response = session.post(url, data=payload, headers=headers, verify=False)

    responseCode = response.status_code

    return responseCode, response.text

def checkJobStatus(jobID):
    print "Waiting 5 seconds for job to process"
    time.sleep(5)

    print "Checking Job status..."
    running = True

    while running:
        jobStatus = hpooJobStatus(jobID)
        data = json.loads(jobStatus)

        if data[0]['status'].lower() == 'running':
            print "\tJob still running, waiting 5 seconds"
            time.sleep(5)
        else:
            print "\tJob done running. Status: %s" % data[0]['status']
            running = False

def hpooJobStatus(jobID):

    headers = {
        'content-type': "application/json",
        'authorization': "Basic %s" % basic_auth
    }
    url = "https://ootest.nml.com:8443/oo/rest/v2/executions/%s/summary" % jobID
    response = requests.get(url, headers=headers, verify=False)
    responseCode = response.status_code

    if str(responseCode) == '200':
        return response.text
    elif str(responseCode) == '404':
        print "\Job not found"
        exit()

print "Get Access Token..."
session, token, rawcookie = getToken()

print "Start Maintenance Mode Job..."
jobResponseCode, jobResponse = setMaintenanceMode(session, hostName, mode, token, rawcookie)

if str(jobResponseCode) != '201':
    print "\n\tHPOO Job not submitted. Code: %s" % (jobResponseCode)
    print "\tFull Response:"
    print jobResponse
    exit(1)
else:
    print "\n\tCode: %s" % jobResponseCode
    print "\tHPOO Job job submitted successfully"
    print "\tJob ID: %s\n" % jobResponse

#checkJobStatus(jobResponse)

print "Closing Session..."
session.close()

exit(0)