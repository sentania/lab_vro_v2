import requests, json, urllib3, argparse, ssl, os, sys, time
from pprint import pprint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class dynatracemaintenancemode():
    def __init__(self, slack=False, hosts='', mode='OFF', runenv='', dyna_api_token=''):
        print("{:*^25s}".format("STARTING"))
        
        ######
        # Variables
        ######
        # Get Commandline variables
        args = self.getArgs()

        # Set variables

        ## Slack
        if args.slack:
            slack = args.slack
        
        ## Host List
        if args.hosts:
            hosts = args.hosts
        
        ## Dynatrace Mode
        if not args.mode:
            print("ERROR - Please provide a mode for Dynatrace")
        
        ## Validate mode option
        valid_mode = ['OFF', 'ON']

        if args.mode.upper() not in valid_mode:
            print("ERORR - '{}' is not a validate dynatrace mode option.\nPlease select a valid mode. Use '-h' for script options".format(mode))
            exit(1)
        else:
            mode = args.mode.upper()

        ## Check Dynatrace API tokens were provided
        if not args.prod_api_token:
            print("ERROR - No Dynatrace Production API token was provided. Please enter valid token")
            exit(3)

        if not args.nonprod_api_token:
            print("ERROR - No Dynatrace Non-Production API token was provided. Please enter valid token")
            exit(3)
        
        # Assign commandline variables (if required)
        searchName = hosts
        if not searchName:
            print("ERROR - No host names provided.")
            exit(2)
        
        print("Running with the following variables:\n\tHosts: {}\n\tMode: {}\n".format(hosts, mode))

        # NodeJS Global variables
        nodejs_tenant = "MyTenantA"

        # Dynatrace API Global variables

        # Check for each host provided against Dynatrace
        for host_raw in searchName.split(','):
            host = host_raw.strip()

            print("="*20)
            print("{:^20s}".format(host))
            print("="*20)

            # Check Production
            production = self.dynatraceProduction(host, args.prod_api_token, nodejs_tenant, args.mode)

            # Check Non-Production if not found within production
            if not production:
                print("\n\tNot found in production, moving to Non-Production\n")
                nonproduction = self.dynatraceNonProduction(host, args.nonprod_api_token, nodejs_tenant, args.mode)

                if not nonproduction:
                    print("\n\tNot found in any Dynatrace environment skipping")


        print("{:*^25s}".format("ENDING"))

    # Define all the arguments used within the script
    def getArgs(self):
        parser = argparse.ArgumentParser(
            description='Set host(s) into maintenance mode within Dynatrace',
            usage='use "%(prog)s --help" for more information',
            formatter_class=argparse.RawTextHelpFormatter
        )
        parser.add_argument('-d', '--debug', action="store_true", help='Display more output for debugging')
        parser.add_argument('-s', '--slack', action="store_true", help='Post error output to slack')
        parser.add_argument('-o', '--hosts', help="Enter the host or hosts that you want to filter on.\nUse commas (,) to speperate multiple items\n"
            "Examples:\n\tSingle host: python %(prog)s -o host1\n\tMulitple hosts: python %(prog)s -o host1,host2,host3"
        )
        parser.add_argument('-m', '--mode', help="Select a validate option:\n\tOFF - Turn monitoring mode to OFF\n\tON - Turn monitoring mode to ON")
        parser.add_argument('-p', '--prod_api_token', help="Enter the Dynatrace Prod API token")
        parser.add_argument('-n', '--nonprod_api_token', help="Enter the Dynatrace Non-Prod API token")
        args = parser.parse_args()
        return args

    # Use REST API to get list of servers from Dynatrace
    def getData(self, url_host, url_env_id, dyna_api_token):
        url = "https://{}/e/{}/api/v1/entity/infrastructure/hosts".format(url_host, url_env_id)

        querystring = {"Api-Token":"{}".format(dyna_api_token),"includeDetails":"false","showMonitoringCandidates":"false"}

        payload = ""
        headers = {
            'cache-control': "no-cache",
            }

        response = requests.request("GET", url, data=payload, headers=headers, params=querystring, verify=False)
        if response.status_code != 200:
            print("ERROR - Data retrevial didn't come back 200. Response Code: {}".format(response.status_code))
            exit(4)
        else:
            return response.text

    # Check Production
    def dynatraceProduction(self, host, dyna_api_token, nodejs_tenant, mode):
        print("\tRunning against Dynatrace Production envriornment")
        url_host = "dynatrace.nml.com"
        url_env_id = "24c7f591-f1b4-4d06-af07-8ae7510382e0"
        nodejs_address = "http://ucp-snmptrap.nm.nmfco.com:8080"

        # Get all data from Dynatrace variable
        all_data = self.getData(url_host, url_env_id, dyna_api_token)

        # Convert data to json to allow for easier looping
        data = json.loads(all_data)

        lookup = self.dataParse(data, host, nodejs_address, nodejs_tenant, mode)
        
        if not lookup:
                print("\t\tJob Content -> Host {} was not found in Production.".format(host))
                print("\t\tJob Exit Code -> {}".format(200))
        
        return lookup

    # Check Non-Production
    def dynatraceNonProduction(self, host, dyna_api_token, nodejs_tenant, mode):
        print("\tRunning against Dynatrace Non-Production environment")
        url_host = "dynatrace.nml.com"
        url_env_id = "c1d7b099-bb20-4a65-8742-eacc8e53acc2"
        nodejs_address = "http://ucp-snmptrap.nm.nmfco.com:8081"

        # Get all data from Dynatrace variable
        all_data = self.getData(url_host, url_env_id, dyna_api_token)

        # Convert data to json to allow for easier looping
        data = json.loads(all_data)

        lookup = self.dataParse(data, host, nodejs_address, nodejs_tenant, mode)

        if not lookup:
                print("\t\tJob Content -> Host {} was not found in Non-Production.".format(host))
                print("\t\tJob Exit Code -> {}".format(200))

        return lookup

    # Parse through data
    def dataParse(self, data, host, nodejs_address, nodejs_tenant, mode):
        found = False
        # Loop through host list, and check if it is found in the data
        
        for d in data:
            name = d['displayName']
            entityID = d['entityId']
            if name.startswith(host):
                found = True
                print("\t\tFound -> HOST: {}, ID: {}".format(name, entityID))
                try:
                    nodejs_url = "{}/configuration/{}/host/monitoringMode".format(nodejs_address, nodejs_tenant)
                    postjob = requests.get("{}/configuration/{}/host/monitoringMode".format(nodejs_address, nodejs_tenant),params={'id': entityID, 'value': mode})
                    if postjob.status_code != 200:
                        print("\t\tERROR Response not 200")
                        print("\t\tJob Exit Code -> {}".format(postjob.status_code))
                        print("\t\tJob Content -> {}".format(postjob.content))
                        break
                    else:
                        print("\t\tHost set successfully")
                        print("\t\tJob Exit Code -> {}".format(postjob.status_code))
                        print("\t\tJob Content -> {}".format(postjob.json()))
                        break
                except Exception as e:
                    print("\t\tERROR:\n{}".format(e))

        return found


if __name__ == '__main__':
    dynatracemaintenancemode()