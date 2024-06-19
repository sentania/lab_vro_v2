import requests, argparse, json, time, re, getpass
from pprint import pprint
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

##
## Global Variables
##
adlist = []

def auth_token(version, campus):
    if version == "3":
        url = "https://%s.nm.nmfco.com:5000/v3/auth/tokens" % campus

        payload = "{\n\"auth\":{\n\"identity\":{\n\"methods\":[\n\"password\"\n],\n\"password\":{\n\"user\": {\n\"name\":\"ucpadmin\",\n\"domain\":{\n\"name\":\"local\"\n},\n\"password\": \"Looney!toons1\"\n}\n}\n}\n}\n}"
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            }

        response = requests.request("POST", url, data=payload, headers=headers, verify=False)

        if response.status_code == 201:
            print "\tSuccussfully authenticated with 'ucpadmin', and retreived auth v3 token"
            return response.headers['X-Subject-Token']
        else:
            print "\t!!!ERROR!!! authenticating for v3: %s" % response
            exit()
    elif version == "2":
        url = "https://%s.nm.nmfco.com:5000/v2.0/tokens" % campus

        payload = "{\n\"auth\":{\n\"tenantName\":\"admin\",\n\"passwordCredentials\":{\n\t\"username\":\"ucpadmin\",\n\t\"password\":\"Looney!toons1\"\n}\n}\n}"
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            }

        response = requests.request("POST", url, data=payload, headers=headers, verify=False)

        if response.status_code == 200:
            print "\tSuccussfully authenticated with 'ucpadmin', and retreived auth 2 token"
            response_data = response.json()
            auth_token = response_data['access']['token']['id']
            return auth_token
        else:
            print "\t!!!ERROR!!! authenticating for V2.0: %s" % response

def create_project(auth_token, pro_name, campus):
    url = "https://%s.nm.nmfco.com:5000/v3/projects" % campus

    pro_des = "Created via Python"
    pro_domain = "default"

    payload = "{\n\"project\":{\n\"description\": \"%s\",\n\"domain_id\": \"%s\",\n \"enabled\": true,\n\"is_domain\": false,\n\"name\": \"%s\"\n}\n}" % (pro_des, pro_domain, pro_name)

    headers = {
        'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
        }

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)

    if response.status_code == 201:
        print "\tProject '%s' successfully created" % pro_name
        project_data = response.json()
        project_id = project_data['project']['id']
        return project_id
    elif response.status_code == 409:
        print "\tProject with name (%s) already exists" % pro_name
        exit()
    else:
        print "\t!!!ERROR!!! creating project: %s" % response
        exit()

def roleids(auth_token, campus):
    url = "https://%s.nm.nmfco.com:5000/v3/roles" % campus

    headers = {
        'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
    }

    response = requests.request("GET", url, headers=headers, verify=False)

    if response.status_code == 200:
        response_data = response.json()
        roles = response_data['roles']
        for r in roles:
            name = r['name']
            id   = r['id']

            if name.lower() == 'admin':
                admin_id = id
            elif name.lower() == '_member_':
                member_id = id

        return admin_id, member_id
    else:
        print "\t!!!ERROR!!! roles response: %s" % response
        exit()

def assign_group_to_project(auth_token, project_id, adlist, pro_name, campus):
    admin_id, member_id = roleids(auth_token, campus)

    print "\tAdmin ID: %s\n\tMember ID: %s" % (admin_id, member_id)

    for a in adlist:
        a.strip()

        url = "https://%s.nm.nmfco.com:5000/v3/projects/%s/groups/%s/roles/%s" % (campus, project_id, a, member_id)

        headers = {
            'content-type': "application/json",
            'x-auth-token': auth_token,
            'cache-control': "no-cache",
        }

        response = requests.request("PUT", url, headers=headers, verify=False)

        if response.status_code == 204:
            print "\tGroup '%s' added to project (%s) succussfully" % (a, pro_name)
        else:
            print "\t!!!ERROR!!! Group not found: %s" % response

    url = "https://%s.nm.nmfco.com:5000/v3/projects/%s/groups/AA-SDDC-Admin/roles/%s" % (campus, project_id, admin_id)

    headers = {
    'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
    }

    response = requests.request("PUT", url, headers=headers, verify=False)

    if response.status_code == 204:
        print "\tGroup 'AA-SDDC-Admin' added to project (%s) successfully" % pro_name
    else:
        print "\t!!!ERROR!!! Assigning group to project: %s" % response

    url = "https://%s.nm.nmfco.com:5000/v3/projects/%s/users/VCACP/roles/%s" % (campus, project_id, admin_id)

    response = requests.request("PUT", url, headers=headers, verify=False)

    if response.status_code == 204:
        print "\tUser 'VCACP' added to project (%s) successfully"
    else:
        print "\t!!!ERROR!!! Assigning user VCACP to project: %s" % response

def attach_gw_int(auth_token, campus, rtr_id, net_id, subnet_id):
    url = "https://%s.nm.nmfco.com:9696/v2.0/routers/%s/add_router_interface" % (campus, rtr_id)

    port_id = vio_create_gwport(auth_token, campus, net_id, subnet_id)

    payload = "{\n\"port_id\":\"%s\"\n}" % port_id

    headers = {
        'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
    }

    #print "\tRTR ID: %s\n\tPort ID: %s" % (rtr_id, port_id)
    response = requests.request("PUT", url, data=payload, headers=headers, verify=False)

    if response.status_code == 200:
        print "\tMGMT Gateway attached"
    else:
        print "\t!!!ERROR!!! connection gateway port to router: %s" % response
        exit()

def vio_create_gwport(auth_token, campus, network_id, subnet_id):
    url = "https://%s.nm.nmfco.com:9696/v2.0/ports" % campus

    headers = {
        'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
    }
    #print "\tNet ID: %s\n\tSub ID: %s" % (network_id, subnet_id)
    payload = "{\n\"port\": {\n\"network_id\":\"%s\",\"fixed_ips\": [{\"ip_address\":\"192.168.255.1\",\"subnet_id\":\"%s\"}]\n}\n}" % (network_id, subnet_id)

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)

    if response.status_code == 201:
        print "\tMGMT Gateway port created successfully"
        data = response.json()
        port_id = data['port']['id']
        return port_id
    else:
        print "\t!!!ERROR!!! creating MGMT GW port: %s" % response
    exit()

def vio_external_network(auth_token, campus):
    url = "https://%s.nm.nmfco.com:9696/v2.0/networks" % campus

    headers = {
    'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
    }

    response = requests.request("GET", url, headers=headers, verify=False)

    if response.status_code == 200:
        response_data = response.json()
        networks = response_data['networks']

        for n in networks:
            name = n['name']
            id	 = n['id']

            if "float-ip" in name.lower():
                float_id = id
        return float_id
    else:
        print "\t!!!ERROR!!! finding external network: %s" % response
        exit()

def vio_create_network(auth_token, net_name, project_id, campus):
    url = "https://%s.nm.nmfco.com:9696/v2.0/networks" % campus

    payload = "{\n\"network\": {\n\"name\":\"%s\",\n\"provider:network_type\":\"vxlan\",\n\"tenant_id\":\"%s\",\n\"admin_state_up\":true\n}\n}" % (net_name, project_id)
    headers = {
        'x-auth-token': auth_token,
        'content-type': "application/json",
        'cache-control': "no-cache",
    }

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)

    if response.status_code == 201:
        print "\tNetwork '%s' succussfully created" % net_name
        data = response.json()
        net_id = data['network']['id']
        return net_id
    else:
        print "\t!!!ERROR!!! creating mgmt network: %s" % response
        exit()

def vio_create_subnet(auth_token, net_id, net_cidr, net_gw, project_id, sub_name, campus):
    url = "https://%s.nm.nmfco.com:9696/v2.0/subnets" % campus

    payload = "{\n\"subnet\": {\n\"network_id\":\"%s\",\n\"ip_version\": 4,\n\"cidr\": \"%s\",\n\"gateway_ip\":\"%s\",\n\"tenant_id\":\"%s\",\n\"name\":\"%s\",\n\"dns_nameservers\":[\"172.16.31.41\",\"172.16.29.41\"],\n\"enable_dhcp\":\"True\"\n}\n}" % (net_id, net_cidr, net_gw, project_id, sub_name)
    headers = {
        'x-auth-token': auth_token,
        'content-type': "application/json",
        'cache-control': "no-cache",
    }

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)

    if response.status_code == 201:
        print "\tSubnet '%s' succussfully created" % sub_name
        data = response.json()
        sub_id = data['subnet']['id']
        return sub_id
    else:
        print "\t!!!ERROR!!! creating subnet: %s" % response
        exit()

def vio_create_router(auth_token, campus, pro_name, project_id):
    url = "https://%s.nm.nmfco.com:9696/v2.0/routers" % campus

    float_id = vio_external_network(auth_token, campus)
    #print "\tFloat ID: %s" % float_id
    #print "\tProject ID: %s" % project_id

    payload = "{\n\"router\": {\"name\": \"%s-mgmt-rtr\",\"tenant_id\": \"%s\",\"external_gateway_info\": {\"network_id\": \"%s\",\"enable_snat\": true\n},\"admin_state_up\": true,\"availability_zone_hints\":[\"default\"]\n}\n}" % (pro_name, project_id, float_id)

    headers = {
        'x-auth-token': auth_token,
        'content-type': "application/json",
        'cache-control': "no-cache",
    }

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)

    if response.status_code == 201:
        print "\tMGMT Router '%s-mgmt-rtr' successfully created" % pro_name
        data = response.json()
        rtr_id = data['router']['id']
        return rtr_id
    else:
        print "\t!!!ERROR!!! router create error: %s" % response
        exit()

def project_auth_token(version, campus, username, passwd, project_id):
    if version == "3":
        url = "https://%s.nm.nmfco.com:5000/v3/auth/tokens" % campus

        payload = "{\n\"auth\":{\n\"identity\":{\n\"methods\":[\n\"password\"\n],\n\"password\":{\n\"user\": {\n\"id\":\"%s\",\n\"password\": \"%s\"\n}\n}\n},\n\"scope\": {\n\"project\": {\n\"domain\": {\"id\":\"default\"\n},\n\"id\":\"%s\"\n}\n}\n}\n}" % (
        username, passwd, project_id)
        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
        }

        response = requests.request("POST", url, data=payload, headers=headers, verify=False)
        if response.status_code == 201:
            print "\t\tSuccussfully authenticated with 'ucpadmin', and retreived auth v3 token"
            return response.headers['X-Subject-Token']
        else:
            print "\t\t!!!ERROR!!! authenticating for v3: %s" % response
            exit()

def deploy_vio_server(auth_token, campus, project_id, net_id, server_name, az):
    image_id, flavor_id = item_lookup(auth_token, campus, project_id)
    url = "https://%s.nm.nmfco.com:8774/v2.1/%s/servers" % (campus, project_id)

    payload = """
    {
        "server": {
            "name": "%s",
            "imageRef": "%s",
            "flavorRef": "%s",
            "availability_zone": "%s",
            "networks": [{
                "uuid": "%s"
            }],
            "metadata": {
                "My Server Name": "%s"
            },
            "security_groups": [
                {
                    "name": "default"
                }
            ]
        }
    }
    """ % (server_name, image_id, flavor_id, az, net_id, server_name)
    headers = {
        'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
    }
    response = requests.request("POST", url, data=payload, headers=headers, verify=False)
    if response.status_code == 202:
        print "\t\tServer deployed successfully"
        data = response.json()
        server_id = data['server']['id']
        return server_id
    else:
        print "\t\t!!!ERROR!!! Server deploy error: %s" % response
        exit()

def item_lookup(auth_token, campus, project_id):
    print "\t\tLooking up Image ID:"
    headers = {
        'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
    }

    image_url = "https://%s.nm.nmfco.com:9292/v2/images" % campus

    image_response = requests.request("GET", image_url, headers=headers, verify=False)

    if image_response.status_code == 200:
        data = image_response.json()
        images = data['images']
        found = False
        for i in images:
            name = i['name']
            id = i['id']

            if name.lower() == 'centos-vio-master-current':
                image_id = id
                print "\t\t\tSuccessfully found image id (%s)" % image_id
                found = True
                break

        if found != True:
            print "\t\t\t!!!ERROR!!! Couldn't find image"
            exit()
    else:
        print "\t\t\t!!!ERROR!!! Didn't get image ID, error code: %s" % image_response

    print "\t\tLooking up flavor id:"
    flavor_url = "https://%s.nm.nmfco.com:8774/v2.1/%s/flavors" % (campus, project_id)

    flavor_response = requests.request("GET", flavor_url, headers=headers, verify=False)

    if flavor_response.status_code == 200:
        data = flavor_response.json()
        flavors = data['flavors']
        found = False
        for f in flavors:
            name = f['name']
            id = f['id']

            if name.lower() == 'nm.small':
                flavor_id = id
                print "\t\t\tSuccessfully found flavor id (%s)" % flavor_id
                found = True
                break

        if found != True:
            print "\t\t\t!!!ERROR!!! Couldn't find flavor"
            exit()
    else:
        print "\t\t\t!!!ERROR!!! Didn't get flavor ID, error code: %s" % flavor_response

    return image_id, flavor_id

def server_status(auth_token, campus, project_id, server_id):
    url = "https://%s.nm.nmfco.com:8774/v2.1/%s/servers/%s" % (campus, project_id, server_id)

    headers = {
        'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
    }

    deployed = False

    while deployed == False:
        response = requests.request("GET", url, headers=headers, verify=False)

        data = response.json()
        status = data['server']['status']

        if status == "ACTIVE":
            print "\t\tServer finished deploying"
            deployed = True
        elif status == "ERROR":
            print "\t\t!!!ERROR!!! Server deploy error, check OpenStack logs for error"
            exit()
        else:
            print "\t\tServer still deploying, sleep 5 seconds before checking again..."
            time.sleep(5)

def lock_server(auth_token, campus, project_id, server_id):
    url = "https://%s.nm.nmfco.com:8774/v2.1/%s/servers/%s/action" % (campus, project_id, server_id)

    headers = {
        'content-type': "application/json",
        'x-auth-token': auth_token,
        'cache-control': "no-cache",
    }

    payload = "{\n\"lock\":true\n}"

    response = requests.request("POST", url, data=payload, headers=headers, verify=False)

    if response.status_code == 202:
        print "\t\tServer locked successfully"
    else:
        print "\t\t!!!ERROR!!! Server not locked: %s" % response
        print "\t\t\tURL: %s" % url
        print "\t\t\tData: %s" % payload
        print "\t\t\tHeaders: %s" % headers

def project_floatingIPs(auth_token, campus, project_id, port_id):
    print "\tChecking Project for unused Floating IP's:"
    url = "https://%s.nm.nmfco.com:9696/v2.0/floatingips" % campus
    querystring = {"tenant_id":"%s" % project_id}
    headers = {
        'x-auth-token': auth_token,
        'content-type': "application/json",
        'cache-control': "no-cache",
    }

    response = requests.request("GET", url, headers=headers, params=querystring, verify=False)

    if response.status_code == 200:
        print "\t\tFloating IP API Connection successful"
        data = response.json()
        floatingips = data['floatingips']
        if len(floatingips) == 0:
            print "\t\t\tNo floating IP's found"
            print "\t\tCreating floating IP for jump server"
            float_address = create_floating_ip(auth_token, campus, project_id, port_id)
            return float_address
        else:
            found = False
            for i in floatingips:
                status = i['status']
                float_id = i['id']
                float_address = i['floating_ip_address']

                if status == "DOWN":
                    found = True
                    print "\t\t\tFloating IP found (%s), assigning to jump server" % float_address
                    update_float_ip(auth_token, campus, port_id, float_id)
                    return

            if found == False:
                print "\t\t\tNo available Floating IP's found"
                print "\t\tCreating floating IP for jump server"
                float_address = create_floating_ip(auth_token, campus, project_id, port_id)
                return float_address
    else:
        print "\t\t!!!ERROR!!! Couldn't connect to %s Neutron API" % campus.upper()

def create_floating_ip(auth_token, campus, project_id, port_id):
    external_net_id = vio_external_network(auth_token, campus)

    url = "https://%s.nm.nmfco.com:9696/v2.0/floatingips" % campus

    headers = {
        'x-auth-token': auth_token,
        'content-type': "application/json",
        'cache-control': "no-cache",
    }

    payload = """
    {
        "floatingip": {
            "floating_network_id": "%s",
            "tenant_id":"%s",
            "port_id":"%s"
        }
    }
    """ % (external_net_id, project_id, port_id)

    response = requests.request("POST", url, headers=headers, data=payload, verify=False)

    if response.status_code == 201:
        data = response.json()
        float_address = data['floatingip']['floating_ip_address']
        server_ip = data['floatingip']['fixed_ip_address']
        print "\t\t\tNew Floating IP (%s) Created and Assigned to JumpServer (%s)" % (float_address, server_ip)

        return float_address
    else:
        print "\t\t\t!!!ERROR!!! Couldn't assign floating IP to project: %s" % response.status_code

def update_float_ip(auth_token, campus, port_id, float_id):
    url = "https://%s.nm.nmfco.com:9696/v2.0/floatingips/%s" % (campus, float_id)

    headers = {
        'x-auth-token': auth_token,
        'content-type': "application/json",
        'cache-control': "no-cache",
    }

    payload = """
    {
        "floatingip": {
            "port_id": "%s"
        }
    }
    """ % port_id

    response = requests.request("PUT", url, headers=headers, data=payload, verify=False)

    if response.status_code == 200:
        data =response.json()
        float_ip = data['floatingip']['floating_ip_address']
        server_ip = data['floatingip']['fixed_ip_address']
        print "\t\t\t\tFloat IP '%s' has been assign from project to jump server '%s'" % (float_ip, server_ip)
        return
    else:
        print "\t\t\t\t!!!ERROR!!! Couldn't update floating ip port %s: %s" % (port_id, response)

def server_port_id(auth_token, port_auth, campus, project_id, server_id, net_name):
    url = "https://%s.nm.nmfco.com:8774/v2.1/%s/servers/%s" % (campus, project_id, server_id)

    headers = {
        'x-auth-token': auth_token,
        'content-type': 'application/json',
        'cache-control': 'no-cache',
    }

    response = requests.request("GET", url, headers=headers, verify=False)

    if response.status_code == 200:
        print "\tServer Found, locating Information"
        data = response.json()
        ip = data['server']['addresses'][net_name][0]['addr']
        print "\t\tServer IP: %s" % ip

        port_url = "https://%s.nm.nmfco.com:9696/v2.0/ports" % campus

        querystring = {"project_id":'%s' % project_id}
        port_headers = {
            'x-auth-token': port_auth,
            'content-type': 'application/json',
            'cache-control': 'no-cache',
        }

        port_response = requests.request("GET", port_url, headers=port_headers, params=querystring, verify=False)
        if port_response.status_code == 200:
            print "\tSuccessfully connected to Port API"
            port_data = port_response.json()
            ports = port_data['ports']

            found = False

            for p in ports:
                port_id = p['id']
                port_ip = p['fixed_ips'][0]['ip_address']

                if port_ip == ip:
                    print "\t\tPort ID (%s) Found" % port_id
                    found = True
                    return port_id

            if found == False:
                "\t!!!ERROR!!! Port with IP matching server not found"
                exit()
        else:
            print "\t!!!ERROR!!! Couldn't connect to port API: %s" % port_response
            exit()
    else:
        print "\t!!!ERROR!!! Couldn't connect to server API: %s" % response
        exit()


##
## Main
##
## Define the arguements for the script to work properly
parser = argparse.ArgumentParser(description="Create a new Project doing the following:\n\t- Assign AD Groups\n\t- Create mgmt network\n\t- Create mgmt subnet\n\t- Attach mgmt defualt gateway to NSX router\n\t- Deploy JumpServer and assign floating IP")
parser.add_argument('--application', help="Enter the name of the application. Don't use any spaces.", required=True)
parser.add_argument('--adgroups',help="Enter name of AD groups that need _member_ access", required=True)
parser.add_argument('--environment',help="Enter the environemnt (Prod, NonProd)", required=True)
parser.add_argument('--campus',help="Which campus do you want to build the project in? (MKE, FRK)", required=True)
parser.add_argument('--username',help="Enter your admin username. This is used to auth to the project to deploy the server")
parser.add_argument('--password',help="Enter the admin password. This is used to auth to the project to deploy the server")
#parser.add_argument('--servercount', help="Enter the number of servers that will be needed, including long term", type=int, required=True)
args = parser.parse_args()

if args.environment.lower() == "prod":
    pro_name = "%s_prod" % args.application.lower()
elif args.environment.lower() == "nonprod":
    pro_name = "%s_nonprod" % args.application.lower()
else:
    print "Please enter environment of Prod or NonProd"
    exit()

if args.username:
    username = args.username
else:
    username = "vcacp"

if ((args.password is None) & (args.username is not None)):
    print "ERROR: Please use '--password' option with the when specifying username"
    exit()
elif ((args.username is not None) & (args.password is not None)):
    password = args.password
else:
    password = 'onWeek36'


if args.campus.lower() == "mke":
    campus = "mke-vio"
    az = "mkevioaz"
elif args.campus.lower() == "frk":
    campus = "frk-vio"
    az = "frkvioaz"
else:
    print "Please enter campus of MKE or FRK"
    exit()

for ad in args.adgroups.split(','):
    adlist.append(ad.strip())

net_name = "%s_mgmt_net" % pro_name.lower()
sub_name = "%s_mgmt_sub" % pro_name.lower()

mgmt_sub = "192.168.255.0/24"
mgmt_gw = "192.168.255.1"

print "Creating Project and assigning Access Groups:"
auth_token_v3 = auth_token("3", campus)

project_id = create_project(auth_token_v3, pro_name, campus)

assign_group_to_project(auth_token_v3, project_id, adlist, pro_name, campus)

print "Creating Network, Subnet, and Router within in project:"
#auth_token_v2 = auth_token("3", campus)

net_id = vio_create_network(auth_token_v3, net_name, project_id, campus)

subnet_id = vio_create_subnet(auth_token_v3, net_id, mgmt_sub, mgmt_gw, project_id, sub_name, campus)

rtr_id = vio_create_router(auth_token_v3, campus, pro_name, project_id)

attach_gw_int(auth_token_v3, campus, rtr_id, net_id, subnet_id)

print "!!!Project successfully created!!!"

server_name = "%s-jumpserver" % pro_name

print "\nCreating Jump Server"

print "\tRetrieving Auth token:"
project_auth_token = project_auth_token("3", campus, username, password, project_id)

print "\tDeploying Server:"
server_id = deploy_vio_server(project_auth_token, campus, project_id, net_id, server_name, az)

print "\tChecking Server deploy status"
server_status(project_auth_token, campus, project_id, server_id)

print "\tLocking Server:"
lock_server(project_auth_token, campus, project_id, server_id)

print "\nAssign Floating IP to Server"
port_id = server_port_id(project_auth_token, auth_token_v3, campus, project_id, server_id, net_name)

floating_ip = project_floatingIPs(auth_token_v3, campus, project_id, port_id)
print "!!!Jump Server fully deployed!!!"

print "!!!Project is fully deployed, email client!!!"

print "===Summary==="
print "Campus: %s" % args.campus
print "\tURL: https://%s.nm.nmfco.com" % campus
print "Project Name(s): %s" % pro_name
print "Jump  Server Floating IP: %s" % floating_ip