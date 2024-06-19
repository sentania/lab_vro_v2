#!/usr/local/bin/python3.7
import requests
import urllib3
import json
import getpass
import datetime
import dateutil
import argparse
import sys
from dateutil import parser
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
lease_update_link = []
'''
def GetArgs():
    parser = argparse.ArgumentParser(description='Check Arg Parser')
    parser.add_argument('-id', '--authid', required=True, help="Bearer-ID")
    parser.add_argument('-d', '--daystoextend', type=int, required=True, help="Time to Extend Lease")
    parser.add_argument('-bg', '--Businessgroup',required=True, help="Business Group Name")
    args = parser.parse_args()
    return args

park = GetArgs()
Auth_id = "Bearer " + park.authid
Number_of_days_to_extend = park.daystoextend
Business_group = park.Businessgroup
'''
Auth_id ="Bearer " +"MTU2NDU4ODExNDkzNjo0ODJjNDAxYjJhMjBiOGNlNzljYjp0ZW5hbnQ6dnNwaGVyZS5sb2NhbHVzZXJuYW1lOnNvbDE1NDQtbm1Abm0ubm1mY28uY29tZXhwaXJhdGlvbjoxNTY0NjE2OTE0MDAwOjRiMmRlNDdiODVhN2YxYTc2NzY3MjEwNjQwMmJmMmFjZjA5NDBiNWY3Y2ZjYzQ4MTg3ZDU1OTQyM2NjNGMzMzE3Y2EzZDNjN2M1ZGFhY2MxMzY0MDgwMmU2MDQ5ZGRjOTA2MTJkODU2MWQ4MWNiMjQ0NDRlNmM5ZDU5YjJmMzMy"
Number_of_days_to_extend = 51
Business_group = 'test group 87'

print(Auth_id)
print(Number_of_days_to_extend)
print(Business_group)

auth_headers = {
    'accept': "application/json",
    'content-type': "application/json",
    'Authorization': Auth_id
}

print(auth_headers)

get_resource_url = "https://myucp.nm.nmfco.com/identity/api/tenants/vsphere.local/subtenants"
resource_data = requests.request(
    "GET", get_resource_url, headers=auth_headers, verify=False)
full_opt = json.loads(resource_data.content)

for bg in full_opt['content']:
    if re.sub('[^A-Za-z0-9]+', '', bg['name']).lower() == re.sub('[^A-Za-z0-9]+', '', Business_group).lower():
        print(f"Found Business group,  {bg['name']}")
        bg_id = bg['id']
        print(bg['id'])

        get_resource_url2 = "https://myucp.nm.nmfco.com/catalog-service/api/consumer/resourceViews?page=1&limit=1000&resourceType=composition.resource.type.deployment"
        resource_data2 = requests.request(
            "GET", get_resource_url2, headers=auth_headers, verify=False)
        full_opt1 = json.loads(resource_data2.content)

        for i in full_opt1['content']:
            for j, k in i.items():
                if j == 'businessGroupId' and k == bg_id:
                    check_parent_link = {
                        key_link: key_value for key_link, key_value in i.items() if key_link == 'links'}
                    if check_parent_link is not None:
                        tmp_lnk = ({res_key: res_value for res_key, res_value in check_parent_link.items() if res_key == 'links'})['links']
                        par_value = "NA"
                        try:
                            par = next(item for item in tmp_lnk if item["rel"] == "GET: Parent Resource")
                            action_parm = 'GET Template: {com.vmware.csp.component.cafe.composition@resource.action.deployment.changelease.name}'
                            tmp_x = ({par_link: par_value for par_link, par_value in par.items() if par_link == 'href'}).get('href')
                            tmp_data = requests.request("GET", tmp_x, headers=auth_headers, verify=False)
                            tmp_full_opt = json.loads(tmp_data.content)
                            par_value = "Available"
                            tmp_cmd = ({k_link: k_value for k_link, k_value in tmp_full_opt.items() if k_link == 'links'}).get('links')
                            lease_update_link.append((next(item1 for item1 in tmp_cmd if item1["rel"] == action_parm)).get('href'))
                        except Exception as Er:
                            print("Oops!  No parent value Found, Checking for Child...")
                        if par_value == 'NA':
                            par = next(
                                item for item in tmp_lnk if item["rel"] == "GET: Child Resources")
                            action_parm = 'GET Template: {com.vmware.csp.component.iaas.proxy.provider@resource.action.name.machine.ChangeLease}'
                            tmp_x = ({par_link: par_value for par_link, par_value in par.items(
                            ) if par_link == 'href'}).get('href')
                            tmp_data = requests.request(
                                "GET", tmp_x, headers=auth_headers, verify=False)
                            tmp_full_opt = json.loads(tmp_data.content)
                            tmp_cmp = tmp_full_opt['content'][0]['links']
                            try:
                                lease_update_link.append(
                                    (next(item1 for item1 in tmp_cmp if item1["rel"] == action_parm)).get('href'))
                            except Exception as Er:
                                print("Oops!  Child has a parent value...")
        if len(lease_update_link) != 0:
            lease_update_link_u = list(set(lease_update_link))
            for template_iter in lease_update_link_u:
                print(template_iter)
                lease_url = template_iter.split('/actions')[0]
                get_json = requests.request("GET", lease_url, headers=auth_headers, verify=False)
                tmp_get_json_value = json.loads(get_json.content)
                'print(tmp_get_json_value)'
                '''
                Ran in to issue if we take 365 days from the date of Expiry where it cross the max blueprint lease limit, New lease expiration date will be calculated from current time.
                date_to_update = (({Data_key: Data_value for Data_key, Data_value in tmp_get_json_value.items() if Data_key == 'lease'}).get('lease')).get('end')
                final_date_toupdate = ((datetime.datetime.strptime(date_to_update, "%Y-%m-%dT%H:%M:%S.%fZ") + datetime.timedelta(days=Number_of_days_to_extend)).isoformat()).split(".")[0] + ".000Z"
                '''
                rx = str(datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
                final_date_toupdate = ((datetime.datetime.strptime(rx, "%Y-%m-%dT%H:%M:%S.%fZ") + datetime.timedelta(days=Number_of_days_to_extend)).isoformat()).split(".")[0] + ".000Z"
                get_json_payload = requests.request(
                    "GET", template_iter, headers=auth_headers, verify=False)
                tmp_get_json_pay = json.loads(get_json_payload.content)
                data_type = (({Data_key: Data_value for Data_key, Data_value in tmp_get_json_pay.items() if Data_key == 'type'}).get('type'))
                data_resourceid = (({Data_key: Data_value for Data_key, Data_value in tmp_get_json_pay.items() if Data_key == 'resourceId'}).get('resourceId'))
                data_actionid = (({Data_key: Data_value for Data_key, Data_value in tmp_get_json_pay.items() if Data_key == 'actionId'}).get('actionId'))
                update_payload = '{ "type" :"' + data_type + '", "resourceId":"' + data_resourceid + '", "actionId": "' + data_actionid + \
                    '","description": null, "reasons": null, "data": {"provider-ExpirationDate":"' + \
                    final_date_toupdate + '"}}'
                post_url = template_iter.split("template")[0]
                request_lease_update = requests.request(
                    "POST", post_url, data=update_payload, headers=auth_headers, verify=False)
                print(request_lease_update)
                if request_lease_update.status_code != 201:
                    print("Failur Message: " + request_lease_update.text)
