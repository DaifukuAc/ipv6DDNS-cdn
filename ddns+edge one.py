import time
import json
import configparser
import socket
import os
import netifaces
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.teo.v20220901 import teo_client, models

def get_ipv6_address(interface_name):
    # 获取所有网络接口的地址信息
    addrs = netifaces.ifaddresses(interface_name).get(netifaces.AF_INET6, [])
    # 过滤出指定接口的IPv6地址
    for addr in addrs:
        if not addr['addr'].startswith('fe80::'):
            return addr['addr']
    return None

def modify_acceleration_domain(ipv6_address, secret_id, secret_key, zone_id, domain_names):
    cred = credential.Credential(secret_id, secret_key)
    httpProfile = HttpProfile()
    httpProfile.endpoint = "teo.tencentcloudapi.com"

    clientProfile = ClientProfile()
    clientProfile.httpProfile = httpProfile
    client = teo_client.TeoClient(cred, "", clientProfile)

    for domain_name in domain_names:
        try:
            req = models.ModifyAccelerationDomainRequest()
            params = {
                "ZoneId": zone_id,
                "DomainName": domain_name,
                "OriginInfo": {
                    "OriginType": "IP_DOMAIN",
                    "Origin": ipv6_address
                }
            }
            req.from_json_string(json.dumps(params))

            resp = client.ModifyAccelerationDomain(req)
            print(f"Modified the IPv6 address of domain {domain_name} to {ipv6_address}. Response: {resp.to_json_string()}")
        except Exception as e:
            print(f"Failed to modify the IPv6 address for domain {domain_name}. Error: {e}")


def get_last_ipv6(secret_id, secret_key, zone_id, domain_names):
    cred = credential.Credential(secret_id, secret_key)
    # 实例化一个http选项，可选的，没有特殊需求可以跳过
    httpProfile = HttpProfile()
    httpProfile.endpoint = "teo.tencentcloudapi.com"

    # 实例化一个client选项，可选的，没有特殊需求可以跳过
    clientProfile = ClientProfile()
    clientProfile.httpProfile = httpProfile
    # 实例化要请求产品的client对象,clientProfile是可选的
    client = teo_client.TeoClient(cred, "", clientProfile)

    # 实例化一个请求对象,每个接口都会对应一个request对象
    req = models.DescribeAccelerationDomainsRequest()
    params = {
        "ZoneId": zone_id,
        "Filters": [
            {
                "Name": "domain-name",
                "Values": domain_names
            }
        ]
    }
    req.from_json_string(json.dumps(params))

    # 返回的resp是一个DescribeAccelerationDomainsResponse的实例，与请求对象对应
    resp = client.DescribeAccelerationDomains(req)
    # 输出json格式的字符串回包
    print(resp.to_json_string())
    try:
        origin = resp._AccelerationDomains[0]._OriginDetail.Origin
        return origin
    except (AttributeError, IndexError, TypeError):
        return "::1"

def main():
    config = configparser.ConfigParser()
    config.read('config.conf', encoding='utf-8')
    secret_id = config.get('DEFAULT', 'SecretId')
    secret_key = config.get('DEFAULT', 'SecretKey')
    zone_id = config.get('DEFAULT', 'ZoneId')
    domain_names = config.get('DEFAULT', 'DomainName').split(',')
    interface_name = config.get('DEFAULT', 'InterfaceName') 

    print(f"Starting the program with the following configuration: SecretId={secret_id}, ZoneId={zone_id}, DomainNames={domain_names}, InterfaceName={interface_name}")  # 修改这一行

    # last_ipv6_address = "::1"  # Initialize to an unlikely IPv6 address
    # print(f"Initial IPv6 address: {last_ipv6_address}")

    current_ipv6_address = get_ipv6_address(interface_name)  
    last_ipv6_address = get_last_ipv6(secret_id, secret_key, zone_id, domain_names)
    if current_ipv6_address != last_ipv6_address:
        print(f"IPv6 address changed from {last_ipv6_address} to {current_ipv6_address}")
        modify_acceleration_domain(current_ipv6_address, secret_id, secret_key, zone_id, domain_names)
        last_ipv6_address = current_ipv6_address
    else:
        print("The current IP address has not changed; there is no need to submit.")

if __name__ == "__main__":
    main()
