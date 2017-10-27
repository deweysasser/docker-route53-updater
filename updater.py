#!/usr/bin/env python

import boto3
import docker
import argparse
import os
import traceback
import time
import urllib2
import sys

def exception_ignored(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            traceback.print_exc()
            print "Function {} threw exception.  Execution continuing".format(func.__name__)

    return wrapper

def retry(func):
    '''retry the given function call 3x with sleeps before giving up'''
    def wrapper(*args, **kwargs):
        for i in xrange(3):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                traceback.print_exc()
                print "Function {} threw exception.  will retry".format(func.__name__)
                time.sleep(1)
                print "Retrying {}".format(func.__name__)
        print "Function {} threw exception 3 times.  Aborting call".format(func.__name__)

    return wrapper
            
class Route53(object):
    def __init__(self, args):
        if args.key:
            self.client = boto3.client(
                'route53',
                aws_access_key_id=args.key,
                aws_secret_access_key=args.secret,
                )
        else:
            self.client = boto3.client('route53')

        self.args = args

    def delete(self, names, ip):
        self.update(names, ip, op="DELETE")

    def update(self, names, ip, op="UPSERT"):
        '''Update Route 53 for all the names given to the specified ip'''

        for name in names:
            try:
                hostname, domain = name.split(".", 1)
                zone_id = self.get_zone_id(domain)

                if zone_id:
                    print "Updating %s to %s in zone %s" % (name, ip, zone_id)
                    if not self.args.noop:
                        response = self.client.change_resource_record_sets(
                            HostedZoneId=zone_id,
                            ChangeBatch={
                                "Comment": 'Automatically created entry for docker service',
                                "Changes": [
                                    {
                                        "Action": op,
                                        "ResourceRecordSet": {
                                            "Name": name,
                                            "Type": 'A',
                                            "TTL": 300,
                                            "ResourceRecords": [
                                                {
                                                    "Value": ip
                                                    },
                                                ],
                                            }
                                        },
                                    ]
                                }
                            )
            except Exception as e:
                print "ERROR while updating {} to {}: {}".format(name, ip, e)

    def get_zone_id(self, domain):
        '''Return the Route 53 zone id for the given 'domain'
        '''
        response = self.client.list_hosted_zones()
    
        name=domain
        if not name.endswith("."):
            name = domain + "."
        
        zones = [x for x in response['HostedZones'] 
                 if x['Name'] == name]
    
        if len(zones) < 1:
            raise Exception("Can't find existing zone for %s" % domain)
    
        return zones[0]['Id']


def get_host_ip(args):
    '''Get the AWS host IP.  

    Use 'args' to determine exact behavior:
       * args.my_ip is set, return it
       * args.aws_public_ip is True, return public instance IP retrieved from AWS instance metadata service
       * args.aws_local_ip is True, return local (private) instance IP retrieved from AWS instance metadata service
       * otherwise, return the public IP as determined by an Internet IP address reporting service

       if no IP can be found or the web call fails, the method will raise an exception'''


    if args.my_ip is not None:
        ip = args.my_ip
    elif args.aws_public_ip:
        ip = urllib2.urlopen("http://169.254.169.254/latest/meta-data/public-ipv4").read()
    elif args.aws_local_ip:
        ip = urllib2.urlopen("http://169.254.169.254/latest/meta-data/local-ipv4").read()
    else:
        ip = urllib2.urlopen("http://ipv4bot.whatismyipaddress.com").read()

    if ip is None:
        raise Exception("Can't get IP")
    return ip

def regenerate(args, client, rt53, remove=None):
    # TODO:  at this point we have the container that is dying
    ip=get_host_ip(args)
    proxy_names = set()
    for label in args.labels:
        for x in client.containers.list():
            if label in x.labels:
                proxy_names.add(x.labels[label])

    print "Adding proxy names {} ".format(proxy_names)
    rt53.update(proxy_names, ip)

    if remove and 'proxy.host' in remove.labels:
        name = remove.labels['proxy.host']
        if not name in proxy_names:
            # TODO: now remove it from route53
            print "Removing {} from route53".format(name)
            rt53.delete([name], ip)

@retry
def handleAction(e, args, client, rt53):
    name = e['Actor']['Attributes']['name']
    print "Event {} on {}".format(e['Action'], name)
    if e['Action'] == 'start':
        regenerate(args, client, rt53)
    else:
        try:
            regenerate(args, client, rt53, client.containers.get(name))
        except Exception:
            # this likely means the container was killed rather than
            # stopped gracefully, so there's not much we can do to
            # remove it
            regenerate(args, client, rt53)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--route53", action='store_true', help="True if we should update Route 53")
    parser.add_argument("--key", help="AWS key to use", default=os.getenv('AWS_ACCESS_KEY_ID'))
    parser.add_argument("--secret", help="AWS secret to use", default=os.getenv('AWS_SECRET_ACCESS_KEY'))
    parser.add_argument("--aws-public-ip", action='store_true', help="Update Route 53 with public IP")
    parser.add_argument("--aws-local-ip", action='store_true', help="Update Route 53 with local IP")
    parser.add_argument("--my-ip", help="Use the given IP instead of the discovered one")
    parser.add_argument("--noop", help="Do not actually update Route53", action='store_true')
    parser.add_argument("--labels", help="Docker labels from which to collect hostnames", nargs="*", default=["proxy.host"])
    parser.add_argument("--add-label",  help="Docker labels from which to collect hostnames", dest="labels", action="append")


    args = parser.parse_args()

    while True:
        try:
            client = docker.from_env()
            rt53 = Route53(args)
            regenerate(args, client, rt53)

            for e in client.api.events(decode=True):
                if e['Action'] in ['start', 'die']:
                    handleAction(e, args, client, rt53)
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            traceback.print_exc()
            time.sleep(5)




if __name__ == "__main__":
    main()
