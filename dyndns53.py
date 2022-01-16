import sys
import argparse
import logging
import boto3
import requests
import ipaddress


def get_public_ip() -> str:
    """Ask ipify and ipinfo about out public IP address
    Both services must be reachable and report the same address,
    otherwise exit.
    """
    logging.debug("Requesting our IP address from ipify")
    try:
        public_ip_ipify = ipaddress.ip_address(
            requests.get('https://api.ipify.org').text)
    except Exception as e:
        logging.error(e)
        raise e
    logging.debug("Got {} from ipify".format(public_ip_ipify))

    logging.debug("Requesting our IP address from ipinfo")
    try:
        public_ip_ipinfo = ipaddress.ip_address(
            requests.get('https://ipinfo.io/ip').text)
    except Exception as e:
        logging.error(e)
        raise e
    logging.debug("Got {} from ipinfo".format(public_ip_ipinfo))

    if public_ip_ipify != public_ip_ipinfo:
        logging.error("Public IP address mismatch: {} != {}".format(
            public_ip_ipify, public_ip_ipinfo))
        sys.exit(1)

    return str(public_ip_ipify)


def get_route53_ip(zone_id, dns_record) -> str:
    """Check DNS record on Route53 by using test_dns_answer.
    Errors are logged and raised.
    """
    try:
        response = route53_client.test_dns_answer(
            HostedZoneId=zone_id,
            RecordName=dns_record,
            RecordType='A')
    except Exception as e:
        logging.error(e)
        raise e

    return response['RecordData'][0]


def update_route53(zone_id, dns_record, desired_ip, ttl):
    """Update the DNS record on Route53 to the desired IP address.
    Errors are logged and raised.
    """
    logging.info("Updating Route53: {}/{} A {} TTL={}".format(
        zone_id, dns_record, desired_ip, ttl))
    try:
        route53_client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Comment': 'DynDNS Change',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': dns_record,
                            'Type': 'A',
                            'TTL': ttl,
                            'ResourceRecords': [
                                {
                                    'Value': desired_ip
                                },
                            ],
                        }
                    },
                ]
            }
        )
    except Exception as e:
        logging.error(e)
        raise e


def main():
    global route53_client

    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.ArgumentDefaultsHelpFormatter(prog, max_help_position=50))
    parser.add_argument("zone_id", type=str, help="Route53 Zone ID",)
    parser.add_argument("dns_record", type=str, help="DNS record to update")
    parser.add_argument("--ttl", type=int, default=30, help="TTL to set on update")
    parser.add_argument("--ipaddr", type=str, help="IP address to use instead of lookup via external service")
    parser.add_argument("--aws-profile", type=str, help="AWS profile to use. Overrides ENV")
    parser.add_argument("--loglevel", type=str, help="Log level", default="INFO", choices=[
        'DEBUG',
        'INFO',
        'WARNING',
        'ERROR',
        'CRITICAL'
    ])
    args = parser.parse_args()

    # Configure logging
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(stream=sys.stdout, format='%(asctime)s %(message)s', level=numeric_level)

    # Arguments
    zone_id = args.zone_id
    dns_record = args.dns_record
    ttl = args.ttl

    # Start
    logging.info("Checking {}/{}".format(zone_id, dns_record))

    # Create route53 client
    if args.aws_profile:
        logging.debug("Using AWS profile [{}]".format(args.aws_profile))
        route53_client = boto3.session.Session(
            profile_name=args.aws_profile).client('route53')
    else:
        route53_client = boto3.session.Session().client('route53')

    # Determine desired IP address for update
    # Use --ipaddr parameter if specified, otherwise ask external services
    if args.ipaddr:
        logging.debug("Using ipaddr from --ipaddr {}".format(args.ipaddr))
        desired_ip = args.ipaddr
    else:
        desired_ip = get_public_ip()
    logging.info("Desired IP address: {}".format(desired_ip))

    # Get record details from Route53
    route53_ip = get_route53_ip(zone_id, dns_record)
    logging.info("Route53 IP address: {}".format(route53_ip))

    # Compare and update if needed
    if desired_ip != route53_ip:
        update_route53(zone_id, dns_record, desired_ip, ttl)
    else:
        logging.info("No update needed")


if __name__ == '__main__':
    main()
