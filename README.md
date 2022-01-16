# dyndns53

## About

dyndns53 updates DNS A records on AWS Route 53 with public or private IP address.
Public IP address is retreived from external services ipify and ipinfo. Both services must report the same address, or else the update will not be performed. Manual update is also possible with --ipaddr

## Requirements

* python3
* boto3
* requests

## Installation

    git clone https://github.com/bjeborn/dyndns53.git
    cd dyndns53
    python3 -mvenv venv
    source venv/bin/activate
    pip install -r requirements.txt

## AWS credentials

AWS profile can be specified with --aws-profile  
If no profile is specified, the default or ENV is used by boto3.  

### IAM account actions needed

* route53:TestDNSAnswer
* route53:ChangeResourceRecordSets

### AWS policy example

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "route53:TestDNSAnswer",
                    "route53:ChangeResourceRecordSets"
                ],
                "Resource": "*"
            }
        ]
    }

## Usage

    usage: dyndns-route53.py [-h] [--ttl TTL] [--ipaddr IPADDR] [--aws-profile AWS_PROFILE] [--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}] zone_id dns_record

    positional arguments:
    zone_id                                         Route53 Zone ID
    dns_record                                      DNS record to update

    optional arguments:
    -h, --help                                      show this help message and exit
    --ttl TTL                                       TTL to set on update (default: 30)
    --ipaddr IPADDR                                 IP address to use instead of lookup via external service (default: None)
    --aws-profile AWS_PROFILE                       AWS profile to use. Overrides ENV (default: None)
    --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}  Log level (default: INFO)

## Examples

Update home.example.com in zone Z01234567ABCDEFGHIJKL with public ip looked up via external services

    ./venv/bin/python dyndns53.py Z01234567ABCDEFGHIJKL home.example.com

Update local-service.example.com in zone Z01234567ABCDEFGHIJKL with address 192.168.0.100 and set TTL to 600 seconds

    ./venv/bin/python dyndns53.py Z01234567ABCDEFGHIJKL home.example.com --ipaddr 192.168.0.100 --ttl 600
