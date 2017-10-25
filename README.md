docker-route53-updater
======================

Update Route53 with the current host IP for labeled docker containers
running on the current host.

This likely works best in conjunction with a proxy driven by e.g. a
[web proxy
generator](https://hub.docker.com/r/deweysasser/web-proxy-generator/)


Quick Start
=========== 

```
docker run --name route53-updater -v /var/run/docker.sock:/var/run/docker.sock deweysaser/docker-route53-updater --key AWS_KEY --secret AWS_SECRET
```
