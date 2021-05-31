ARCHIVED
========

This project is no longer maintained.  

The world has changed substantially since I wrote this.  I'm currently using kubernetes with [external-dns](https://github.com/kubernetes-sigs/external-dns) to solve this problem, and [Traefik](https://traefik.io/) for the proxy part.

This should be considered deprecated.

---

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
