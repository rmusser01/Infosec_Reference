# Containers
---------------------
## Table of contents
- [Containers 101](#c101)
- [Containers General](#cgen)
	- [101](#c101)
	- [Building Containers](#cbuild)
	- [Capabilities](#ccap)
	- [Container General](#cgen)
	- [Container Namespaces](#cns)
	- [Container Privileges](#cps)
	- [Container Security](#csec)
	- [Container Tools](#ctools)
- [Docker](#docker)
	- [Docker 101](#d101)
	- [Docker Compose](#dcom)
	- [Docker Images & Containers](#dci)
	- [Deployment](#ddep)
	- [Dockerfiles](#ddock)
	- [Layers](#dlay)
	- [Logging & Monitoring](#dlog)
	- [Namespaces](#dns)
	- [Networking](#dnet)
	- [Privileges](#dps)
	- [Security](#dsec)
	- [Storage](#dstorage)
	- [Tools](#tools)
- [Jails](#jails)
- [Kubernetes](#kubernetes)
	- [101](#k101)
	- [Security](#ksec)
- [RunC](#runc)
	- [101](#r101)

------------------------
### <a name="containers"></a>Containers
* **101**<a name="c101"></a>
	* [LXC - Wikipedia](https://en.wikipedia.org/wiki/LXC)
	* [Process Containers - lwn.net](https://lwn.net/Articles/236038/)
	* [cgroups - wikipedia](https://en.wikipedia.org/wiki/Cgroups)
	* [Everything you need to know about Jails - bsdnow.tv](http://www.bsdnow.tv/tutorials/jails)
	* [Jails - FreeBSD handbook](https://www.freebsd.org/doc/handbook/jails.html)
	* [xkcd on containers](https://xkcd.com/1988/)
	* [Docker Internals: A Deep Dive Into Docker For Engineers Interested In The Gritty Details - Docker Saigon](http://docker-saigon.github.io/post/Docker-Internals/)
* **Containers(General)**<a name="cgen"></a>
	 * **101**<a name="c101"></a>
		* [Linux LXC vs FreeBSD jail - Are there any notable differences between LXC (Linux containers) and FreeBSD's jails in terms of security, stability & performance? - unix.StackExchange](https://unix.stackexchange.com/questions/127001/linux-lxc-vs-freebsd-jail)
		* [Architecting Containers Part 1: Why Understanding User Space vs. Kernel Space Matters - Scott McCarty](https://www.redhat.com/en/blog/architecting-containers-part-1-why-understanding-user-space-vs-kernel-space-matters)
		* [From 30 to 230 docker containers per host - stormbind.net](http://sven.stormbind.net/blog/posts/docker_from_30_to_230/)
	* **Building**<a name="cbuild"></a>
		* [Best practices for building containers - cloud.google](https://cloud.google.com/solutions/best-practices-for-building-containers)
		* [img](https://github.com/genuinetools/img)
			* Standalone, daemon-less, unprivileged Dockerfile and OCI compatible container image builder.
	* **Capabilities**<a name="ccap"></a>
		* [Exploiting capabilities: Parcel root power, the dark side of capabilities - Emeric Nasi](http://blog.sevagas.com/IMG/pdf/exploiting_capabilities_the_dark_side.pdf)
	* **General**<a name="cgen2"></a>
		* [Getting Towards Real Sandbox Containers - Jesse Frazelle(May2016)](https://blog.jessfraz.com/post/getting-towards-real-sandbox-containers/)
		* [Best Practices for Operating Containers - cloud.google](https://cloud.google.com/solutions/best-practices-for-operating-containers)
			* This article describes a set of best practices for making containers easier to operate. These practices cover a wide range of topics, from security to monitoring and logging.
	* **Logging**
		* [Auditing containers with osquery - Corentin Badot-Bertrand](https://itnext.io/auditing-containers-with-osquery-389636f8c420)
	 * **Namespaces**<a name="cns"></a>
		* [Controlling access to user namespaces - lwn.net](https://lwn.net/Articles/673597/)
		* [Namespaces in operation, part 1: namespaces overview - lwn.net](https://lwn.net/Articles/531114/#series_index)
		* [A deep dive into Linux namespaces - Ifeanyi Ubah](http://ifeanyi.co/posts/linux-namespaces-part-1/)
			* [Part 2](http://ifeanyi.co/posts/linux-namespaces-part-2/)
			* [Part 3](http://ifeanyi.co/posts/linux-namespaces-part-3/)
			* [Part 4](http://ifeanyi.co/posts/linux-namespaces-part-4/)
	* **Privilegs**<a name="cpriv"></a>
		* [Privilege Escalation via lxd - Josiah Beverton](https://reboare.github.io/lxd/lxd-escape.html)
	* **Security**<a name="cs"></a>
		* [What is container security? - redhat.com](https://www.redhat.com/en/topics/security/container-security)
		* [NIST Special Publication 800-190: Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
		* [Container security: What you need to know about the NIST standards - Neil McAllister](https://techbeacon.com/enterprise-it/container-security-what-you-need-know-about-nist-standards)
		* [Understanding and Hardening Linux Containers - nccgroup](https://www.nccgroup.trust/uk/our-research/understanding-and-hardening-linux-containers/)
			* Linux containers offer native OS virtualisation, segmented by kernel namespaces, limited through process cgroups and restricted through reduced root capabilities, Mandatory Access Control and user namespaces. This paper discusses these container features, as well as exploring various security mechanisms. Also included is an examination of attack surfaces, threats, and related hardening features in order to properly evaluate container security. Finally, this paper contrasts different container defaults and enumerates strong security recommendations to counter deployment weaknesses-- helping support and explain methods for building high-security Linux containers. Are Linux containers the future or merely a fad or fantasy? This paper attempts to answer that question.
		* [Containers and Cloud Security - James Bottomley(2018)](https://blog.hansenpartnership.com/containers-and-cloud-security/)
			* The idea behind this blog post is to take a new look at how cloud security is measured and what its impact is on the various actors in the cloud ecosystem.
		* [Exploring container security: An overview - Maya Kaczorowski(GCP Focused)](https://cloud.google.com/blog/products/gcp/exploring-container-security-an-overview?m=1)
		* [Docker, Linux Containers (LXC), and security(2014) - Jerome Petazzoni](https://www.slideshare.net/jpetazzo/docker-linux-containers-lxc-and-security)
			* Virtual machines are generally considered secure. At least, secure enough to power highly multi-tenant, large-scale public clouds, where a single physical machine can host a large number of virtual instances belonging to different customers. Containers have many advantages over virtual machines: they boot faster, have less performance overhead, and use less resources. However, those advantages also stem from the fact that containers share the kernel of their host, instead of abstracting a new independent environment. This sharing has significant security implications, as kernel exploits can now lead to host-wide escalations. We will show techniques to harden Linux Containers; including kernel capabilities, mandatory access control, hardened kernels, user namespaces, and more, and discuss the remaining attack surface. 
		* [All Your Containers Are Belong to Us - James Condon(BSidesSF 2019)](https://www.youtube.com/watch?v=VqThnb-GML4&list=PLbZzXF2qC3RvGRbNQwKcf2KVaTCjzOB8o&index=6)
			* The rising adoption of container orchestration tools, such as Kubernetes, has enabled developers to scale cloud applications quickly and efficiently. However with this adoption comes with a new set of security challenges, such as securing the APIs used to manage these ecosystems. We recently conducted a research study that uncovered more than 20,000 publicly accessible management nodes open to the Internet. In this talk we will discuss the implications of the findings and provide recommendations for running orchestration systems securely in the public cloud. The following platforms are exposed and part of the research: Kubernetes, Mesos Marathon, RedHat OpenShift, Docker Swarm, and Portainer (Docker Management). Not only are these management UIs available on the web but we also discovered that their APIs are also available. Some are wide open. We will uncover how we did this research, who is the most popular cloud provider hosting the containers, which regions are most popular, and show demonstrations of exploitation and discover.
	* **Storage**
		* [REX-Ray](https://github.com/rexray/rexray)
			* REX-Ray provides a vendor agnostic storage orchestration engine. The primary design goal is to provide persistent storage for Docker, Kubernetes, and Mesos. The long-term goal of the REX-Ray project is to enable collaboration between organizations focused on creating enterprise-grade storage plugins for the Container Storage Interface (CSI).
	* **Tools**<a name="ctools"></a>
		* [nsjail](https://github.com/google/nsjail)
			* A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters (with help of the kafel bpf language)
* **Docker**<a name="docker"></a>
	* **101**<a name="d101"></a>
		* [Get Started, Part 1: Orientation and setup - docs.docker](https://docs.docker.com/get-started/)
		* [Play with Docker Classroom - Docker](https://training.play-with-docker.com/)
			* The Play with Docker classroom brings you labs and tutorials that help you get hands-on experience using Docker.
		* [Life in Containers: The Big Picture - Pankaj Mouriya](https://www.youtube.com/watch?v=UwBshgfnAGA)
			* In today's contemporary world, containers are one of the most trending and hottest topics in IT, wherever you go, you will find people talking about some shiny and new technologies and most of the time they're either talking about DevOps, Docker, Kubernetes or are deploying it. It becomes very difficult to know where to start and how to take your career to the next level in these shiny technologies. So, in today's session, we will be talking about the Big Picture of Docker. You will learn the basic fundamentals and how it works. After this session, you'll be able to get started with Docker.
			* [Gitbook](https://dockub.rootrwx.com/)
		* [Docker Cheat Sheet - wsargent](https://github.com/wsargent/docker-cheat-sheet)
	* **Compose**<a name="dcom"></a>
	* **Containers & Images**<a name="dci"></a>
		* **101**
			* [Docker Image Specification v1.0.0](https://github.com/moby/moby/blob/master/image/spec/v1.md)
			* [Docker image in depth - Bikram Kundu](https://jstobigdata.com/docker-image-in-depth/)
		* **Analysis**
			* [Static Analysis of Docker image vulnerabilities with Clair - Petr Kohut](https://www.nearform.com/blog/static-analysis-of-docker-image-vulnerabilities-with-clair/)
			* [Dive](https://github.com/wagoodman/dive)
				* A tool for exploring a docker image, layer contents, and discovering ways to shrink your Docker image size.
		* **Building**
			* **Articles/Blogposts/Writeups**
				* [Debugging Docker builds - Hongli Lai](https://www.joyfulbikeshedding.com/blog/2019-08-27-debugging-docker-builds.html)
			* **Tools**
				* [img](https://github.com/genuinetools/img)
					* Standalone, daemon-less, unprivileged Dockerfile and OCI compatible container image builder.
		* **Registry**
			* [Setting up a private Docker registry - Nicolas Frankel](https://www.exoscale.com/syslog/setup-private-docker-registry/)
			* [How to secure a private Docker registry - Nicolas Frankel](https://www.exoscale.com/syslog/securing-private-docker-registry/)
		* **Scanning**
			* **Articles/Blogposts/Writeups**
				* [Docker Security Best Practices: Part 3 – Securing Container Images - Jeremy Valance](https://anchore.com/docker-security-best-practices-part-3-securing-container-images/)
				* [How to implement Docker image scanning with open source tools - Mateo Burillo](https://sysdig.com/blog/docker-image-scanning/)
				* [Scanning Docker images with CoreOS Clair - wdijkerman](https://werner-dijkerman.nl/2019/01/28/scanning-docker-images-with-coreos-clair/)
				* [How to implement Docker image scanning with open source tools - Mateo Burillo(2018)](https://sysdig.com/blog/docker-image-scanning/)
			* **Tools**
				* [clair](https://github.com/coreos/clair)
					* Clair is an open source project for the static analysis of vulnerabilities in application containers (currently including appc and docker).
	* **Deployment**<a name="ddep"></a>
		* [Hawkeye](https://github.com/hawkeyesec/scanner-cli)
			* The Hawkeye scanner-cli is a project security, vulnerability and general risk highlighting tool. It is meant to be integrated into your pre-commit hooks and your pipelines.
	* **Dockerfiles**<a name="ddock"></a>
		* [Dockerfile reference - docs.docker.com](https://docs.docker.com/engine/reference/builder/)
		* [How to write excellent Dockerfiles - Jakub Skalecki](https://rock-it.pl/how-to-write-excellent-dockerfiles/)
		* [What is the purpose of VOLUME in Dockerfile - StackOverflow](https://stackoverflow.com/questions/34809646/what-is-the-purpose-of-volume-in-dockerfile)
		* **Collections**
			* [Dockerfiles - Jessie Frazelle](https://github.com/jessfraz/dockerfiles)
	* **Layers**<a name="dlay"></a>
		* [Optimising Docker Layers for Better Caching with Nix - Graham Christensen](https://grahamc.com/blog/nix-and-layered-docker-images)
	* **Logging & Monitoring**<a name="dlog"></a>)
		* [Docker container Logs and Process management - Bikram Kundu](https://jstobigdata.com/docker-container-logs-process-management/)
		* [Top 10 Docker logging gotchas every Docker user should know(2017) - Stefan Thies](https://jaxenter.com/docker-logging-gotchas-137049.html)
		* [Docker Reference Architecture: Docker Logging Design and Best Practices - docker.com](https://success.docker.com/article/logging-best-practices)
		* [Docker Logging, a Hitchhiker's Guide - Nicolas Frankel](https://www.exoscale.com/syslog/docker-logging/)
		* [How to redirect Docker logs to a single file - Erik Dietrich](https://www.scalyr.com/blog/how-to-redirect-docker-logs-to-a-single-file)
		* [Reducing Deploy Risk With Docker’s Health Check Instruction - newrelic.com](https://blog.newrelic.com/engineering/docker-health-check-instruction/)
	* **Namespaces**<a name="dns"></a>
		* [Introduction to User Namespaces in Docker Engine - Docker](https://success.docker.com/article/introduction-to-user-namespaces-in-docker-engine)
		* [Hardening Docker Hosts with User Namespaces - Linux.com](https://www.linux.com/tutorials/hardening-docker-hosts-user-namespaces/)
	* **Networking**<a name="dnet"></a>
		* [Networking overview - docs.docker](https://docs.docker.com/network/)
	* **Privileges**<a name="dpriv"></a>
		* [Is it possible to escalate privileges and escaping from a Docker container? - StackOverflow](https://security.stackexchange.com/questions/152978/is-it-possible-to-escalate-privileges-and-escaping-from-a-docker-container)
		* [Abusing Privileged and Unprivileged Linux Containers - nccgroup](https://www.nccgroup.trust/uk/our-research/abusing-privileged-and-unprivileged-linux-containers/)
	* **Security**<a name="dsec"></a>
		* **General**
			* [Docker security - docs.docker](https://docs.docker.com/engine/security/security/)
		* **Attacking**
			* [The Dangers of Docker.sock](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)
			* [On Docker security: 'docker' group considered harmful - Andreas Jung](https://www.zopyx.com/andreas-jung/contents/on-docker-security-docker-group-considered-harmful)
			* [Docker Container Breakout Proof-of-Concept Exploit - James Turnbull(2014)](https://blog.docker.com/2014/06/docker-container-breakout-proof-of-concept-exploit/)
			* [Vulnerability Exploitation in Docker Container Environments - Anthony Bettini(BH EU 2015)](https://www.blackhat.com/docs/eu-15/materials/eu-15-Bettini-Vulnerability-Exploitation-In-Docker-Container-Environments-wp.pdf)
			* [Attacking & Auditing Docker Containers Using Open Source tools - Madhu Akula](https://www.youtube.com/watch?v=ru7GicI5iyI)
				* [Defcon 26 Workshop](https://www.defcon.org/html/defcon-26/dc-26-workshops.html#akula)
			* [Whaler](https://github.com/P3GLEG/Whaler)
				* Program to reverse Docker images into Dockerfiles
			* [Docker for Hackers? A pen tester’s guide - Robert Bone](https://www.pentestpartners.com/security-blog/docker-for-hackers-a-pen-testers-guide/)
			* [Harpoon](https://github.com/ProfessionallyEvil/harpoon)
	    		* A collection post-exploitation scripts for determining if that shell you just got is in a container, what kind, and ways to escape.
			* [You can't contain me! :: Analyzing and Exploiting an Elevation of Privilege Vulnerability in Docker for Windows - srcincite.io](https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html)
		* **Securing**
			* **101**
				* [Docker security - docs.docker](https://docs.docker.com/engine/security/security/)
				* [CIS Benchmarks: Docker](https://www.cisecurity.org/benchmark/docker/)
			* **Articles/Blogposts/Writeups**
				* [10 Docker Image Security Best Practices - Liran Tal, Omer Levi Hevroni(snyk)](https://snyk.io/blog/10-docker-image-security-best-practices/)
				* [Docker Security Best-Practices - Peter Benjamin](https://dev.to/petermbenjamin/docker-security-best-practices-45ih)
				* [Security Risks and Benefits of Docker Application Containers - Lenny Zeltser](https://zeltser.com/security-risks-and-benefits-of-docker-application/)
				* [Hardening Docker Containers & Images - The Ultimate Security Guide - Yathi Naik](https://www.stackrox.com/post/2017/08/hardening-docker-containers-and-hosts-against-vulnerabilities-a-security-toolkit/)
				* [Added no-new-privileges Security Flag to Docker - Mrunal Patel](http://www.projectatomic.io/blog/2016/03/no-new-privs-docker/)
				* [Making Docker images read-only in production - Dan Walsh](http://www.projectatomic.io/blog/2015/12/making-docker-images-write-only-in-production/)
				* [Your Docker Image IDs are secrets, and it’s time you treated them that way! - Quay.io](https://medium.com/@quayio/your-docker-image-ids-are-secrets-and-its-time-you-treated-them-that-way-f55e9f14c1a4)
				* [Docker Security: Best Practices for your Vessel and Containers - linux-audit.com](https://linux-audit.com/docker-security-best-practices-for-your-vessel-and-containers/)
				* [Follow Up: Container Scanning Comparison - kubedex](https://kubedex.com/follow-up-container-scanning-comparison/)
				* [The Danger of Exposing Docker.sock](https://dejandayoff.com/the-danger-of-exposing-docker.sock/)
					* Exposing /var/run/docker.sock could lead to full environment takeover.
			* **Tools**
				* [Docker Bench for Security](https://github.com/docker/docker-bench-security)
					* The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production. The tests are all automated, and are inspired by the CIS Docker Benchmark v1.2.0.
				* [bane](https://github.com/genuinetools/bane)
					* AppArmor profile generator for docker containers. Basically a better AppArmor profile, than creating one by hand, because who would ever do that.
		* **Talks & Presentations**
			* [An Attacker Looks at Docker: Approaching Multi-Container Applications - Wesley McGrew](https://i.blackhat.com/us-18/Thu-August-9/us-18-McGrew-An-Attacker-Looks-At-Docker-Approaching-Multi-Container-Applications-wp.pdf)
			* [Docker: Security Myths, Security Legends - Rory McCune](https://www.youtube.com/watch?v=uQigvjSXMLw)
			* [Securing The Docker Containers At CI/CD Pipeline Level - Alina Radu(BSidesBCN 2019)](https://www.youtube.com/watch?v=4whoQoNpu9Y&list=PLDuy2rk8e-D-foVf0ylfnHhSo2elmxRqy&index=10&t=0s)
			* [How to Lose a Container in 10 Minutes - Sarah Young(BSidesSF 2019)](https://www.youtube.com/watch?v=fSj6_WgDATE&list=PLbZzXF2qC3RvGRbNQwKcf2KVaTCjzOB8o&index=4)
				* Moving to the cloud and deploying containers? In this talk I will discuss both the mindset shift and tech challenges, with some common mistakes made in real-life deployments with some real life (albeit redacted) examples. We'll also look at what happens to a container that's been left open to the Internet for the duration of the talk.
			* [Well, That Escalated Quickly! How Abusing Docker API Led to Remote Code Execution, Same Origin Bypass and Persistence in The Hypervisor via Shadow Containers - Michael Cherny, Sagi Dulce(BH US 17)](https://www.blackhat.com/docs/us-17/thursday/us-17-Cherny-Well-That-Escalated-Quickly-How-Abusing-The-Docker-API-Led-To-Remote-Code-Execution-Same-Origin-Bypass-And-Persistence_wp.pdf)
	* **Storage**<a name="dstorage"></a>
		* [Why Containers Miss a Major Mark: Solving Persistent Data in Docker - Chris Brandon](https://storageos.com/why-containers-miss-a-major-mark-solving-persistent-data-in-docker/)
	* **Tools**<a name="dtools"></a>
		* [docker-layer2-icc](https://github.com/brthor/docker-layer2-icc)
			* Demonstrating that disabling ICC in docker does not block raw packets between containers.
		* [docker-bench-security](https://github.com/docker/docker-bench-security)
			* The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production.	
		* [Vulnerable Docker VM](https://www.notsosecure.com/vulnerable-docker-vm/)
			* For practicing pen testing docker instances
* **Jails**<a name="jails"></a>
	* **101**
		* [FreeBSD Handbook: Jails](https://www.freebsd.org/doc/handbook/jails.html)
	* **Tools**<a name="jtools"></a>
		* [ezjail – Jail administration framework](https://erdgeist.org/arts/software/ezjail/)
* **LXC**
	* **101**
		* [Linux containers](https://linuxcontainers.org/)
	* **Articles/Blogposts/Writeups**
		* [LXC 1.0: Blog post series [0/10] - Stephane Graber](https://stgraber.org/2013/12/20/lxc-1-0-blog-post-series/)
* **Kubernetes**<a name="kubernetes"></a>
	* **101**<a name="k101"></a>
		* [An Introduction to Kubernetes(2018) - Justin Ellingwood(DO tutorials)](https://www.digitalocean.com/community/tutorials/an-introduction-to-kubernetes)
	* **Articles/Blogposts/Writeups**
	* **Secrets Management**
		* [Kamus](https://github.com/Soluto/kamus)
			* An open source, GitOps, zero-trust secrets encryption and decryption solution for Kubernetes applications. Kamus enable users to easily encrypt secrets than can be decrypted only by the application running on Kubernetes. The encryption is done using strong encryption providers (currently supported: Azure KeyVault, Google Cloud KMS and AES). To learn more about Kamus, check out the blog post and slides.
	* **Security**<a name="ksec"></a>
		* **101**
			* [CIS Kubernetes Security Benchmarks](https://www.cisecurity.org/benchmark/kubernetes/)
		* **Articles/Blogposts/Writeups**
			* [Kubernetes Security Best-Practices - Peter Benjamin](https://dev.to/petermbenjamin/kubernetes-security-best-practices-hlk)
			* [hardening-kubernetes from-scratch](https://github.com/hardening-kubernetes/from-scratch)
				* A hands-on walkthrough for creating an extremely insecure Kubernetes cluster and then hardening it, step by step.
			* [Kubernetes security best practices - Christian Melendez](https://blog.sqreen.com/kubernetes-security-best-practices/)
			* [Kubernetes Hardening - Moshe Roth](https://itnext.io/kubernetes-hardening-d24bdf7adc25)
			* [Attacking default installs of Helm on Kubernetes - ropnop](https://blog.ropnop.com/attacking-default-installs-of-helm-on-kubernetes/)
			* [Kubernetes Security - Best Practice Guide - freach](https://github.com/freach/kubernetes-security-best-practice)
			* [Container Platform Security at Cruise - Karl Isenberg](https://medium.com/cruise/container-platform-security-7a3057a27663)
		* **Attacking**
			* [Attacking Kubernetes - A Guide for Administrators and Penetration Testers(Atredis Partners)](https://github.com/kubernetes/community/blob/master/wg-security-audit/findings/AtredisPartners_Attacking_Kubernetes-v1.0.pdf)
			* [Kubernetes Pentest Methodology Part 2 - Or Ida](https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-2/)
			* [Analysing and Exploiting Kubernetes APIServer Vulnerability Kubernetes CVE - CVE-2018–1002105 - Abhisek Datta](https://blog.appsecco.com/analysing-and-exploiting-kubernetes-apiserver-vulnerability-cve-2018-1002105-3150d97b24bb)
			* [DIY Pen-Testing for Your Kubernetes Cluster - Liz Rice](https://www.youtube.com/watch?v=fVqCAUJiIn0&feature=youtu.be)
			* [Tools and Methods for Auditing Kubernetes RBAC Policies - Mark Manning(NCCGroup)](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/august/tools-and-methods-for-auditing-kubernetes-rbac-policies/)
			* [A hacker's guide to Kubernetes security - Rory McCune](https://techbeacon.com/enterprise-it/hackers-guide-kubernetes-security)
			* [The security footgun in etcd - gcollazo](https://gcollazo.com/the-security-footgun-in-etcd/)
			* [Hacking Kubelet on Google Kubernetes Engine - Marc Wickenden](https://www.4armed.com/blog/hacking-kubelet-on-gke/)
			* [Hacking DigitalOcean's New Kubernetes Service - Marc Wickenden](https://www.4armed.com/blog/hacking-digitalocean-kubernetes/)
			* [Kubletmein - A Tool for Abusing Kubelet Credentials - Marc Wickenden](https://www.4armed.com/blog/kubeletmein-kubelet-hacking-tool/)
			* [The Ultimate Guide to Kubernetes Security - Fei Huang & Gary Duan](https://neuvector.com/container-security/kubernetes-security-guide/)
			* [Persistent XSRF on Kubernetes Dashboard using Redhat Keycloak Gatekeeper on Microsof Azure -	Antonio Sanso ](https://blog.intothesymmetry.com/2018/12/persistent-xsrf-on-kubernetes-dashboard.html)
			* [The Kubernetes API call is coming from inside the cluster! - Paul Czarkowski](https://medium.com/@pczarkowski/the-kubernetes-api-call-is-coming-from-inside-the-cluster-f1a115bd2066)
			* [Kubernetes Attack Surface - cAdvisor - raesene](https://raesene.github.io/blog/2016/10/14/Kubernetes-Attack-Surface-cAdvisor/)
			* [Kubernetes Attack Surface - etcd - raesene](https://raesene.github.io/blog/2017/05/01/Kubernetes-Security-etcd/)
			* [Kubernetes Attack Surface - Service Tokens - raesene](https://raesene.github.io/blog/2017/04/02/Kubernetes-Service-Tokens/)
			* [Securing Kubernetes Clusters by Eliminating Risky Permissions - Eviatar Gerzi](https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/)
			* [Attacking Kubernetes through Kubelet - Alexandre Kaskasoli](https://labs.f-secure.com/blog/attacking-kubernetes-through-kubelet/)
		* **Carnal0wnage Posts**
			* [Kubernetes: open etcd - carnal0wnage](http://carnal0wnage.attackresearch.com/2019/01/kubernetes-open-etcd.html)
			* [Kubernetes: kube-hunter.py etcd - carnal0wnage](http://carnal0wnage.attackresearch.com/2019/01/kubernetes-kube-hunterpy-etcd.html)
			* [Kubernetes: cAdvisor - carnal0wnage](http://carnal0wnage.attackresearch.com/2019/01/kubernetes-cadvisor.html)
			* [Kubernetes: List of ports - carnal0wnage](https://carnal0wnage.attackresearch.com/2019/01/kubernetes-list-of-ports.html)
			* [Kubernetes: Kubernetes Dashboard - carnal0wnage](http://carnal0wnage.attackresearch.com/2019/01/kubernetes-kubernetes-dashboard.html)
			* [Kubernetes: Kube-Hunter 10255 - carnal0wnage](https://carnal0wnage.attackresearch.com/2019/01/kubernetes-kube-hunter-10255.html)
			* [Kubernetes: Kubelet API containerLogs endpoint - carnal0wnage](http://carnal0wnage.attackresearch.com/2019/01/kubernetes-kubelet-api-containerlogs.html)
			* [Kubernetes: unauth kublet API 10250 basic code exec - carnal0wnage](https://carnal0wnage.attackresearch.com/2019/01/kubernetes-unauth-kublet-api-10250.html)
			* [Kubernetes: unauth kublet API 10250 token theft & kubectl - carnal0wnage](https://carnal0wnage.attackresearch.com/2019/01/kubernetes-unauth-kublet-api-10250_16.html)
		* **CVEs**
			* [The silent CVE in the heart of Kubernetes apiserver - Abraham Ingersoll](https://gravitational.com/blog/kubernetes-websocket-upgrade-security-vulnerability/)
			* [CVE-2018-1002105](https://github.com/gravitational/cve-2018-1002105)
			* [CVE-2018-1002105 PoC](https://github.com/evict/poc_CVE-2018-1002105)
		* **Talks & Presentations**
			* [Hacking and Hardening Kubernetes Clusters by Example - Brad Geesaman(KubeCon 2017)](https://www.youtube.com/watch?v=vTgQLzeBfRU)
				* "an eye-opening journey examining real compromises and sensitive data leaks that can occur inside a Kubernetes cluster, highlighting the configurations that allowed them to succeed, applying practical applications of the latest built-in security features and policies to prevent those attacks, and providing actionable steps for future detection."
			* [Attacking and Defending Kubernetes [SeaSec East] - Jay Beale](https://www.youtube.com/watch?v=N_g0QXhJMRk&feature=share)
			* [Perfect Storm Taking the Helm of Kubernetes - Ian Coldwater(Derbycon2018)](https://www.youtube.com/watch?v=1k-GIDXgfLw)
				* Containers don't always contain. For attackers, Kubernetes contains a number of interesting attack surfaces and opportunities for exploitation. For defenders and operators, it's complicated to set up and the defaults often aren't enough. This can create a perfect storm. This talk will walk you through attacking Kubernetes clusters, and give defenders tools and techniques to protect themselves from shipwrecks.
			* [A Hacker's Guide to Kubernetes and the Cloud - Rory McCune(Cloud Native ConEU18)](https://www.youtube.com/watch?v=dxKpCO2dAy8)
				* As Kubernetes increases in adoption it is inevitable that more clusters will come under attack by people wanting to compromise specific applications or just people looking to get access to resources for things like crypto-coin mining. The goal of this talk is to take an attackers perspective on typical cloud-based Kubernetes deployments, examine how attackers will find and compromise clusters and the applications running on them and suggest practical ways to improve the security of your cluster. This talk will draw on the presenters long experience of offensive security to provide an attacker's eye view of the challenges of running production Kubernetes clusers in cloud-facing environments.
			* [Shipping in Pirate-Infested Waters: Practical Attack and Defense in Kubernetes - Greg Castle, CJ Cullen](https://www.youtube.com/watch?v=ohTq0no0ZVU)
				* Kubernetes has a growing array of security controls available, but knowing where they all fit in, what the highest priorities are, and how it all helps against real attacks is still far from obvious. In this talk we’ll take a vulnerable application, exploit it, install tools, escalate privileges, propagate between containers and gain control of the cluster. At each stage of the attack we’ll demonstrate how proactive steps could have prevented these actions (or at least made them more difficult), from the container build process to writing RBAC/PodSecurity/AppArmor/Network policies, and more. Since configuration of each defence could be the subject of it’s own deep-dive talk, we’ll mainly focus on the big picture of “what” technologies you’d use to configure your cluster securely and “why”.
			* [DIY Pen-Testing for Your Kubernetes Cluster - Liz Rice](https://www.youtube.com/watch?v=fVqCAUJiIn0&feature=youtu.be)
				* See how to use kube-hunter to run penetration tests on your Kubernetes clusters, and reveal misconfigurations that might leave you open to attack!     Kube-hunter is an open source tool that simulates what a hacker might do when trying to attack a deployment.     We’ll discuss the motivations behind the project, and some interesting aspects of how it is implemented.     There will be plenty of demos, including:  - Testing for the basics, like an unsecured Kubelet API  - Simulating an attack from within a compromised container   - Re-using credentials from a compromised container    You'll need a basic understanding of Kubernetes components, and with using curl to issue API requests.    You’ll leave this talk ready to test your own cluster, and with new insights into the possible routes that an attacker might attempt. Perhaps you’ll even be inspired to submit a new Hunter to the project! 
			* [Ship of Fools: Shoring up Kubernetes Security - Ian Coldwater(devopsdays Minneapolis 2018)](https://www.youtube.com/watch?v=n9ljS-TQRQE&list=PLKDRii1YwXnLmd8ngltnf9Kzvbja3DJWx&index=2&t=0s)
				* This talk will give you practical advice about securing your Kubernetes clusters, from an attacker’s perspective. We’ll walk through the attack process from discovery to post-exploitation, and you’ll walk away with tools and techniques that can be used for prevention along the way. Learn how to keep your infrastructure safer by making a hacker’s job harder.
			* [Crafty Requests: Deep Dive Into Kubernetes CVE-2018-1002105 - Ian Coldwater(CloudNativeConEU19)](https://www.youtube.com/watch?v=VjSJqc13PNk&list=PLKDRii1YwXnLmd8ngltnf9Kzvbja3DJWx&index=6&t=0s)
				* You may have heard about CVE-2018-1002105, one of the most severe Kubernetes security vulnerabilities of all time. But how does this flaw work? How can it be exploited, and what does it all mean? This deep dive will walk the audience through the Kubernetes back end, going over relevant concepts like aggregated API servers, the kubelet API, and permissions for namespace-constrained users. We will explain the details of how this flaw works, how a cluster’s moving parts can fit together to create a vulnerable context, and the risks involved in leaving this CVE unpatched in the wild. A live demonstration will show the audience exactly how easy it is to exploit this vulnerability. After explaining the attack pathways, the audience will leave with practical advice about mitigation and how to protect their clusters. 
	* **Tools**
		* **Authentication**
		* **Operating**
			* [kops](https://github.com/kubernetes/kops)
				* Kubernetes Operations (kops) - Production Grade K8s Installation, Upgrades, and Management
		* **Security**
			* [Kube-hunter](https://github.com/aquasecurity/kube-hunter)
				* Kube-hunter hunts for security weaknesses in Kubernetes clusters. The tool was developed to increase awareness and visibility for security issues in Kubernetes environments.
			* [kubeaudit](https://github.com/Shopify/kubeaudit)
				* kubeaudit helps you audit your Kubernetes clusters against common security controls
			* [kube-bench](https://github.com/aquasecurity/kube-bench)
				* kube-bench is a Go application that checks whether Kubernetes is deployed securely by running the checks documented in the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes/).
		* [Install and run a SPIRE Server and Agent locally on a Kubernetes cluster](https://spiffe.io/spire/getting-started-k8s/)
			* This tutorial walks you through getting a SPIRE Server and SPIRE Agent running in a Kubernetes cluster, and configuring a workload container to access SPIRE.
		* [Argo](https://github.com/argoproj/argo)
			* Argoproj is a collection of tools for getting work done with Kubernetes.
* **Mesos**<a name="mesos"></a>
	* **101**<a name="m101"></a>
		* [Apache Mesos - Wikipedia](https://en.wikipedia.org/wiki/Apache_Mesos)
		* [Mesos Architecture - mesos.apache](http://mesos.apache.org/documentation/latest/architecture/)
		* [Apache Mesos Documentation](http://mesos.apache.org/documentation/latest/)
		* [What does Apache Mesos actually do? - stackoverflow](https://stackoverflow.com/questions/28094147/what-does-apache-mesos-actually-do)
		* [What's the difference between Apache's Mesos and Google's Kubernetes - stackoverflow](https://stackoverflow.com/questions/26705201/whats-the-difference-between-apaches-mesos-and-googles-kubernetes?noredirect=1)
		* [What does Apache Mesos do that Kubernetes can't do and vice-versa? - stackoverflow](https://stackoverflow.com/questions/47769570/what-does-apache-mesos-do-that-kubernetes-cant-do-and-vice-versa?rq=1)
	* **Articles/Blogposts/Writeups**
	* **Securing**
	* **Tools**
		* [PaaSTA](https://github.com/Yelp/paasta)
			* PaaSTA is a highly-available, distributed system for building, deploying, and running services using containers and Apache Mesos!
* **RunC**<a name="runc"></a>
	* **101**<a name="r101"></a>
		* [One of the original developers of cgroups on why it was created](https://news.ycombinator.com/item?id=20599672)
	* **Articles/Blogposts/Writeups**
	* **Securing**
	* **Tools**



------------------------
### Sort
	
* [How to implement an open source container security stack (part 1)(2018) - Mateo Burillo](https://sysdig.com/blog)

* [Gravity](https://github.com/gravitational/gravity)
	* Gravity is an open source toolkit for creating "images" of Kubernetes clusters and the applications running inside the clusters. The resulting images are called cluster images and they are just .tar files.

* [Container Forensics: What to Do When Your Cluster is a Cluster - Maya Kaczorowski & Ann Wallace(CloudNativeConEU19) ](https://www.youtube.com/watch?v=MyXROAqO7YI&list=PLKDRii1YwXnLmd8ngltnf9Kzvbja3DJWx&index=7&t=0s)
	* When responding to an incident in your containers, you don’t necessarily have the same tools at your disposal that you do with VMs - and so your incident investigation process and forensics are different. In a best case scenario, you have access to application logs, orchestrator logs, node snapshots, and more.  In this talk, we’ll go over where to get information about what’s happening in your cluster, including logs and open source tools you can install, and how to tie this information together to get a better idea of what’s happening in your infrastructure. Armed with this info, we’ll review the common mitigation options such as to alert, isolate, pause, restart, or kill a container. For common types of container attacks, we'll discuss what options are best and why. Lastly, we’ll talk about restoring services after an incident, and the best steps to take to prevent the next one. 

* [Photon OS](https://github.com/vmware/photon)
	* Photon OS™ is an open source Linux container host optimized for cloud-native applications, cloud platforms, and VMware infrastructure. Photon OS provides a secure run-time environment for efficiently running containers.
* [T19 Challenge – Twistlock Lab’s first security challenge summary and solutions](https://www.twistlock.com/labs-blog/t19-challenge-twistlock-labs-first-security-challenge-summary-solutions/)
* [The Twelve-Factor App](https://12factor.net/)

* [6 Ways Ansible Makes Docker-Compose BETTER - ](https://www.ansible.com/blog/six-ways-ansible-makes-docker-compose-better)
	* [The AWX Project FAQ](https://www.ansible.com/products/awx-project/faq)
* [Runtimes And the Curse of the Privileged Container - brauner](https://brauner.github.io/2019/02/12/privileged-containers.html)
* [Understanding how uid and gid work in Docker containers - Marc Campbell](https://medium.com/@mccode/understanding-how-uid-and-gid-work-in-docker-containers-c37a01d01cf)
Solaris Zones
	* https://docs.oracle.com/cd/E18440_01/doc.111/e18415/chapter_zones.htm#OPCUG426
	https://en.wikipedia.org/wiki/Solaris_Containers
	https://www.fujitsu.com/global/products/computing/servers/unix/sparc-enterprise/software/solaris10/container/zone/
https://sysdig.com/blog/oss-container-security-stack/
https://sysdig.com/blog/docker-image-scanning/
https://docs.google.com/presentation/d/1u6S1ycs8DURORf6S9XYKjP56oszJpouOca6xlkH9ILs/edit#slide=id.p
https://medium.com/@mccode/understanding-how-uid-and-gid-work-in-docker-containers-c37a01d01cf
* [Getting vulnerabilities and metadata for images - cloud.google](https://cloud.google.com/container-registry/docs/get-image-vulnerabilities)

https://blog.aquasec.com/dns-spoofing-kubernetes-clusters
https://blog.aquasec.com/a-brief-history-of-containers-from-1970s-chroot-to-docker-2016
https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-2/

https://blog.appsecco.com/from-thick-client-exploitation-to-becoming-kubernetes-cluster-admin-the-story-of-a-fun-bug-we-fe92a7e70aa2
