# Containers


---------------------
## Table of contents
- []()
- []()
- []()
- []()

--------------------


https://wiki.unraid.net/UnRAID_6/Overview#Containers

Understanding and HardeningLinux Containers - NCCGroup

https://blog.appsecco.com/analysing-and-exploiting-kubernetes-apiserver-vulnerability-cve-2018-1002105-3150d97b24bb?gi=da5afbcc2d73

https://github.com/ProfessionallyEvil/harpoon
https://github.com/P3GLEG/Whaler
https://samaritan.ai/blog/reversing-docker-images-into-dockerfiles/
http://ifeanyi.co/posts/linux-namespaces-part-1/
http://ifeanyi.co/posts/linux-namespaces-part-2/

Mesos
	https://stackoverflow.com/questions/47769570/what-does-apache-mesos-do-that-kubernetes-cant-do-and-vice-versa?rq=1
	https://stackoverflow.com/questions/26705201/whats-the-difference-between-apaches-mesos-and-googles-kubernetes?noredirect=1
	https://stackoverflow.com/questions/28094147/what-does-apache-mesos-actually-do
	http://mesos.apache.org/documentation/latest/architecture/
	http://mesos.apache.org/documentation/latest/
	

* [Create a Reusable Burner OS with Docker, Part 1: Making an Ubuntu Hacking Container - EvilToddler](https://null-byte.wonderhowto.com/how-to/create-reusable-burner-os-with-docker-part-1-making-ubuntu-hacking-container-0175328/)
	* [Part 2](https://null-byte.wonderhowto.com/how-to/create-reusable-burner-os-with-docker-part-2-customizing-our-hacking-container-0175353/)
* [Docker Your Command & Control (C2) - obscuritylabs](https://blog.obscuritylabs.com/docker-command-controll-c2/)
* [Vulnerable Docker VM - notsosecure](https://www.notsosecure.com/vulnerable-docker-vm/)


Peter Benjamins blogposts
https://www.youtube.com/playlist?list=PLKDRii1YwXnLmd8ngltnf9Kzvbja3DJWx

https://www.youtube.com/watch?v=fVqCAUJiIn0&feature=youtu.be
https://www.youtube.com/watch?v=UwBshgfnAGA

https://www.youtube.com/watch?v=ru7GicI5iyI
https://docs.google.com/presentation/d/1u6S1ycs8DURORf6S9XYKjP56oszJpouOca6xlkH9ILs/edit#slide=id.p
https://sysdig.com/blog/docker-image-scanning/


https://sysdig.com/blog/oss-container-security-runtime/
https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/august/tools-and-methods-for-auditing-kubernetes-rbac-policies/
http://sven.stormbind.net/blog/posts/docker_from_30_to_230/



http://www.slideshare.net/jpetazzo/linux-containers-lxc-docker-and-security
https://www.blackhat.com/docs/eu-15/materials/eu-15-Bettini-Vulnerability-Exploitation-In-Docker-Container-Environments-wp.pdf
https://www.sumologic.com/blog-security/securing-docker-containers/
https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/2016/april/ncc_group_understanding_hardening_linux_containers-10pdf/

https://medium.com/cruise/building-a-container-platform-at-cruise-part-1-507f3d561e6f



https://itnext.io/kubernetes-hardening-d24bdf7adc25
https://blog.ropnop.com/attacking-default-installs-of-helm-on-kubernetes/

https://www.pentestpartners.com/security-blog/docker-for-hackers-a-pen-testers-guide/




Docker
* https://github.com/wsargent/docker-cheat-sheet
* https://www.nccgroup.trust/globalassets/our-research/us/whitepapers/2016/april/ncc_group_understanding_hardening_linux_containers-1-1.pdf
* https://www.slideshare.net/jpetazzo/linux-containers-lxc-docker-and-security
* http://www.projectatomic.io/blog/2014/08/is-it-safe-a-look-at-docker-and-security-from-linuxcon/
* https://linux-audit.com/docker-security-best-practices-for-your-vessel-and-containers/
* https://blog.docker.com/2016/02/docker-engine-1-10-security/
* https://medium.com/@quayio/your-docker-image-ids-are-secrets-and-its-time-you-treated-them-that-way-f55e9f14c1a4
* https://github.com/konstruktoid/Docker/blob/master/Security/CheatSheet.adoc
* https://github.com/docker/docker-bench-security
* https://blog.docker.com/2015/05/understanding-docker-security-and-best-practices/
* http://www.projectatomic.io/blog/2016/03/no-new-privs-docker/
* https://container-solutions.com/content/uploads/2015/06/15.06.15_DockerCheatSheet_A2.pdf
* https://github.com/genuinetools/bane






----------------------
### <a name="containers"></a>Containers
* **101**
	* [LXC - Wikipedia](https://en.wikipedia.org/wiki/LXC)
	* [Process Containers - lwn.net](https://lwn.net/Articles/236038/)
	* [cgroups - wikipedia](https://en.wikipedia.org/wiki/Cgroups)
	* [Everything you need to know about Jails - bsdnow.tv](http://www.bsdnow.tv/tutorials/jails)
	* [Jails - FreeBSD handbook](https://www.freebsd.org/doc/handbook/jails.html)
	* [xkcd on containers](https://xkcd.com/1988/)
* **Containers(General)**
	 * **101**
		* [Linux LXC vs FreeBSD jail - Are there any notable differences between LXC (Linux containers) and FreeBSD's jails in terms of security, stability & performance? - unix.StackExchange](https://unix.stackexchange.com/questions/127001/linux-lxc-vs-freebsd-jail)
		* [Architecting Containers Part 1: Why Understanding User Space vs. Kernel Space Matters - Scott McCarty](https://www.redhat.com/en/blog/architecting-containers-part-1-why-understanding-user-space-vs-kernel-space-matters)
	* **Building**
		* [Best practices for building containers - cloud.google](https://cloud.google.com/solutions/best-practices-for-building-containers)
		* [img](https://github.com/genuinetools/img)
			* Standalone, daemon-less, unprivileged Dockerfile and OCI compatible container image builder.
	* **Capabilities**
		* [Exploiting capabilities: Parcel root power, the dark side of capabilities - Emeric Nasi](http://blog.sevagas.com/IMG/pdf/exploiting_capabilities_the_dark_side.pdf)
	* **General**
		* [Getting Towards Real Sandbox Containers - Jesse Frazelle(May2016)](https://blog.jessfraz.com/post/getting-towards-real-sandbox-containers/)
		* [Best Practices for Operating Containers - cloud.google](https://cloud.google.com/solutions/best-practices-for-operating-containers)
			* This article describes a set of best practices for making containers easier to operate. These practices cover a wide range of topics, from security to monitoring and logging.
	 * **Namespaces**
		* [Controlling access to user namespaces - lwn.net](https://lwn.net/Articles/673597/)
		* [Namespaces in operation, part 1: namespaces overview - lwn.net](https://lwn.net/Articles/531114/#series_index)
	* **Privilegs**
		* [Privilege Escalation via lxd - Josiah Beverton](https://reboare.github.io/lxd/lxd-escape.html)
	* **Security**
		* [Understanding and Hardening Linux Containers - nccgroup](https://www.nccgroup.trust/uk/our-research/understanding-and-hardening-linux-containers/)
			* Linux containers offer native OS virtualisation, segmented by kernel namespaces, limited through process cgroups and restricted through reduced root capabilities, Mandatory Access Control and user namespaces. This paper discusses these container features, as well as exploring various security mechanisms. Also included is an examination of attack surfaces, threats, and related hardening features in order to properly evaluate container security. Finally, this paper contrasts different container defaults and enumerates strong security recommendations to counter deployment weaknesses-- helping support and explain methods for building high-security Linux containers. Are Linux containers the future or merely a fad or fantasy? This paper attempts to answer that question.
		* [Containers and Cloud Security - James Bottomley(2018)](https://blog.hansenpartnership.com/containers-and-cloud-security/)
			* The idea behind this blog post is to take a new look at how cloud security is measured and what its impact is on the various actors in the cloud ecosystem.
		* [Exploring container security: An overview - Maya Kaczorowski(GCP Focused)](https://cloud.google.com/blog/products/gcp/exploring-container-security-an-overview?m=1)
	* **Tools**
		* [nsjail](https://github.com/google/nsjail)
			* A light-weight process isolation tool, making use of Linux namespaces and seccomp-bpf syscall filters (with help of the kafel bpf language)


* **Docker**
	* **101**
		* [Get Started, Part 1: Orientation and setup - docs.docker](https://docs.docker.com/get-started/)
		* [Play with Docker Classroom - Docker](https://training.play-with-docker.com/)
			* The Play with Docker classroom brings you labs and tutorials that help you get hands-on experience using Docker.
	* **Compose**
	* **Containers & Images**
		* **101**
			* [Docker Image Specification v1.0.0](https://github.com/moby/moby/blob/master/image/spec/v1.md)
			* [Docker image in depth - Bikram Kundu](https://jstobigdata.com/docker-image-in-depth/)
		* **Analysis**
			* [Static Analysis of Docker image vulnerabilities with Clair - Petr Kohut](https://www.nearform.com/blog/static-analysis-of-docker-image-vulnerabilities-with-clair/)
		* **Building**
			* **Articles/Blogposts/Writeups**
				* [Debugging Docker builds - Hongli Lai](https://www.joyfulbikeshedding.com/blog/2019-08-27-debugging-docker-builds.html)
			* **Tools**
				* [img](https://github.com/genuinetools/img)
					* Standalone, daemon-less, unprivileged Dockerfile and OCI compatible container image builder.
		* **Scanning**
			* **Articles/Blogposts/Writeups**
				* [Docker Security Best Practices: Part 3 – Securing Container Images - Jeremy Valance](https://anchore.com/docker-security-best-practices-part-3-securing-container-images/)
				* [How to implement Docker image scanning with open source tools - Mateo Burillo](https://sysdig.com/blog/docker-image-scanning/)
				* [Scanning Docker images with CoreOS Clair - wdijkerman](https://werner-dijkerman.nl/2019/01/28/scanning-docker-images-with-coreos-clair/)
			* **Tools**
				* [clair](https://github.com/coreos/clair)
					* Clair is an open source project for the static analysis of vulnerabilities in application containers (currently including appc and docker).
	* **Deployment**
		* [Hawkeye](https://github.com/hawkeyesec/scanner-cli)
			* The Hawkeye scanner-cli is a project security, vulnerability and general risk highlighting tool. It is meant to be integrated into your pre-commit hooks and your pipelines.
	* **Dockerfiles** 
		* [Dockerfile reference - docs.docker.com](https://docs.docker.com/engine/reference/builder/)
		* [How to write excellent Dockerfiles - Jakub Skalecki](https://rock-it.pl/how-to-write-excellent-dockerfiles/)
		* [What is the purpose of VOLUME in Dockerfile - StackOverflow](https://stackoverflow.com/questions/34809646/what-is-the-purpose-of-volume-in-dockerfile)
		* **Collections**
			* [Dockerfiles - Jessie Frazelle](https://github.com/jessfraz/dockerfiles)
	* **Layers**
		* [Optimising Docker Layers for Better Caching with Nix - Graham Christensen](https://grahamc.com/blog/nix-and-layered-docker-images)
	* **Logging**
		* [Docker container Logs and Process management - Bikram Kundu](https://jstobigdata.com/docker-container-logs-process-management/)
	* **Monitoring**
		* [Reducing Deploy Risk With Docker’s Health Check Instruction - newrelic.com](https://blog.newrelic.com/engineering/docker-health-check-instruction/)
	* **Namespaces**
		* [Introduction to User Namespaces in Docker Engine - Docker](https://success.docker.com/article/introduction-to-user-namespaces-in-docker-engine)
		* [Hardening Docker Hosts with User Namespaces - Linux.com](https://www.linux.com/tutorials/hardening-docker-hosts-user-namespaces/)
	* **Networking**
		* [Networking overview - docs.docker](https://docs.docker.com/network/)
	* **Privileges**
		* [Is it possible to escalate privileges and escaping from a Docker container? - StackOverflow](https://security.stackexchange.com/questions/152978/is-it-possible-to-escalate-privileges-and-escaping-from-a-docker-container)
		* [Abusing Privileged and Unprivileged Linux Containers - nccgroup](https://www.nccgroup.trust/uk/our-research/abusing-privileged-and-unprivileged-linux-containers/)
	* **Security**
		* **General**
			* [Docker security - docs.docker](https://docs.docker.com/engine/security/security/)
		* **Attacking**
			* [The Dangers of Docker.sock](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)
			* [On Docker security: 'docker' group considered harmful - Andreas Jung](https://www.zopyx.com/andreas-jung/contents/on-docker-security-docker-group-considered-harmful)
			* [Docker Container Breakout Proof-of-Concept Exploit - James Turnbull(2014)](https://blog.docker.com/2014/06/docker-container-breakout-proof-of-concept-exploit/)
		* **Securing**
			* [Docker Security Best-Practices - Peter Benjamin](https://dev.to/petermbenjamin/docker-security-best-practices-45ih)
			* [Security Risks and Benefits of Docker Application Containers - Lenny Zeltser](https://zeltser.com/security-risks-and-benefits-of-docker-application/)
			* [Hardening Docker Containers & Images - The Ultimate Security Guide - Yathi Naik](https://www.stackrox.com/post/2017/08/hardening-docker-containers-and-hosts-against-vulnerabilities-a-security-toolkit/)
		* **Talks & Presentations**
			* [An Attacker Looks at Docker: Approaching Multi-Container Applications - Wesley McGrew](https://i.blackhat.com/us-18/Thu-August-9/us-18-McGrew-An-Attacker-Looks-At-Docker-Approaching-Multi-Container-Applications-wp.pdf)
			* [Docker: Security Myths, Security Legends - Rory McCune](https://www.youtube.com/watch?v=uQigvjSXMLw)
			* [Securing The Docker Containers At CI/CD Pipeline Level - Alina Radu(BSidesBCN 2019)](https://www.youtube.com/watch?v=4whoQoNpu9Y&list=PLDuy2rk8e-D-foVf0ylfnHhSo2elmxRqy&index=10&t=0s)
			* [How to Lose a Container in 10 Minutes - Sarah Young(BSidesSF 2019)](https://www.youtube.com/watch?v=fSj6_WgDATE&list=PLbZzXF2qC3RvGRbNQwKcf2KVaTCjzOB8o&index=4)
				* Moving to the cloud and deploying containers? In this talk I will discuss both the mindset shift and tech challenges, with some common mistakes made in real-life deployments with some real life (albeit redacted) examples. We'll also look at what happens to a container that's been left open to the Internet for the duration of the talk.
			* [Well, That Escalated Quickly! How Abusing Docker API Led to Remote Code Execution, Same Origin Bypass and Persistence in The Hypervisor via Shadow Containers - Michael Cherny, Sagi Dulce(BH US 17)](https://www.blackhat.com/docs/us-17/thursday/us-17-Cherny-Well-That-Escalated-Quickly-How-Abusing-The-Docker-API-Led-To-Remote-Code-Execution-Same-Origin-Bypass-And-Persistence_wp.pdf)
	* **Storage**
		* [Why Containers Miss a Major Mark: Solving Persistent Data in Docker - Chris Brandon](https://storageos.com/why-containers-miss-a-major-mark-solving-persistent-data-in-docker/)
	* **Tools**
		* [docker-layer2-icc](https://github.com/brthor/docker-layer2-icc)
			* Demonstrating that disabling ICC in docker does not block raw packets between containers.
		* [docker-bench-security](https://github.com/docker/docker-bench-security)
			* The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production.	
		* [Vulnerable Docker VM](https://www.notsosecure.com/vulnerable-docker-vm/)
			* For practicing pen testing docker instances
* **Jails**
	* **Tools**
		* [ezjail – Jail administration framework](https://erdgeist.org/arts/software/ezjail/)
* **Kubernetes**
	* **101**
		* [An Introduction to Kubernetes(2018) - Justin Ellingwood(DO tutorials)](https://www.digitalocean.com/community/tutorials/an-introduction-to-kubernetes)
	* **Articles/Blogposts/Writeups**
	* **Security**
		* **Articles/Blogposts/Writeups**
			* [Kubernetes Security Best-Practices - Peter Benjamin](https://dev.to/petermbenjamin/kubernetes-security-best-practices-hlk)
			* [hardening-kubernetes from-scratch](https://github.com/hardening-kubernetes/from-scratch)
				* A hands-on walkthrough for creating an extremely insecure Kubernetes cluster and then hardening it, step by step.
		* **Talks & Presentations**
			* [Hacking and Hardening Kubernetes Clusters by Example - Brad Geesaman(KubeCon 2017)](https://www.youtube.com/watch?v=vTgQLzeBfRU)
				* "an eye-opening journey examining real compromises and sensitive data leaks that can occur inside a Kubernetes cluster, highlighting the configurations that allowed them to succeed, applying practical applications of the latest built-in security features and policies to prevent those attacks, and providing actionable steps for future detection."
	* **Tools**
* **Mesos**
	* **101**
		* [Apache Mesos - Wikipedia](https://en.wikipedia.org/wiki/Apache_Mesos)
	* **Articles/Blogposts/Writeups**
	* **Securing**
	* **Tools**
		* [PaaSTA](https://github.com/Yelp/paasta)
			* PaaSTA is a highly-available, distributed system for building, deploying, and running services using containers and Apache Mesos!
* **RunC**
	* **101**
		* [One of the original developers of cgroups on why it was created](https://news.ycombinator.com/item?id=20599672)
	* **Articles/Blogposts/Writeups**
	* **Securing**
	* **Tools**


	
* [Kamus](https://github.com/Soluto/kamus)
	* An open source, GitOps, zero-trust secrets encryption and decryption solution for Kubernetes applications. Kamus enable users to easily encrypt secrets than can be decrypted only by the application running on Kubernetes. The encryption is done using strong encryption providers (currently supported: Azure KeyVault, Google Cloud KMS and AES). To learn more about Kamus, check out the blog post and slides.


* [REX-Ray](https://github.com/rexray/rexray)
	* REX-Ray provides a vendor agnostic storage orchestration engine. The primary design goal is to provide persistent storage for Docker, Kubernetes, and Mesos. The long-term goal of the REX-Ray project is to enable collaboration between organizations focused on creating enterprise-grade storage plugins for the Container Storage Interface (CSI).



https://github.com/kubernetes/community/blob/master/wg-security-audit/findings/AtredisPartners_Attacking_Kubernetes-v1.0.pdf
* [Install and run a SPIRE Server and Agent locally on a Kubernetes cluster](https://spiffe.io/spire/getting-started-k8s/)
	* This tutorial walks you through getting a SPIRE Server and SPIRE Agent running in a Kubernetes cluster, and configuring a workload container to access SPIRE.

https://github.com/freach/kubernetes-security-best-practice
https://github.com/argoproj/argo

* [Gravity](https://github.com/gravitational/gravity)
	* Gravity is an open source toolkit for creating "images" of Kubernetes clusters and the applications running inside the clusters. The resulting images are called cluster images and they are just .tar files.

http://carnal0wnage.attackresearch.com/2019/01/kubernetes-master-post.html?m=1
