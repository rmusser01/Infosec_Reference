# Building\_A\_Lab

## Table of Contents

* [General Info]()
* [Virtual Machines]()
* [Installing/Configuring Active Directory]()
* [Building a Pentest Lab]()
* [Infrastructure Automation]()
* **To Do**
  * Building a defensive Lab
  * Infra Automation

### General

* This page is supposed to be a collection of resources for building a lab for performing various security related tasks. Generally, the idea is that you setup a local VM hypervisor software\(VMware, Virtualbox\) and then install a virtual machine to perform testing and analysis without any impact to your "physical" machine.

### Virtual Machines

* **101**
  * [Virtual Machine - Wikipedia](https://en.wikipedia.org/wiki/Virtual_machine)
* **VM Hypervisor Software**
  * **Desktop**
    * [Oracle VirtualBox - free](https://www.virtualbox.org/)
    * [VMware Workstation - paid](https://www.vmware.com/products/workstation-pro.html)
  * **Server**
    * [Proxmox - free](https://www.proxmox.com/en/)
    * [VMware vSphere - free](https://www.vmware.com/products/vsphere-hypervisor.html)
    * [Xen - free](https://www.xenproject.org/)
* **Obtaining VMs**
  * [Internet Explorer Windows Vista through 10 Virtual Machines](https://github.com/mikescott/ie-virtual-machines/blob/master/README.md)
  * [Windows Server Evaluation ISOs](https://www.microsoft.com/en-us/evalcenter/)
  * [Vulnhub](https://www.Vulnhub.com)
    * Vulnhub is a website dedicated to cataloging various vulnerable VMs from across the web. It also has a healthy community that creates and submits new VMs on a regular basis. As I write this now, I believe there is around 100 or so different VMs on Vulnhub, so you have a bit of variation.
  * [macOS-Simple-KVM](https://github.com/foxlet/macOS-Simple-KVM)
    * Documentation to set up a simple macOS VM in QEMU, accelerated by KVM.
  * [unlocker](https://github.com/DrDonk/unlocker)
    * VMware Workstation macOS
  * [Running macOS Catalina Beta on VirtualBox Linux - Astr0baby](https://astr0baby.wordpress.com/2019/07/04/running-macos-catalina-beta-on-virtualbox-linux/)
* **Automated Lab/Machine Creation Tools**
  * Security Scenario Generator \(SecGen\)\]\([https://github.com/cliffe/SecGen](https://github.com/cliffe/SecGen)\)
    * SecGen creates vulnerable virtual machines so students can learn security penetration testing techniques. Boxes like Metasploitable2 are always the same, this project uses Vagrant, Puppet, and Ruby to create randomly vulnerable virtual machines that can be used for learning or for hosting CTF events.
  * [Detection Lab](https://github.com/clong/DetectionLab)
    * Vagrant & Packer scripts to build a lab environment complete with security tooling and logging best practices. This lab has been designed with defenders in mind. Its primary purpose is to allow the user to quickly build a Windows domain that comes pre-loaded with security tooling and some best practices when it comes to system logging configurations. It can easily be modified to fit most needs or expanded to include additional hosts.
  * [Set up your own malware analysis lab with VirtualBox, INetSim and Burp - Christophe Tafani-Dereeper](https://blog.christophetd.fr/malware-analysis-lab-with-virtualbox-inetsim-and-burp/)
  * [CyRIS: Cyber Range Instantiation System](https://github.com/crond-jaist/cyris)
    * CyRIS is a tool for facilitating cybersecurity training by automating the creation and management of the corresponding training environments \(a.k.a, cyber ranges\) based on a description in YAML format. CyRIS is being developed by the Cyber Range Organization and Design \(CROND\) NEC-endowed chair at the Japan Advanced Institute of Science and Technology \(JAIST\).
  * [DockerSecurityPlayground](https://github.com/giper45/DockerSecurityPlayground)
    * A Microservices-based framework for the study of Network Security and Penetration Test techniques
* **VMs/Apps Designed to be Attacked**
  * [List of VMs that are preconfigured virtual machines](http://www.amanhardikar.com/mindmaps/PracticeUrls.html)
  * [The Hacker Games - Hack the VM before it hacks you](http://www.scriptjunkie.us/2012/04/the-hacker-games/)
    * I have talked about counterattacks here before, and this system has implemented a number of aggressive anti-hacker measures.  In fact, this VM is downright evil. I am probably legally obligated to tell you that it will try to hack you. So if a calculator or message declaring your pwnedness pops up or shows up on your desktop, you asked for it. But don’t worry, it won’t steal your docs or rm you, it will just demonstrate compromise for the game.  To save precious bandwidth, this has been implemented in a minimal tinycore-based VM, and will require VirtualBox to run.
  * **AWS**
    * [AWS Well-Architected Security Labs - Amazon\(Official\)](https://www.wellarchitectedlabs.com/Security/README.html)
      * This repository contains documentation and code in the format of hands-on labs to help you learn, measure, and build using architectural best practices. The labs are categorized into levels, where 100 is introductory, 200/300 is intermediate and 400 is advanced.
    * [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
      * CloudGoat is Rhino Security Labs' "Vulnerable by Design" AWS deployment tool. It allows you to hone your cloud cybersecurity skills by creating and completing several "capture-the-flag" style scenarios. Each scenario is composed of AWS resources arranged together to create a structured learning experience. Some scenarios are easy, some are hard, and many offer multiple paths to victory. As the attacker, it is your mission to explore the environment, identify vulnerabilities, and exploit your way to the scenario's goal\(s\).
    * [CloudGoat 2: The New & Improved “Vulnerable by Design” AWS Deployment Tool - Jeffrey Anderson](https://rhinosecuritylabs.com/aws/introducing-cloudgoat-2/)
    * [CloudGoat 2 Walkthrough - Part One - thetestlabs.io](https://thetestlabs.io/post/cloudgoat-2-walkthrough-part-one/)
    * [OWASP Mutillidae II](https://sourceforge.net/projects/mutillidae/)
      * OWASP Mutillidae II is a free, open source, deliberately vulnerable web-application providing a target for web-security enthusiast. Mutillidae can be installed on Linux and Windows using LAMP, WAMP, and XAMMP. It is pre-installed on SamuraiWTF and OWASP BWA. The existing version can be updated on these platforms. With dozens of vulnerabilities and hints to help the user; this is an easy-to-use web hacking environment designed for labs, security enthusiast, classrooms, CTF, and vulnerability assessment tool targets. Mutillidae has been used in graduate security courses, corporate web sec training courses, and as an "assess the assessor" target for vulnerability assessment software.
    * **Lambda**
      * [lambhack](https://github.com/wickett/lambhack)
        * A vulnerable serverless lambda application. This is certainly a bad idea to base any coding patterns of what you see here. lambhack allows you to take advantage of our tried and true application security problems, namely arbitrary code execution, XSS, injection attacks aand more. This first release only contains arbitrary code execution through the query string. Please feel free to contribute new vulnerabilities.
  * **Docker**
    * [Down by the Docker](https://www.notsosecure.com/vulnerable-docker-vm/)
      * Ever fantasized about playing with docker misconfigurations, privilege escalation, etc. within a container? Download this VM, pull out your pentest hats and get started 
    * [Vulhub - Some Docker-Compose files for vulnerabilities environment](https://github.com/vulhub/vulhub)
    * [Vulnerable Docker VM - notsosecure](https://www.notsosecure.com/vulnerable-docker-vm/)
  * **Exploit Development**
    * [exploit\_me](https://github.com/bkerler/exploit_me)
      * Very vulnerable ARM application \(CTF style exploitation tutorial for ARM, but portable to other platforms\)
  * **Git Repo**
    * [Leaky Repo](https://github.com/digininja/leakyrepo)
  * **Router**
    * [iv-wrt](https://github.com/iv-wrt/iv-wrt)
      * An Intentionally Vulnerable Router Firmware Distribution
  * **Thick Client**
    * [Damn Vulnerable Thick Client Application - Part 1 - Setup - Parsia's Den](https://parsiya.net/blog/2018-07-15-damn-vulnerable-thick-client-application---part-1---setup/)
  * **Web Application Focused**
    * **OWASP**
      * [OWASP Vulnerable Web Applications Directory Project/Pages/Offline](https://www.owasp.org/index.php/OWASP_Vulnerable_Web_Applications_Directory_Project/Pages/Offline)
      * [OWASP Broken Web Applications Project](https://www.owasp.org/index.php/OWASP_Broken_Web_Applications_Project)
        * OWASP Broken Web Applications Project is a collection of vulnerable web applications that is distributed on a Virtual Machine.
      * [OWASP Juiceshop](https://www.owasp.org/index.php/OWASP_Juice_Shop_Project)
        * [OWASP Juice Shop\(Github\)](https://github.com/bkimminich/juice-shop)
        * OWASP Juice Shop is an intentionally insecure web application written entirely in Javascript which encompasses the entire range of OWASP Top Ten and other severe security flaws.
        * [OWASP JuiceShop Gitbook walkthrough](https://www.gitbook.com/book/bkimminich/pwning-owasp-juice-shop/details)
        * [Video Walk through by Sunny Wear](https://www.youtube.com/watch?v=zi3yDovd0RY&list=PL-giMT7sGCVI9T4rKhuiTG4EDmUz-arBo)
        * [Pwning OWASP Juice Shop](https://leanpub.com/juice-shop)
      * [OWASP Damn Vulnerable Web Sockets](https://github.com/interference-security/DVWS)
        * OWASP Damn Vulnerable Web Sockets \(DVWS\) is a vulnerable web application which works on web sockets for client-server communication. The flow of the application is similar to DVWA. You will find more vulnerabilities than the ones listed in the application.
      * [NodeGoat](https://github.com/OWASP/NodeGoat)
        * Being lightweight, fast, and scalable, Node.js is becoming a widely adopted platform for developing web applications. This project provides an environment to learn how OWASP Top 10 security risks apply to web applications developed using Node.js and how to effectively address them.
      * [OWASP DevSlop Project](https://www.owasp.org/index.php/OWASP_DevSlop_Project)
        * collection of DevOps-driven applications, specifically designed to showcase security catastrophes and vulnerabilities for use in security testing, software testing, learning and teaching for both developers and security professionals.
    * **General**
      * [Damn Vulnerable Web App](https://github.com/ethicalhack3r/DVWA)
        * Damn Vulnerable Web Application \(DVWA\) is a PHP/MySQL web application that is damn vulnerable. Its main goal is to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and to aid both students & teachers to learn about web application security in a controlled class room environment.
      * [Damn Small Vulnerable Web](https://github.com/stamparm/DSVW)
        * Damn Small Vulnerable Web \(DSVW\) is a deliberately vulnerable web application written in under 100 lines of code, created for educational purposes. It supports majority of \(most popular\) web application vulnerabilities together with appropriate attacks.
      * [File scanner web app \(Part 1 of 5\): Stand-up and webserver](http://0xdabbad00.com/2013/09/02/file-scanner-web-app-part-1-of-5-stand-up-and-webserver/)
      * [Xtreme Vulnerable Web Application \(XVWA\)](https://github.com/s4n7h0/xvwa)
        * XVWA is a badly coded web application written in PHP/MySQL that helps security enthusiasts to learn application security. It’s not advisable to host this application online as it is designed to be “Xtremely Vulnerable”. We recommend hosting this application in local/controlled environment and sharpening your application security ninja skills with any tools of your own choice.
      * [Hackazon](https://github.com/rapid7/hackazon)
        * Hackazon is a free, vulnerable test site that is an online storefront built with the same technologies used in today’s rich client and mobile applications. Hackazon has an AJAX interface, strict workflows and RESTful API’s used by a companion mobile app providing uniquely-effective training and testing ground for IT security professionals. And, it’s full of your favorite vulnerabilities like SQL Injection, cross-site scripting and so on.
      * [Vulnerable Web applications Generator](https://github.com/qazbnm456/VWGen)
        * This is the Git repo of the VWGen, which stands for Vulnerable Web applications Generator.
      * [secDevLabs](https://github.com/globocom/secDevLabs)
        * By provisioning local environments via docker-compose, you will learn how the most critical web application security risks are exploited and how these vulnerable codes can be fixed to mitigate them. woman\_technologist
    * **API**
      * [vulnerable-api](https://github.com/mattvaldes/vulnerable-api)
      * [How to configure Json.NET to create a vulnerable web API](https://www.alphabot.com/security/blog/2017/net/How-to-configure-Json.NET-to-create-a-vulnerable-web-API.html)
    * **Django**
      * [django.nV](https://github.com/nVisium/django.nV)
        * django.nV is a purposefully vulnerable Django application provided by nVisium.
    * **JSP**
      * [MoneyX](https://github.com/nVisium/MoneyX)
        * MoneyX is an intentionally vulnerable JSP application used for training developers in application security concepts.
    * **Node.js**
      * [node.nV](https://github.com/nVisium/node.nV)
        * Intentionally Vulnerable node.js application
      * [goat.js](https://github.com/nVisium/goat.js)
        * Tutorial for Node.js security
      * [Damn Vulnerable NodeJS Application\(DVNA\)](https://github.com/appsecco/dvna)
        * Damn Vulnerable NodeJS Application \(DVNA\) is a simple NodeJS application to demonstrate OWASP Top 10 Vulnerabilities and guide on fixing and avoiding these vulnerabilities. The fixes branch will contain fixes for the vulnerabilities. Fixes for vunerabilities OWASP Top 10 2017 vulnerabilities at fixes-2017 branch.
    * **Ruby**
      * [grails\_nV](https://github.com/nVisium/grails-nV)
        * grails\_nV is a vulnerable jobs listing website.
      * [RailsGoat](https://github.com/OWASP/railsgoat)
        * RailsGoat is a vulnerable version of the Ruby on Rails Framework from versions 3 to 5. It includes vulnerabilities from the OWASP Top 10, as well as some "extras" that the initial project contributors felt worthwhile to share. This project is designed to educate both developers, as well as security professionals.
    * **SSRF**
      * [SSRF Vulnerable Lab](https://github.com/incredibleindishell/SSRF_Vulnerable_Lab)
        * This repository contain PHP codes which are vulnerable to Server-Side Request Forgery \(SSRF\) attack.
    * **SSO**
      * [Vulnerable SSO](https://github.com/dogangcr/vulnerable-sso)
        * Vulnerable SSo is focused on single sign on related vulnerabilities. If you want to learn, you should check this and contribute this project. VulnSSO tool is focused on sso attacks. Nowadays most of the company uses their own implementation for sso solutions. Some of the bug hunters found really good vulnerability on the big company. There are some tools\(dvwa and others .. \) that contains vulnerability. They don't have any support for sso vulnerability. Our focus is only sso related bugs. VulnSSO is training tool.It will contain redirect uri vulnerability , XXE on saml request and many others.
    * **Web Cache Poisoning**
      * [Web Cache Poisoning Lab](https://poison.digi.ninja)
        * Welcome to the Cache Poisoning Lab. In this lab you will have the opportunity to experiment with some of the vulnerabilities presented in the brilliant paper Practical Web Cache Poisoning by James Kettle.

### Setting up ActiveDirectory Focused Labs

* **Official Documentation**
  * [Install AD DS using Powerhsell](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-#BKMK_PS)
  * [Active Directory Domain Services Overview](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
  * \[Understanding Active Directory - docs.ms\]\([https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc781408\(v=ws.10](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc781408%28v=ws.10)\)\)
  * [Windows Server 2016: Build a Windows Domain Lab at Home for Free - social.technet](https://social.technet.microsoft.com/wiki/contents/articles/36438.windows-server-2016-build-a-windows-domain-lab-at-home-for-free.aspx#Download)
* **Guides**
  * [Building an Effective Active Directory Lab Environment for Testing - adsecurity.org](https://adsecurity.org/?p=2653)
  * [Step-By-Step: Setting up Active Directory in Windows Server 2016 - blogs.technet](https://blogs.technet.microsoft.com/canitpro/2017/02/22/step-by-step-setting-up-active-directory-in-windows-server-2016/)
  * [Pentest Home Lab - 0x2 - Building Your AD Lab on Premises-SethSec](https://sethsec.blogspot.com/2017/06/pentest-home-lab-0x2-building-your-ad.html)
  * [Building and Attacking an Active Directory lab with PowerShell - 1337red](https://1337red.wordpress.com/building-and-attacking-an-active-directory-lab-with-powershell/)
  * [DarthSidious](https://github.com/chryzsh/DarthSidious)
    * Building an Active Directory domain and hacking it
  * [Creating a SCCM Lab: Part 1 - Setting up AD](https://www.youtube.com/watch?v=4zwQsQEtrwY&feature=share)
  * [Build a new Windows Domain with a \(semi\) easy button - Craig Bowser](http://shadowtrackers.net/blog/build-a-new-windows-domain-with-a-semi-easy-button)
  * [Introducing the Active Directory Learning Lab - @jckhmr\_t](https://github.com/jckhmr/adlab)
    * I'm a big fan of automation with tools such as Ansible, Vagrant and Terrorm now being put to regular use by me. Also, as a Red Team Operator I spend a lot of time modelling attacks up, trying new ideas out and generally keeping myself 'sharp'. I wanted to create something that help me to scratch all of these itches. The research and development culminated in my [BSides Belfast 2019 presentation: Offensive Ansible for Red Teams \(Attack, Build, Learn\)](https://github.com/jckhmr/presentations/blob/master/BSidesBelfast2019_Final_Optimized.pptx?raw=true).
  * **AWS**
    * [Active Directory Domain Services on the AWS Cloud: Quick Start Reference Deployment - docs.aws](https://docs.aws.amazon.com/quickstart/latest/active-directory-ds/welcome.html)
    * [Active Directory Domain Services on AWS](https://aws.amazon.com/quickstart/architecture/active-directory-ds/)
      * This Quick Start deploys Microsoft Active Directory Domain Services \(AD DS\) on the AWS Cloud. AD DS and Domain Name Server \(DNS\) are core Windows services that provide the foundation for many Microsoft-based solutions for the enterprise, including Microsoft SharePoint, Microsoft Exchange, and .NET Framework applications.
  * **Azure**
    * [Disruption](https://github.com/xFreed0m/Disruption/)
      * Disruption is a code for Terraform to deploy a small AD domain-based environment in Azure. The environment contains two domain controllers \(Windows Server 2012\), Fileserver + Web server \(Windows Server 2019\), Windows 7 client, Windows 10 client, and kali Linux machine. They are connected to the same subnet. Each windows machine has some packages being installing during deployment \(the list can be viewed and modified here: chocolist\). All the needed configurations \(Domain creation, DC promotion, joining the machines to the domain and more are automated and part of the deployment. However, there are more improvments to be added \(creating OUs, Users, and stuff like that. I'll might get to it in the future, or, you will submit a pull request :\)\)
* **Tools**
  * **Lab Generation**
    * [WSLab - Official Microsoft Stuff](https://github.com/microsoft/WSLab)
      * Windows Server rapid lab deployment scripts
    * [AutomatedLab](https://github.com/AutomatedLab/AutomatedLab)
      * AutomatedLab is a provisioning solution and framework that lets you deploy complex labs on HyperV and Azure with simple PowerShell scripts. It supports all Windows operating systems from 2008 R2 to 2016 including Nano Server and various products like AD, Exchange, PKI, IIS, etc.    
    * [Automated-AD-Setup](https://github.com/OneLogicalMyth/Automated-AD-Setup)
      * A PowerShell script that aims to have a fully configured domain built in under 10 minutes, but also apply security configuration and hardening.
    * [Invoke-ADLabDeployer](https://github.com/outflanknl/Invoke-ADLabDeployer)
      * Automated deployment of Windows and Active Directory test lab networks. Useful for red and blue teams.
      * [Blogpost](https://outflank.nl/blog/2018/03/30/automated-ad-and-windows-test-lab-deployments-with-invoke-adlabdeployer/)\)
  * **User Generation**
    * [ADImporter](https://github.com/curi0usJack/ADImporter)
      * When you need to simulate a real Active Directory with thousands of users you quickly find that creating realistic test accounts is not trivial. Sure enough, you can whip up a quick PowerShell one-liner that creates any number of accounts, but what if you need real first and last names? Real \(existing\) addresses? Postal codes matching phone area codes? I could go on. The point is that you need two things: input files with names, addresses etc. And script logic that creates user accounts from that data. This blog post provides both.
    * [youzer](https://github.com/SpiderLabs/youzer)
      * Fake User Generator for Active Directory Environments
  * **User Simulation**
    * [sheepl](https://github.com/SpiderLabs/sheepl)
      * sheepl is a tool that aims to bridge the gap by emulating the behaviour that people normally undertake within a network environment. Using Python3 and AutoIT3 the output can be compiled into a standalone executable without any other dependancies that when executed on an Windows endpoint, executes a set of tasks randomly over a chosen time frame.

### Building a Pen test lab

* **Guides**
  * [DarthSidious](https://chryzsh.gitbooks.io/darthsidious/content/)
    * To share my modest knowledge about hacking Windows systems. This is commonly refered to as red team exercises. This book however, is also very concerned with the blue team; the defenders. That is, helping those who are working as defenders, analysts and security experts to build secure Active Directory environments and monitor them for malicious activity.
  * [SANS Webcast: Building Your Own Super Duper Home Lab](https://www.youtube.com/watch?v=uzqwoufhwyk&app=desktop)
  * [Home Lab with pfSense & VMware Workstation - sysadmin perspective](http://itpro.outsidesys.com/2015/02/19/home-lab-with-pfsense-workstation/)
    * I wanted to build a virtual lab environment at home that would emulate an office environment.  My requirements were to have separate network segments for Clients & Servers, and two DMZ networks.  I also wanted my home network, which is external to the virtual lab environment, to emulate the Internet, even though it really isn’t. The following is how I created multiple “named” LAN segments within VMware Workstation, and routed between them using a VM running pfSense, which is an open source firewall.
  * [Setting Up a Pentest/Hacking Lab with Hyper-V](http://cyberthreathunt.com/2017/04/01/setting-up-a-pentest-lab-with-hyper-v/)
  * [Hack Yourself: Building a Test Lab - David Boyd](https://www.youtube.com/watch?v=rgdX-hn0xXU)
  * [Hack-Yourself: Building a pentesting lab for fun & profit](https://www.slideshare.net/DavidBoydCISSP/hack-yourself-building-a-pentesting-lab-for-fun-and-profit)
  * [Setting up a Windows Lab Environment](http://thehackerplaybook.com/Windows_Domain.htm)
  * [Setting Up A Penetration Testing Lab - Rapid7](https://kb.help.rapid7.com/docs/setting-up-a-penetration-testing-lab)
  * [Building a Pentest Lab - stan.gr](http://www.stan.gr/2013/03/building-pentest-lab.html)
* **Tools**
  * [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire)
    * [Slides](https://github.com/TryCatchHCF/DumpsterFire/raw/master/CactusCon_2017_Presentation/DumpsterFire_CactusCon_2017_Slides.pdf)
    * The DumpsterFire Toolset is a modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor / alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations. Turn paper tabletop exercises into controlled "live fire" range events. Build event sequences \("narratives"\) to simulate realistic scenarios and generate corresponding network and filesystem artifacts.
  * [Pentest Environment Deployer](https://github.com/Sliim/pentest-env)
    * This repo provides an easy way to deploy a clean and customized pentesting environment with Kali linux using vagrant and virtualbox.
* **In the Clouds**
  * **AWS**
    * **Official Documentation**
      * [Getting Started with AWS Managed Microsoft AD - docs.aws](https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started.html)
      * [Active Directory Domain Services on the AWS Cloud: Quick Start Reference Deployment](https://docs.aws.amazon.com/quickstart/latest/active-directory-ds/welcome.html)
    * **Un-Official**
      * [Building A Lab on AWS - 0x1 SethSec](https://sethsec.blogspot.com/2017/05/pentest-home-lab-0x1-building-your-ad.html)
      * [Pentesting In The Cloud - primalsecurity](http://www.primalsecurity.net/pentesting-in-the-cloud/)
  * **Azure**
    * [Building a security lab in Azure - blogs.technet](https://blogs.technet.microsoft.com/motiba/2018/05/11/building-a-security-lab-in-azure/)
  * **GCP**

### Building a Defensive Lab

* **Guides**
* **Tools**
* **In the Clouds**
  * [Securing Azure Infrastructure - Hands on Lab Guide - Adam Raffle, Tom Wilde](https://github.com/Araffe/azure-security-lab)

### Infrastructure Automation

* **Articles/Blogposts**
  * [PhoenixServer - Martin Fowler](https://martinfowler.com/bliki/PhoenixServer.html)
  * [An introduction to immutable infrastructure - Josh Stella](https://www.oreilly.com/radar/an-introduction-to-immutable-infrastructure/)
  * [An Introduction to the /opt Directory - Nick Sweeting](https://docs.sweeting.me/s/an-intro-to-the-opt-directory#)
  * [Automation Testing With Ansible, Molecule, And Vagrant - Mike Spitzer](https://www.trustedsec.com/blog/automation-testing-with-ansible-molecule-and-vagrant/)
* **Infrastructure Automation**
  * [An Intro to Terraform with Azure, PFSense, and Windows 10 - FortyNorth Security](https://www.fortynorthsecurity.com/an-intro-to-terraform-with-azure-pfsense-and-windows-10/)
  * [Automating Red Team Homelabs: Part 2 – Build, Pentest, Destroy, and Repeat - Alex Rodriguez](https://blog.secureideas.com/2019/05/automating-red-team-homelabs-part-2-build-pentest-destroy-and-repeat.html)
  * [Self-Installing Windows OVA](https://github.com/brimstone/windows-ova)
    * This is an Virtual Machine in OVA format that will install Windows ontop of itself. I wrote this as an alternative to packer. This OVA basically downloads the evaluation version of the Windows version you select to one drive as installation media and then installs onto the primary drive. After this is done, the smaller secondary drive can be discarded to save disk space.
  * [Modern C2 Infrastructure with Terraform, DigitalOcean, Covenant and Cloudflare - Riccardo](https://riccardoancarani.github.io/2019-09-28-modern-c2-infra/)
  * [Automating Red Team Homelabs: Part 1 – Kali Automation - Alex Rodriguez](https://blog.secureideas.com/2018/09/automating-red-team-homelabs-part-1-kali-automation.html)
* **Sort**
  * [Building a scalable, highly available, and portable web server - Surya Dantuluri](https://blog.suryad.com/sd2/)
  * [Containerised Home Server With Docker Compose and Traefik - Kristian Glass](https://blog.doismellburning.co.uk/containerised-home-server-with-docker-compose-and-traefik/)
  * [Modern Windows Attacks and Defense Lab](https://github.com/jaredhaight/WindowsAttackAndDefenseLab/)
    * This is the lab configuration for the Modern Windows Attacks and Defense class that Sean Metcalf \(@pyrotek3\) and I\(Jared Haight\) teach.

