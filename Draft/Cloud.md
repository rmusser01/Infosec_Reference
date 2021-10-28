# The 'Cloud' aka Someone's Else's Data Center

----------------------------------
## Table of Contents
- [Cloud Provider Agnostic](#agnostic)
- [Amazon Web Services](#aws)
	- [101](#101)
	- [Attacking](#atkws)
	- [IAM](#awsiam)
- [Google Cloud Platform](#gcp)
- [MS Azure](#ms-azure)








--------------------
### <a name="agnostic"></a>Cloud Provider Agnostic
* **101**<a name="101ag"></a>
	* [Cloud Security Wiki - NotSoSecure](https://cloudsecwiki.com)
		* Cloud Security Wiki is an initiative to provide all Cloud security related resources to Security Researchers and developers at one place.
* **Attacking/Assessing Security of**
	* **Articles/Blogposts/Writeups**
		* [A Placement Vulnerability Study in Multi-Tenant Public Clouds](https://www.usenix.org/node/191017)

	* **Tools**
		* [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
			* Scout Suite is an open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments. Using the APIs exposed by cloud providers, Scout Suite gathers configuration data for manual inspection and highlights risk areas. Rather than going through dozens of pages on the web consoles, Scout Suite presents a clear view of the attack surface automatically.
		* **Containers**
			* [Cloud Container Attack Tool (CCAT)](https://github.com/RhinoSecurityLabs/ccat)
				* Cloud Container Attack Tool (CCAT) is a tool for testing security of container environments.
* **Cloud Migrations**
	* [Case studies in cloud migration: Netflix, Pinterest, and Symantec - Increment(2017)](https://increment.com/cloud/case-studies-in-cloud-migration/)
* **Compliance Monitoring**
	* [PacBot](https://github.com/tmobile/pacbot)
		Policy as Code Bot (PacBot) is a platform for continuous compliance monitoring, compliance reporting and security automation for the cloud. In PacBot, security and compliance policies are implemented as code. All resources discovered by PacBot are evaluated against these policies to gauge policy conformance. The PacBot auto-fix framework provides the ability to automatically respond to policy violations by taking predefined actions. PacBot packs in powerful visualization features, giving a simplified view of compliance and making it easy to analyze and remediate policy violations. PacBot is more than a tool to manage cloud misconfiguration, it is a generic platform that can be used to do continuous compliance monitoring and reporting for any domain.
* **Hardening**
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
	* **Tools**
		* [LUNAR](https://github.com/lateralblast/lunar)
			* "This scripts generates a scored audit report of a Unix host's security. It is based on the CIS and other frameworks. Where possible there are references to the CIS and other benchmarks in the code documentation."
* **IAM**
	* [SkyArk](https://github.com/cyberark/SkyArk)
		* SkyArk helps to discover, assess and secure the most privileged entities in Azure and AWS
* **Logging**
	* **Articles/Blogposts/Writeups**
		* [Logging in the Cloud: From Zero to (Incident Response) Hero - Jonathon Poling(2020)](https://www.youtube.com/watch?v=n7ec0REBFkk)
			* [Slides](https://ponderthebits.com/wp-content/uploads/2020/02/Logging-in-the-Cloud-From-Zero-to-Incident-Response-Hero-Public.pdf)
			* So many logs, so little time. What logs even exist? Which are enabled by default? Which are the most critical to enable and configure for effective incident response? AWS. Azure. GCP. My. Dear. God. Send help! And, help you this presentation shall. This session will walk through the most important logging to enable (and how) in each cloud provider to take you from zero to incident response hero!Pre-Requisites: Basic familiarity operating with the three major Cloud providers: AWS, Azure, and GCP.
	* **Talks/Presentations/Videos**
	* **Tools**
		* [cloud-service-enum](https://github.com/NotSoSecure/cloud-service-enum)
* **Monitoring**
	* **Articles/Blogposts/Writeups**
		* [Part 1: AWS Continuous Monitoring - Ashish Kurmi, Kaibo Ma, Ankit Kumar(2020)](https://medium.com/@ubersecurity/part-1-aws-continuous-monitoring-f39f81ea6801)
			* [Part 2](https://medium.com/@ubersecurity/part-2-aws-monitoring-case-studies-9fbc613aff28)
* **Rules Engine**
	* **Articles/Blogposts/Writeups**
	* **Talks/Presentations/Videos**
	* **Tools**
		* [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian/)
			* Cloud Custodian is a rules engine for managing public cloud accounts and resources. It allows users to define policies to enable a well managed cloud infrastructure, that's both secure and cost optimized. It consolidates many of the adhoc scripts organizations have into a lightweight and flexible tool, with unified metrics and reporting. Custodian can be used to manage AWS, Azure, and GCP environments by ensuring real time compliance to security policies (like encryption and access requirements), tag policies, and cost management via garbage collection of unused resources and off-hours resource management. Custodian policies are written in simple YAML configuration files that enable users to specify policies on a resource type (EC2, ASG, Redshift, CosmosDB, PubSub Topic) and are constructed from a vocabulary of filters and actions. It integrates with the cloud native serverless capabilities of each provider to provide for real time enforcement of policies with builtin provisioning. Or it can be run as a simple cron job on a server to execute against large existing fleets.
* **Security Auditing**
	* **Articles/Blogposts/Writeups**
	* **Tools**
		* [Cloud Security Suite](https://github.com/SecurityFTW/cs-suite)
			* One stop tool for auditing the security posture of AWS & GCP infrastructure.
		* [CloudSploit Scans](https://github.com/cloudsploit/scans)
			* CloudSploit scans is an open-source project designed to allow detection of security risks in cloud infrastructure accounts, including: Amazon Web Services (AWS), Microsoft Azure, Google Cloud Platform (GCP), and Oracle Cloud Infrastructure (OCI). These scripts are designed to return a series of potential misconfigurations and security risks.
* **"Serverless"**
	* [Peeking Behind the Curtains of Serverless Platforms - Liang Wang, Mengyuan Li, Yinqian Zhang, Thomas Ristenpart, Michael Swift](http://pages.cs.wisc.edu/~liangw/pub/atc18-final298.pdf)
		* Taking on the viewpoint of a serverless customer, we conduct the largest measurement study to date, launching more than 50,000 function instances across these three services, in order to characterize their architectures, performance, and resource management efficiency. We explain how the platforms isolate the functions of different accounts, using either virtual machines or containers, which has important security implications. We characterize performance in terms of scalability, coldstart latency, and resource efficiency, with highlights including that AWS Lambda adopts a bin-packing-like strategy to maximize VM memory utilization, that severe contention between functions can arise in AWS and Azure, and that Google had bugs that allow customers to use resources for free.



















--------------------
### <a name="aws"></a>AWS
* **101**<a name="aws101"></a>
	* **Articles/Blogposts/Writeups**
		* [AWS Security Audit Guidelines - docs.aws](https://docs.aws.amazon.com/general/latest/gr/aws-security-audit-guide.html)
		* [AWS Services Explained through Pictures](https://www.awsgeek.com/?mc_cid=065d80dbfd&mc_eid=f956a0c5ca)
		* [Request form for performing Pentesting on AWS Infrastructure](https://aws.amazon.com/premiumsupport/knowledge-center/penetration-testing/)
	* **Talks/Presentations/Videos**
		* [The Fundamentals of AWS Cloud Security - Becky Weiss(AWS re:Inforce 2019)](https://www.youtube.com/watch?v=-ObImxw1PmI)
			* The services that make up AWS are many and varied, but the set of concepts you need to secure your data and infrastructure is simple and straightforward. By the end of this session, you will know the fundamental patterns that you can apply to secure any workload you run in AWS with confidence. We cover the basics of network security, the process of reading and writing access management policies, and data encryption.
		* [Security Best Practices the Well-Architected Way - Ben Potter(AWS re:Inforce 2019)](https://www.youtube.com/watch?v=u6BCVkXkPnM)
			* As you continually evolve your use of the AWS platform, it’s important to consider ways to improve your security posture and take advantage of new security services and features. In this advanced session, we share architectural patterns for meeting common challenges, service limits and tips, tricks, and ways to continually evaluate your architecture against best practices. Automation and tools are featured throughout, and there will be code giveaways! Be prepared for a technically deep session on AWS security.
* **Attacking**<a name="atkaws"></a>
	* **Articles/Blogposts/Writeups**
		* [An Introduction to Penetration Testing AWS: Same Same, but Different - GracefulSecurity](https://www.gracefulsecurity.com/an-introduction-to-penetration-testing-aws/)
		* [Using DNS to Break Out of Isolated Networks in a AWS Cloud Environment](https://dejandayoff.com/using-dns-to-break-out-of-isolated-networks-in-a-aws-cloud-environment/)
			* Customers can utilize AWS' DNS infrastructure in VPCs (enabled by default). Traffic destined to the AmazonProvidedDNS is traffic bound for AWS management infrastructure and does not egress via the same network links as standard customer traffic and is not evaluated by Security Groups. Using DNS exfiltration, it is possible to exfiltrate data out of an isolated network.
		* [AWS IAM Privilege Escalation – Methods and Mitigation - Spencer Gietzen](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
		* [AWS IAM Exploitation - Evan Perotti](https://securityriskadvisors.com/blog/aws-iam-exploitation/)
		* [AWS IAM Privilege Escalation – Methods and Mitigation – Part 2 - Spencer Gietzen](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/)
		* [Penetration Testing AWS Storage: Kicking the S3 Bucket](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/)
		* [Disrupting AWS logging - Daniel Grzelak](https://danielgrzelak.com/disrupting-aws-logging-a42e437d6594?gi=dde97e1f07f7)
		* [Abusing the AWS metadata service using SSRF vulnerabilities - Christophe Tafani-Dereeper](https://blog.christophetd.fr/abusing-aws-metadata-service-using-ssrf-vulnerabilities/https://0xdf.gitlab.io/2019/08/02/bypassing-php-disable_functions-with-chankro.html)
		* [Bypass GuardDuty PenTest Alerts - Nick Frichette](https://frichetten.com/blog/bypass-guardduty-pentest-alerts)
		* [Getting shell and data access in AWS by chaining vulnerabilities - Riyaz Wilaker](https://blog.appsecco.com/getting-shell-and-data-access-in-aws-by-chaining-vulnerabilities-7630fa57c7ed)
		* [Securing the Cloud: A Story of Research, Discovery, and Disclosure - Jordan Drysdale](https://www.blackhillsinfosec.com/securing-the-cloud-a-story-of-research-discovery-and-disclosure/)
		* BHIS made some interesting discoveries while working with a customer to audit their Amazon Web Services (AWS) infrastructure. At the time of the discovery, we found two paths to ingress the customer’s virtual private cloud (VPC) through the elastic map reduce (EMR) application stacks. One of the vulns that gained us internal access was the Hadoop Unauthenticated RCE, which was patched by Apache a while back now. Another, and a bit more interesting entry point, was the HUE interface, which, by default, allows the creation of a new admin user for the web interface. Once in the web interface, HUE is similar to Jupyter in that it helps visualize code flow and operations. Here, you can create schedules that will send egress shells from the cluster worker nodes. Which, consequently, provides a window to a virtual private cloud network.
	* **Talks/Presentations/Videos**
		* [Step By Step AWS Cloud Hacking - Andres Riancho(SecTor19)](https://sector.ca/sessions/step-by-step-aws-cloud-hacking/)
		* [Gone in 60 Milliseconds - Intrusion and Exfiltration in Server-less Architectures](https://media.ccc.de/v/33c3-7865-gone_in_60_milliseconds)
			* More and more businesses are moving away from monolithic servers and turning to event-driven microservices powered by cloud function providers like AWS Lambda. So, how do we hack in to a server that only exists for 60 milliseconds? This talk will show novel attack vectors using cloud event sources, exploitabilities in common server-less patterns and frameworks, abuse of undocumented features in AWS Lambda for persistent malware injection, identifying valuable targets for pilfering, and, of course, how to exfiltrate juicy data out of a secure Virtual Private Cloud. 
		* [Pivoting in Amazon Clouds - Andres Riancho - BHUSA14](https://www.youtube.com/watch?v=2NF4LjjwoZw)
			* "From no access at all, to the company Amazon's root account, this talk will teach attendees about the components used in cloud applications like: EC2, SQS, IAM, RDS, meta-data, user-data, Celery; and how misconfigurations in each can be abused to gain access to operating systems, database information, application source code, and Amazon's services through its API. The talk will follow a knowledgeable intruder from the first second after identifying a vulnerability in a cloud-deployed Web application and all the steps he takes to reach the root account for the Amazon user. Except for the initial vulnerability, a classic remote file included in a Web application which grants access to the front-end EC2 instance, all the other vulnerabilities and weaknesses exploited by this intruder are going to be cloud-specific.
			* [Paper](https://andresriancho.github.io/nimbostratus/pivoting-in-amazon-clouds.pdf)
		* [Abusing AWS Metadata Service - Casey Goodrich](https://www.youtube.com/watch?v=gZsmpPLZQJM)
		* [Step by step AWS Cloud Hacking - Andres Riancho(SecTor19)](https://sector.ca/sessions/step-by-step-aws-cloud-hacking/)
		* [Account Jumping Post Infection Perstistency & Lateral Movement In AWS - Dan Amiga, Dor Knafo(BH-US16)](https://www.blackhat.com/docs/us-16/materials/us-16-Amiga-Account-Jumping-Post-Infection-Persistency-And-Lateral-Movement-In-AWS-wp.pdf)
	* **Tools**
		* [My Arsenal of AWS Security Tools - toniblyx](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)
		* [Prowler: AWS CIS Benchmark Tool](https://github.com/toniblyx/prowler)
			* Prowler is a command line tool for AWS Security Best Practices Assessment, Auditing, Hardening and Forensics Readiness Tool. It follows guidelines of the CIS Amazon Web Services Foundations Benchmark (49 checks) and has 40 additional checks including related to GDPR and HIPAA.
		* [AWS pwn](https://github.com/dagrz/aws_pwn)
			* This is a collection of horribly written scripts for performing various tasks related to penetration testing AWS. Please don't be sad if it doesn't work for you. It might be that AWS has changed since a given tool was written or it might be that the code sux. Either way, please feel free to contribute. Most of this junk was written by Daniel Grzelak but there's been plenty of contributions, most notably Mike Fuller.
		* **Active Directory**
			* [CloudCopy](https://github.com/Static-Flow/CloudCopy)
				* This tool implements a cloud version of the Shadow Copy attack against domain controllers running in AWS. Any AWS user possessing the EC2:CreateSnapshot permission can steal the hashes of all domain users by creating a snapshot of the Domain Controller mounting it to an instance they control and exporting the NTDS.dit and SYSTEM registry hive file for use with Impacket's secretsdump project.
		* **CloudFront**
			* [CloudFrunt](https://github.com/MindPointGroup/cloudfrunt)
				* CloudFrunt is a tool for identifying misconfigured CloudFront domains.
			* [CloudJack](https://github.com/prevade/cloudjack)
				* CloudJack assesses AWS accounts for subdomain hijacking vulnerabilities as a result of decoupled Route53 and CloudFront configurations. This vulnerability exists if a Route53 alias references 1) a deleted CloudFront web distribution or 2) an active CloudFront web distribution with deleted CNAME(s). If this decoupling is discovered by an attacker, they can simply create a CloudFront web distribution and/or CloudFront NAME(s) in their account that match the victim account's Route53 A record host name. Exploitation of this vulnerability results in the ability to spoof the victim's web site content, which otherwise would have been accessed through the victim's account.
		* **Discovery**
			* [cred_scanner](https://github.com/disruptops/cred_scanner)
				* A simple command line tool for finding AWS credentials in files. Optimized for use with Jenkins and other CI systems.
			* [gitleaks](https://github.com/zricethezav/gitleaks)
				* Gitleaks is a SAST tool for detecting hardcoded secrets like passwords, api keys, and tokens in git repos. Gitleaks aims to be the easy-to-use, all-in-one solution for finding secrets, past or present, in your code.
			* [truffleHog](https://github.com/dxa4481/truffleHog)
				* Searches through git repositories for high entropy strings and secrets, digging deep into commit history
			* [DumpsterDiver](https://github.com/securing/DumpsterDiver)
				* DumpsterDiver is a tool, which can analyze big volumes of data in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords. Additionally, it allows creating a simple search rules with basic conditions (e.g. report only csv files including at least 10 email addresses). The main idea of this tool is to detect any potential secret leaks. 
			* [Whispers](https://github.com/Skyscanner/whispers)
				* Whispers is a static code analysis tool designed for parsing various common data formats in search of hardcoded credentials and dangerous functions. Whispers can run in the CLI or you can integrate it in your CI/CD pipeline.
			* [Dufflebag](https://github.com/BishopFox/dufflebag)
				* Dufflebag is a tool that searches through public Elastic Block Storage (EBS) snapshots for secrets that may have been accidentally left in. You may be surprised by all the passwords and secrets just laying around!
		* **Frameworks**
			* [weirdAAL](https://github.com/carnal0wnage/weirdAAL)
				* The WeirdAAL project has two goals: 1. Answer what can I do with this AWS Keypair [blackbox]?; 2. Be a repository of useful functions (offensive & defensive) to interact with AWS services.
			* [Pacu](https://github.com/RhinoSecurityLabs/pacu)
				* Pacu is an open source AWS exploitation framework, designed for offensive security testing against cloud environments. Created and maintained by Rhino Security Labs, Pacu allows penetration testers to exploit configuration flaws within an AWS account, using modules to easily expand its functionality. Current modules enable a range of attacks, including user privilege escalation, backdooring of IAM users, attacking vulnerable Lambda functions, and much more.
			* [barq](https://github.com/Voulnet/barq)
				* barq is a post-exploitation framework that allows you to easily perform attacks on a running AWS infrastructure. It allows you to attack running EC2 instances without having the original instance SSH keypairs. It also allows you to perform enumeration and extraction of stored Secrets and Parameters in AWS.
		* **IAM**
			* [Enumerate IAM permissions](https://github.com/andresriancho/enumerate-iam)
				* Enumerate the permissions associated with AWS credential set

		* **Nuking**
			* [cloud-nuke](https://github.com/gruntwork-io/cloud-nuke)
				* This repo contains a CLI tool to delete all resources in an AWS account. cloud-nuke was created for situations when you might have an account you use for testing and need to clean up leftover resources so you're not charged for them. Also great for cleaning out accounts with redundant resources. Also great for removing unnecessary defaults like default VPCs and permissive ingress/egress rules in default security groups.

		* **Persistence**
			* [MadKing Amazon Web Services Attack Platform](https://github.com/ThreatResponse/mad-king)
				This project was created as a proof of concept. A marriage of serverless frameworks and the techniques of researcher Daniel Grzelak for persistance in an AWS account.
		* **Scripts & One-offs**
			* [RedDolphin](https://github.com/elitest/RedDolphin)
				* RedDolphin is a collection of scripts that use the Amazon SDK for Python boto3 to perform red team operations against the AWS API.
* **Auditing/Compliance Monitoring**<a name="compliance"></a>
	* [Hammer](https://github.com/dowjones/hammer)
		* Dow Jones Hammer is a multi-account cloud security tool for AWS. It identifies misconfigurations and insecure data exposures within most popular AWS resources, across all regions and accounts. It has near real-time reporting capabilities (e.g. JIRA, Slack) to provide quick feedback to engineers and can perform auto-remediation of some misconfigurations. This helps to protect products deployed on cloud by creating secure guardrails.
	* [ElectricEye](https://github.com/jonrau1/ElectricEye)
		* ElectricEye is a set of Python scripts (affectionately called Auditors) that continuously monitor your AWS infrastructure looking for configurations related to confidentiality, integrity and availability that do not align with AWS best practices. All findings from these scans will be sent to AWS Security Hub where you can perform basic correlation against other AWS and 3rd Party services that send findings to Security Hub. Security Hub also provides a centralized view from which account owners and other responsible parties can view and take action on findings. ElectricEye supports both AWS commercial and GovCloud Regions, however, Auditors for services not supported in GovCloud were not removed. Running these scans in Fargate will not fail the entire task if a service is not supported in GovCloud, in those cases they will fail gracefully.
* **Detecting Credential Compromise**
	* See Defense
	* [SkyWrapper](https://github.com/cyberark/SkyWrapper)
		* SkyWrapper is an open-source project which analyzes behaviors of temporary tokens created in a given AWS account. The tool is aiming to find suspicious creation forms and uses of temporary tokens to detect malicious activity in the account. The tool analyzes the AWS account, and creating an excel sheet includes all the currently living temporary tokens. A summary of the finding printed to the screen after each run.
* **EBS**<a name="ebs"></a>
	* [Dufflebag](https://github.com/BishopFox/dufflebag)
		* Dufflebag is a tool that searches through public Elastic Block Storage (EBS) snapshots for secrets that may have been accidentally left in. You may be surprised by all the passwords and secrets just laying around!
* **External-Monitoring**<a name="external"></a>
	* [aws_public_ips](https://github.com/arkadiyt/aws_public_ips)
		* Fetch all public IP addresses tied to your AWS account. Works with IPv4/IPv6, Classic/VPC networking, and across all AWS services
* **IAM**<a name="awsiam"></a>
		* [AWS IAM Policy Generator for AWS CDK](https://github.com/aletheia/iam-policy-generator)
			* A simple library to generate IAM policy statements with no need to remember all the actions APIs. Remembering IAM policy actions is nearly impossible and sticking to the documentation is time consuming. This library provides a set of predefined constants to be used with any IDE intellisense for autocompletion and a factory class that builds a AWS CDK PolicyStatement with ease. This project goal is to offer simple code handlers, so developers won't have to remember al the complex syntax. This library primary intention is to be used as an helper when writing AWS CDK stack scripts, but it can be used also as a standalone utility in any script.
		* [PMapper](https://github.com/nccgroup/PMapper)
			* Principal Mapper (PMapper) is a script and library for identifying risks in the configuration of AWS Identity and Access Management (IAM) in an AWS account. PMapper allows users to identify which IAM users and roles have access to certain actions and resources in an AWS account. This is important for ensuring that sensitive resources, such as S3 objects with PII, are isolated.
		* [AWS Lambda - IAM Access Key Disabler](https://github.com/te-papa/aws-key-disabler)
			* The AWS Key disabler is a Lambda Function that disables AWS IAM User Access Keys after a set amount of time in order to reduce the risk associated with old access keys.
	* **Least-Privileges**
		* [AirIAM](https://github.com/bridgecrewio/AirIAM)
			* AirIAM is an AWS IAM to least privilege Terraform execution framework. It compiles AWS IAM usage and leverages that data to create a least-privilege IAM Terraform that replaces the exiting IAM management method. AirIAM was created to promote immutable and version-controlled IAM management to replace today's manual and error prone methods.
		* [Policy Sentry](https://github.com/salesforce/policy_sentry)
			* IAM Least Privilege Policy Generator and analysis database.
		* [CloudTracker](https://github.com/duo-labs/cloudtracker)
			* CloudTracker helps you find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies.
			* [Blogpost](https://duo.com/blog/introducing-cloudtracker-an-aws-cloudtrail-log-analyzer)
		* [repokid](https://github.com/Netflix/repokid)
			* AWS Least Privilege for Distributed, High-Velocity Deployment
* **Inventory**<a name="inventory"></a>
	* **Tools**
		* [aws-inventory(janiko71)](https://github.com/janiko71/aws-inventory)	
			* This python script lists all the main resources of your AWS account. This inventory may be uncomplete, but it should help you to find what I call "main" resources that are, in my mind, resources that should affect billing and/or security. Intended for personal use (even if I added some professional features like logging), and for only one account.
		* [clinv](https://github.com/lyz-code/clinv)
			* command line inventory for DevSecOps resources in AWS.
		* [aws-inventory(NCCGroup)](https://github.com/nccgroup/aws-inventory)
			* This is a tool that tries to discover all AWS resources created in an account. AWS has many products (a.k.a. services) with new ones constantly being added and existing ones expanded with new features. The ecosystem allows users to piece together many different services to form a customized cloud experience. The ability to instantly spin up services at scale comes with a manageability cost. It can quickly become difficult to audit an AWS account for the resources being used. It is not only important for billing purposes, but also for security. Dormant resources and unknown resources are more prone to security configuration weaknesses. Additionally, resources with unexpected dependencies pose availability, access control, and authorization issues.
		* [resource-counter](https://github.com/disruptops/resource-counter)
			* This command line tool counts the number of resources in different categories across Amazon regions. This is a simple Python app that will count resources across different regions and display them on the command line. It first shows the dictionary of the results for the monitored services on a per-region basis, then it shows totals across all regions in a friendlier format. It tries to use the most-efficient query mechanism for each resource in order to manage the impact of API activity. I wrote this to help me scope out assessments and know where resources are in a target account.
		* [antiope](https://github.com/turnerlabs/antiope)
			* AWS Inventory and Compliance Framework - intended to be an open sourced framework for managing resources across hundreds of AWS Accounts. From a trusted Security Account, Antiope will leverage Cross Account Assume Roles to gather up resource data and store them in an inventory bucket. This bucket can then be index by ELK or your SEIM of choice to provide easy searching of resources across hundreds of AWS accounts.
* **Lambda**<a name="lambda"></a>
	* [Gaining Persistency on Vulnerable Lambdas - Yuval Avrahami](https://www.twistlock.com/labs-blog/gaining-persistency-vulnerable-lambdas/)
	* [Reverse engineering AWS Lambda - denialof.service](https://www.denialof.services/lambda/)
* **Logging**<a name="logging"></a>
	* **Tools**
		* [trailscraper](https://github.com/flosell/trailscraper)
			* A command-line tool to get valuable information out of AWS CloudTrail and a general purpose toolbox for working with IAM policies
		* [TrailBlazer](https://github.com/willbengtson/trailblazer-aws)
			* TrailBlazer is a tool written to determine what AWS API calls are logged by CloudTrail and what they are logged as. You can also use TrailBlazer as an attack simulation framework.
		* [StreamAlert](https://github.com/airbnb/streamalert)
			* StreamAlert is a serverless, real-time data analysis framework which empowers you to ingest, analyze, and alert on data from any environment, using data sources and alerting logic you define. ]
* **Mapping**<a name="mapping"></a>
	* **Tools**
		* [Cartography](https://github.com/lyft/cartography)
			* Cartography is a Python tool that consolidates infrastructure assets and the relationships between them in an intuitive graph view powered by a Neo4j database.
		* [awspx](https://github.com/FSecureLABS/awspx)
			* awspx is a graph-based tool for visualizing effective access and resource relationships within AWS. It resolves policy information to determine what actions affect which resources, while taking into account how these actions may be combined to produce attack paths. Unlike tools like Bloodhound, awspx requires permissions to function — it is not expected to be useful in cases where these privileges have not been granted.
		* [CloudMapper](https://github.com/duo-labs/cloudmapper)
			* CloudMapper generates network diagrams of Amazon Web Services (AWS) environments and displays them via your browser. It helps you understand visually what exists in your accounts and identify possible network misconfigurations.
* **Resource Usage Tracking**<a name="aresource"></a>
	* [Ice](https://github.com/Teevity/ice)
		* Ice provides a birds-eye view of our large and complex cloud landscape from a usage and cost perspective. It consists of three parts: processor, reader and UI. Processor processes the Amazon detailed billing file into data readable by reader. Reader reads data generated by processor and renders them to UI. UI queries reader and renders interactive graphs and tables in the browser.
* **S3 Buckets**<a name="s3atk>"></a>
	* **Articles/Blogposts/Writeups**
		* [A deep dive into AWS S3 access controls – taking full control over your assets - labs.detectify](https://labs.detectify.com/2017/07/13/a-deep-dive-into-aws-s3-access-controls-taking-full-control-over-your-assets/)
		* [S3 Bucket Namesquatting - Abusing predictable S3 bucket names - Ian Mckay](https://onecloudplease.com/blog/s3-bucket-namesquatting)
		* [A deep dive into AWS S3 access controls – taking full control over your assets(2017)](https://labs.detectify.com/2017/07/13/a-deep-dive-into-aws-s3-access-controls-taking-full-control-over-your-assets/)
	* **General Tools**
		* [s3-utils](https://github.com/whitfin/s3-utils)
			* Utilities and tools based around Amazon S3 to provide convenience APIs in a CLI.
		* [Amazon-Web-Shenanigans](https://github.com/vr00n/Amazon-Web-Shenanigans)
			* A lambda function that checks your account for Public buckets and emails you whenever a new public s3 bucket is created
	* **Discovery/Enumeration of**
		* [Teh S3 Bucketeers](https://github.com/tomdev/teh_s3_bucketeers)
			* Script to scan for buckets with given creds
		* [BuQuikker](https://github.com/Quikko/BuQuikker)
			* This project is intended to show how easy it is to find poorly configured AWS buckets. This project is build on top of bucketeer. It should make the life of a bugbounty hunter much easier. The user needs to provide a list and each word in the list will be used in combination with the teh_s3_bucketeers script. Whenever the script finds an open bucket, the teh_s3_bucketeers script will write it into `result-<name-of-searchword>.txt`
		* [Bucket Stream](https://github.com/eth0izzle/bucket-stream)
			* This tool simply listens to various certificate transparency logs (via certstream) and attempts to find public S3 buckets from permutations of the certificates domain name.
		* [slurp](https://github.com/random-robbie/slurp)
			* Enumerates S3 buckets manually or via certstream
		* [s3finder](https://github.com/magisterquis/s3finder)
			* Yet another program to find readable S3 buckets. Can search using a wordlist or by monitoring the certstream network for domain names from certificate transparency logs. If a name contains dots, a name with the dots replaced by dashes will be tried, as well. All queries are done via HTTPS. Found buckets will be written to stdout. All other messages are written to stderr, to make for easy logging.
		* [S3scan](https://github.com/abhn/S3Scan)
			 * A simple script to find open Amazon AWS S3 buckets in your target websites. S3 buckets are a popular way of storing static contents among web developers. Often, developers tend to set the bucket permissions insecurely during development, and forget to set them correctly in prod, leading to (security) issues.
		* [s3-buckets-bruteforcer](https://github.com/gwen001/s3-buckets-finder)
			* PHP tool to brute force Amazon S3 bucket
		* [s3-fuzzer](https://github.com/pbnj/s3-fuzzer)
			* A concurrent, command-line AWS S3 Fuzzer. Written in Go. 
		* [buckethead.py](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/aws-pentest-tools)
			* buckethead.py searches across every AWS region for a variety of bucket names based on a domain name, subdomains, affixes given and more. Currently the tool will only present to you whether or not the bucket exists or if they're listable.
		* [lazys3](https://github.com/nahamsec/lazys3)
			* A Ruby script to bruteforce for AWS s3 buckets using different permutations.
		* [inSp3ctor](https://github.com/brianwarehime/inSp3ctor)
			* AWS S3 Bucket/Object Finder
	* **Permissions**
		* [S3-Inspector](https://github.com/clario-tech/s3-inspector)
			* Tool to check AWS S3 bucket permissions.
	* **Searching Contents of**
		* [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)
			* AWSBucketDump is a tool to quickly enumerate AWS S3 buckets to look for loot. It's similar to a subdomain bruteforcer but is made specifically for S3 buckets and also has some extra features that allow you to grep for delicious files as well as download interesting files if you're not afraid to quickly fill up your hard drive.
		* [S3Scanner](https://github.com/sa7mon/S3Scanner)
			* A tool to find open S3 buckets and dump their contents
		* [bucketcat](https://github.com/Atticuss/bucketcat)
			* Brute-forces objects within a given bucket using Hashcat mask-like syntax
		* [aws-s3-data-finder](https://github.com/Ucnt/aws-s3-data-finder)
			* Find suspicious files (e.g. data backups, PII, credentials) across a large set of AWS S3 buckets and write the first 200k keys (by default) of listable buckets to a .json or .xml file (in buckets/) via awscli OR unauthenticated via HTTP requests.
		* [Bucketlist](https://github.com/michenriksen/bucketlist)
			* Bucketlist is a quick project I threw together to find and crawl Amazon S3 buckets and put all the data into a PostgreSQL database for querying.
* **Security Groups**
	* [aws-security-viz](https://github.com/anaynayak/aws-security-viz)
		* Need a quick way to visualize your current aws/amazon ec2 security group configuration? aws-security-viz does just that based on the EC2 security group ingress configuration.
* **Securing & Hardening**
	* **101**
		* [CIS Amazon Web Services Foundations](https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf)
		* [asecure.cloud](https://asecure.cloud)
			* A free repository of customizable AWS security configurations and best practices
		* [aws-security-benchmark](https://github.com/awslabs/aws-security-benchmark)
			* Collection of resources related to security benchmark frameworks.
		* [AWS Security Primer](https://cloudonaut.io/aws-security-primer/#fn:2)
		* [AWS Security Hub](https://aws.amazon.com/security-hub/)
			* AWS Security Hub gives you a comprehensive view of your high-priority security alerts and security posture across your AWS accounts. 
		* [Amazon Inspector](https://aws.amazon.com/inspector/)
			* Amazon Inspector is an automated security assessment service that helps improve the security and compliance of applications deployed on AWS. Amazon Inspector automatically assesses applications for vulnerabilities or deviations from best practices. After performing an assessment, Amazon Inspector produces a detailed list of security findings prioritized by level of severity. These findings can be reviewed directly or as part of detailed assessment reports which are available via the Amazon Inspector console or API.
	* **Articles/Blogposts/Writeups**
	* **Tools**
		* [Cloudsplaining](https://github.com/salesforce/cloudsplaining)
			* Cloudsplaining is an AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized HTML report.
		* [LambdaGuard](https://github.com/Skyscanner/LambdaGuard)
			* LambdaGuard is an AWS Lambda auditing tool designed to create asset visibility and provide actionable results. It provides a meaningful overview in terms of statistical analysis, AWS service dependencies and configuration checks from the security perspective.
		* [Cloud-Reports](https://github.com/tensult/cloud-reports)
			* Collects info about various cloud resources and analyzes them against best practices and give a JSON, CSV, HTML, or PDF reports.
		* [Zeus](https://github.com/DenizParlak/Zeus)	
			* Zeus is a powerful tool for AWS EC2 / S3 / CloudTrail / CloudWatch / KMS best hardening practices. It checks security settings according to the profiles the user creates and changes them to recommended settings based on the CIS AWS Benchmark source at request of the user.
		* [terraform-aws-secure-baseline](https://github.com/nozaq/terraform-aws-secure-baseline)
			* Terraform module to set up your AWS account with the secure baseline configuration based on CIS Amazon Web Services Foundations.
* **Tools**
	* [aws_pwn](https://github.com/dagrz/aws_pwn)
		* This is a collection of horribly written scripts for performing various tasks related to penetration testing AWS. Please don't be sad if it doesn't work for you. It might be that AWS has changed since a given tool was written or it might be that the code sux. Either way, please feel free to contribute. Most of this junk was written by Daniel Grzelak but there's been plenty of contributions, most notably Mike Fuller.
	* [Nimbostratus](https://github.com/andresriancho/nimbostratus)
		* Tools for fingerprinting and exploiting Amazon cloud infrastructures
	* [cloudfrunt](https://github.com/MindPointGroup/cloudfrunt)
		* A tool for identifying misconfigured CloudFront domains
	* [cred_scanner](https://github.com/disruptops/cred_scanner)
		* A simple command line tool for finding AWS credentials in files. Optimized for use with Jenkins and other CI systems.
* **Training**
	* [AWS Security Workshops](https://github.com/aws-samples/aws-security-workshops)
		* Here you'll find a collection of security workshops and other hands-on content that will guide you through prepared scenarios that represent common use cases and security operational tasks on Amazon Web Services (AWS). The workshops closely align with the NIST Cyber Security Framework and will provide a deep dive into a variety of AWS security services, techniques, and best practices that'll you'll be able to apply to your own environments to better improve your security posture.
	* [Serverless Security Workshop](https://github.com/aws-samples/aws-serverless-security-workshop)
		* In this workshop, you will learn techniques to secure a serverless application built with AWS Lambda, Amazon API Gateway and RDS Aurora.



















----------------
### <a name="ms-azure"></a>Microsoft Azure
* **101**<a name="a101"></a>
	* [Microsoft Azure: Penetration Testing - Official Documentation](https://docs.microsoft.com/en-us/azure/security/azure-security-pen-testing)
	* [Microsoft Azure Datacenter IP Ranges - ms.com](https://www.microsoft.com/en-us/download/details.aspx?id=41653)
* **Documentation**<a name="adoc"></a>
	* [Azure ATP Security Alerts - docs.ms](https://docs.microsoft.com/en-us/azure-advanced-threat-protection/suspicious-activity-guide)
* **Compliance**<a name="acompliance"></a>
	* [New Azure maps make identifying local compliance options easy - David Burt(2020 azure.microsoft)](https://azure.microsoft.com/en-gb/blog/new-azure-maps-make-identifying-local-compliance-options-easy/)
* **Educational**<a name="aedu"></a>
	* [So you want to learn Azure Security? - Michael Howard(2020)](https://michaelhowardsecure.blog/2020/02/14/so-you-want-to-learn-azure-security/)
* **Articles/Writeups**
	* [An Introduction to PenTesting Azure](https://www.gracefulsecurity.com/an-introduction-to-pentesting-azure/)
	* [Azure operational security checklist - docs.ms](https://docs.microsoft.com/en-us/azure/security/azure-operational-security-checklist)
	* [Security services and technologies available on Azure - docs.ms](https://docs.microsoft.com/en-us/azure/security/azure-security-services-technologies)
	* [Red Teaming Microsoft: Part 1 – Active Directory Leaks via Azure - Mike Felch](https://www.blackhillsinfosec.com/red-teaming-microsoft-part-1-active-directory-leaks-via-azure/)
	* [Identifying & Exploiting Leaked Azure Storage Keys - Sunil Yadav](https://www.notsosecure.com/identifying-exploiting-leaked-azure-storage-keys/)
* **Presentations/Talks/Videos**
	* [Blue Cloud of Death: Red Teaming Azure - Bryce Kunz](https://speakerdeck.com/tweekfawkes/blue-cloud-of-death-red-teaming-azure-1B)
	* [I'm in your cloud: A year of hacking Azure AD - Dirk-Jan Mollema](https://www.youtube.com/watch?v=fpUZJxFK72k)
* **Tools**
	* [Azurite - Azurite Explorer and Azurite Visualizer](https://github.com/mwrlabs/Azurite)
		* consists of two helper scripts: Azurite Explorer and Azurite Visualizer. The scripts are used to collect, passively, verbose information of the main components within a deployment to be reviewed offline, and visulise the assosiation between the resources using an interactive representation. One of the main features of the visual representation is to provide a quick way to identify insecure Network Security Groups (NSGs) in a subnet or Virtual Machine configuration.














------------------
### <a name="gcp"></a>Google Cloud
* **101**<a name="g101"></a>
* **Articles/Writeups**
	* [Abusing Google App Scripting Through Social Engineering](http://www.redblue.team/2017/02/abusing-google-app-scripting-through.html)
	* [Persistent GCP backdoors with Google’s Cloud Shell - Juan Berner](https://medium.com/@89berner/persistant-gcp-backdoors-with-googles-cloud-shell-2f75c83096ec)
	* [Red Team Tactics for Cracking the GSuite Perimeter - Michael Felch](https://www.slideshare.net/MichaelFelch/red-team-tactics-for-cracking-the-gsuite-perimeter)
* **Containers**<a name="gcon"></a>
	* [Getting vulnerabilities and metadata for images - cloud.google](https://cloud.google.com/container-registry/docs/get-image-vulnerabilities)
* **Monitoring**<a name="gmon"></a>
	* [Setting up advanced network threat detection with Packet Mirroring - Shishir Agrawal, Yang Liang(cloud.google)](https://cloud.google.com/blog/products/networking/packet-mirroring-enables-better-network-monitoring-and-security)
* **Presentations/Talks/Videos**
	* [G-Jacking AppEngine-based applications - HITB2014](https://conference.hitb.org/hitbsecconf2014ams/materials/D2T1-G-Jacking-AppEngine-based-Applications.pdf)
* **Tools**<a name="gtools"></a>
	* **Attacking**
		* [Introducing G-Scout](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/august/introducing-g-scout/)
			* G-Scout is a tool to help assess the security of Google Cloud Platform (GCP) environment configurations. By leveraging the Google Cloud API, G-Scout automatically gathers a variety of configuration data and analyzes this data to determine security risks. It produces HTML output.
		* [Google Cloud Platform Security Tool](https://github.com/nccgroup/G-Scout)
	* **Securing**
		* [Google Cloud Security Scanner](https://cloud.google.com/security-scanner/)
			* Cloud Security Scanner is a web security scanner for common vulnerabilities in Google App Engine applications. It can automatically scan and detect four common vulnerabilities, including cross-site-scripting (XSS), Flash injection, mixed content (HTTP in HTTPS), and outdated/insecure libraries. It enables early identification and delivers very low false positive rates. You can easily setup, run, schedule, and manage security scans and it is free for Google Cloud Platform users.
		* [Hayat](https://github.com/DenizParlak/Hayat)
			* Google Cloud Platform Auditing & Hardening Script
