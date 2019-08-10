# Data Visualization



## Table of Contents
* To be sorted
* Tools
* Writeups



* [Open Graph Viz Platform](https://gephi.org/)
	* Gephi is the leading visualization and exploration software for all kinds of graphs and networks. Gephi is open-source and free.

* https://arxiv.org/abs/1901.01769

https://www.blackhillsinfosec.com/pyfunnels-data-normalization-for-infosec-workflows/
https://github.com/packetvitality/PyFunnels
https://www.sans.org/reading-room/whitepapers/OpenSource/pyfunnels-data-normalization-infosec-workflows-38785

### To Do
* Split into Data visualization/Working with data
* Edward Tufte Books

#### Sort

[Userline](https://github.com/THIBER-ORG/userline)
* This tool automates the process of creating logon relations from MS Windows Security Events by showing a graphical relation among users domains, source and destination logons as well as session duration.

[Just-Metadata](https://github.com/ChrisTruncer/Just-Metadata)
* Just-Metadata is a tool that can be used to gather intelligence information passively about a large number of IP addresses, and attempt to extrapolate relationships that might not otherwise be seen. Just-Metadata has "gather" modules which are used to gather metadata about IPs loaded into the framework across multiple resources on the internet. Just-Metadata also has "analysis" modules. These are used to analyze the data loaded Just-Metadata and perform various operations that can identify potential relationships between the loaded systems.

* [NewsDiffs](https://github.com/ecprice/newsdiffs)
	* Automatic scraper that tracks changes in news articles over time.
* [Active Directory Control Paths](https://github.com/ANSSI-FR/AD-control-paths)
	* Control paths in Active Directory are an aggregation of "control relations" between entities of the domain (users, computers, groups, GPO, containers, etc.) which can be visualized as graphs (such as above) and whose purpose is to answer questions like "Who can get 'Domain Admins' privileges ?" or "What resources can a user control ?" and even "Who can read the CEO's emails ?".


Apache Nifi - supports powerful and scalable directed graphs of data routing, transformation, and system mediation logic.
https://nifi.apache.org/

http://linkurio.us/toolkit/

http://marvl.infotech.monash.edu/webcola/

http://www.yasiv.com/graphs#Bai/rw496

http://plaso.kiddaland.net/

Check out http://secviz.org/

http://sourceforge.net/projects/rapidminer/

http://orange.biolab.si/

https://rapidminer.com/


http://ipython.org/

https://www.documentcloud.org/home

http://www.pentaho.com/

Applied Security Visualization: http://www.secviz.org/content/applied-security-visualization

[Scriptorium-LE](https://github.com/imifos/Scriptorium-LE/)
* A Linux machine state enumeration, data visualisation and analysis tool.

#### End Sort

-----
### Tools
* [d3js(Data Driven Documents)](http://d3js.org/)
	* D3.js is a JavaScript library for manipulating documents based on data. D3 helps you bring data to life using HTML, SVG, and CSS. D3’s emphasis on web standards gives you the full capabilities of modern browsers without tying yourself to a proprietary framework, combining powerful visualization components and a data-driven approach to DOM manipulation. 
* [Data Science Toolkit](https://github.com/petewarden/dstk)
	* A collection of the best open data sets and open-source tools for data science, wrapped in an easy-to-use REST/JSON API with command line, Python and Javascript interfaces. Available as a self-contained VM or EC2 AMI that you can deploy yourself.
	* [Documentation](http://www.datasciencetoolkit.org/developerdocs)
* [ORA](http://www.casos.cs.cmu.edu/projects/ora/)
	* ORA is a dynamic meta-network assessment and analysis tool developed by CASOS at Carnegie Mellon.  It contains hundreds of social network, dynamic network metrics, trail metrics, procedures for grouping nodes, identifying local patterns, comparing and contrasting networks, groups, and individuals from a dynamic meta-network perspective. ORA has been used to examine how networks change through space and time,  contains procedures for moving back and forth between trail data (e.g. who was where when) and network data (who is connected to whom,  who is connected to where …),  and has a variety of geo-spatial network metrics, and change detection techniques. ORA can handle multi-mode, multi-plex, multi-level networks.  It can identify key players, groups and vulnerabilities, model network changes over time, and perform COA analysis.  It has been tested with large networks (106 nodes per 5 entity classes). Distance based, algorithmic, and statistical procedures for comparing and contrasting networks are part of this toolkit.  Based on network theory, social psychology, operations research, and management theory a series of measures of “criticality” have been developed at CMU.  Just as critical path algorithms can be used to locate those tasks that are critical from a project management perspective, the ORA algorithms can find those people, types of skills or knowledge and tasks that are critical from a performance and information security perspective. 
* [pewpew](https://github.com/hrbrmstr/pewpew)
	* In all seriousness, IPew provides a simple framework - based on Datamaps - for displaying cartographic attack data in a (mostly) responsive way and shows how to use dynamic data via javascript event timers and data queues (in case you're here to learn vs have fun - or both!). You can customize the display through a myriad of query string options, including sounds.
* [Data Maps](https://datamaps.github.io/)
	* Customizable SVG map visualizations for the web in a single Javascript file using D3.js
* [Import.IO](https://import.io/)
	* Use our tool to build APIs to all your favorite websites with just a few clicks of the mouse.  - Data Scraping
* [kippo-graph](https://github.com/ikoniaris/kippo-graph)
	* Visualize statistics from a Kippo SSH honeypot 
* [simgaJS-webcola](https://github.com/qinfchen/sigmajs-webcola)
	* webcola plugin for sigmajs 
* [Airodump-NG Scan Visualizer](http://hackoftheday.securitytube.net/2015/03/airodump-ng-scan-visualizer-ver-01.html)	
* [Graphite - Scalable Realtime Graphing](http://graphite.wikidot.com/start) 
	* [Quick Start Guide](http://graphite.wikidot.com/quickstart-guide)
* [StatsD](https://github.com/etsy/statsd/)
	* A network daemon that runs on the Node.js platform and listens for statistics, like counters and timers, sent over UDP or TCP and sends aggregates to one or more pluggable backend services (e.g., Graphite).
* [Kismet Log Viewer - KLV](http://mindflip.org/klv/)
	* The Kismet Log Viewer (KLV) takes Kismet .xml log files and produces a nicely formatted html interface to browse the logs with. KLV has the ability to utilize available GPS information to create links for external maps via the net, and provides the ability for those with Snort to generate a page of Snort output for each specific bssid that has data available. KLV also comes with my Kismet Log Combiner script to help users consolidate multiple .xml and .dump log files.
* [plaso](https://github.com/log2timeline/plaso)
	* plaso (Plaso Langar Að Safna Öllu) is a Python-based backend engine for the tool log2timeline. 
* [huginn](https://github.com/huginn/huginn)
	* Create agents that monitor and act on your behalf. Your agents are standing by! Huginn is a system for building agents that perform automated tasks for you online. They can read the web, watch for events, and take actions on your behalf. Huginn's Agents create and consume events, propagating them along a directed graph. Think of it as a hackable version of IFTTT or Zapier on your own server. You always know who has your data. You do.
* [Norikra](http://norikra.github.io/)
	* Norikra is a open source server software provides "Stream Processing" with SQL, written in JRuby, runs on JVM, licensed under GPLv2.
* [Fluentd](https://www.fluentd.org/architecture)
	* Fluentd is an open source data collector, which lets you unify the data collection and consumption for a better use and understanding of data.
* Modeling Network Data
	* [Flowsynth](https://github.com/secureworks/Flowsynth)
		* Flowsynth is a tool for rapidly modelling network traffic. Flowsynth can be used to generate text-based hexdumps of packets as well as native libpcap format packet captures.



-----
### Writeups
* [Generalizing Data Flow Information](http://uninformed.org/?v=all&a=34&t=sumry)
	* Generalizing information is a common method of reducing the quantity of data that must be considered during analysis. This fact has been plainly illustrated in relation to static data flow analysis where previous research has described algorithms that can be used to generalize data flow information. These generalizations have helped support more optimal data flow analysis in certain situations. In the same vein, this paper describes a process that can be employed to generalize and persist data flow information along multiple generalization tiers. Each generalization tier is meant to describe the data flow behaviors of a conceptual software element such as an instruction, a basic block, a procedure, a data type, and so on. This process makes use of algorithms described in previous literature to support the generalization of data flow information. To illustrate the usefulness of the generalization process, this paper also presents an algorithm that can be used to determine reachability at each generalization tier. The algorithm determines reachability starting from the least specific generalization tier and uses the set of reachable paths found to progressively qualify data flow information for each successive generalization tier. This helps to constrain the amount of data flow information that must be considered to a minimal subset. 
*[Using amCharts to Create Beautiful Wireshark Visualizations](http://www.thevisiblenetwork.com/2015/03/19/using-amcharts-to-create-beautiful-wireshark-visualizations/)
* [Drawing effective network diagrams](https://www.auvik.com/media/blog/effective-network-diagrams/)
