##Sandboxes and Sandbox Technology/Methods/Implementations



sandbox-attacksurface-analysis-tools
https://github.com/google/sandbox-attacksurface-analysis-tools
http://googleprojectzero.blogspot.com.mt/2015/11/windows-sandbox-attack-surface-analysis.html



[Adobe Sandbox: When the Broker is Broken - Peter Vreugdenhill](https://cansecwest.com/slides/2013/Adobe%20Sandbox.pdf)

[NaCl SFI model on x86-64 systems](https://developer.chrome.com/native-client/reference/sandbox_internals/x86-64-sandbox#x86-64-sandbox)
* This document addresses the details of the Software Fault Isolation (SFI) model for executable code that can be run in Native Client on an x86-64 system



 Sandboxed Execution Environment 
http://pythonhosted.org/python-see
Documentation: http://pythonhosted.org/python-see
Sandboxed Execution Environment (SEE) is a framework for building test automation in secured Environments.  The Sandboxes, provided via libvirt, are customizable allowing high degree of flexibility. Different type of Hypervisors (Qemu, VirtualBox, LXC) can be employed to run the Test Environments.

| ** sandbox-attacksurface-analysis-tools** | https://github.com/google/sandbox-attacksurface-analysis-tools | This is a small suite of tools to test various properties of sandboxes on Windows. Many of the checking tools take a -p flag which is used to specify the PID of a sandboxed process. The tool will impersonate the token of that process and determine what access is allowed from that location. Also it's recommended to run these tools as an administrator or local system to ensure the system can be appropriately enumerated.


[Adapting Software Fault Isolation to Contemporary CPU Architectures](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/35649.pdf)
* Adapting Software Fault Isolation to Contemporary CPU ArchitecturesSoftware Fault Isolation (SFI) is an effective approach to sandboxing binary code of questionable provenance, an interesting use case for native plugins in a Web browser. We present software fault isolation schemes for ARM and x86-64 that provide control-flow and memory integrity with average performance overhead of under 5% on ARM and 7% on x86-64. We believe these are the best known SFI implementations for these architectures, with significantly lower overhead than previous systems for similar architectures. Our experience suggests that these SFI implementations benefit from instruction-level parallelism, and have particularly small impact for work- loads that are data memory-bound, both properties that tend to reduce the impact of our SFI systems for future CPU implementations.](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/35649.pdf)





[Usermode Sandboxing](http://www.malwaretech.com/2014/10/usermode-sandboxing.html)

[Advanced Desktop Application Sandboxing via AppContainer](https://www.malwaretech.com/2015/09/advanced-desktop-application-sandboxing.html)





