##Sandboxes and Sandbox Technology/Methods/Implementations






[NaCl SFI model on x86-64 systems](https://developer.chrome.com/native-client/reference/sandbox_internals/x86-64-sandbox#x86-64-sandbox)
* This document addresses the details of the Software Fault Isolation (SFI) model for executable code that can be run in Native Client on an x86-64 system





[Adapting Software Fault Isolation to Contemporary CPU Architectures](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/35649.pdf)
* Adapting Software Fault Isolation to Contemporary CPU ArchitecturesSoftware Fault Isolation (SFI) is an effective approach to sandboxing binary code of questionable provenance, an interesting use case for native plugins in a Web browser. We present software fault isolation schemes for ARM and x86-64 that provide control-flow and memory integrity with average performance overhead of under 5% on ARM and 7% on x86-64. We believe these are the best known SFI implementations for these architectures, with significantly lower overhead than previous systems for similar architectures. Our experience suggests that these SFI implementations benefit from instruction-level parallelism, and have particularly small impact for work- loads that are data memory-bound, both properties that tend to reduce the impact of our SFI systems for future CPU implementations.](https://static.googleusercontent.com/media/research.google.com/en/us/pubs/archive/35649.pdf)











