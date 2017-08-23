# AV_Heuristic Measures(Some)

## Some of the known rules about threat grading;

* Decryption loop detected
* Reads active computer name
* Reads the cryptographic machine GUID
* Contacts random domain names
* Reads the windows installation date
* Drops executable files
* Found potential IP address in binary memory
* Modifies proxy settings
* Installs hooks/patches the running process
* Injects into explorer
* Injects into remote process
* Queries process information
* Sets the process error mode to suppress error box
* Unusual entrophy
* Possibly checks for the presence of antivirus engine
* Monitors specific registry key for changes
* Contains ability to elevate privileges
* Modifies software policy settings
* Reads the system/video BIOS version
* Endpoint in PE header is within an uncommon section
* Creates guarded memory regions
* Spawns a lot of processes
* Tries to sleep for a long time
* Unusual sections
* Reads windows product id
* Contains decryption loop
* Contains ability to start/interact device drivers
* Contains ability to block user inpu