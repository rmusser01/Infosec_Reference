Metasploit Reference






Meterpreter CMD Reference:

ps - (show running processes and their associated users/id numbers)
getuid - Get user ID
getpid - Gets the process ID
getprivs - (shows current privileges)
getsystem - Attempts to get SYSTEM using 4 methods, the last being a local exploit called Kitrap0d. This can sometimes be caught by host based IDS systems and even in rare occasions blue screen the machine.
sysinfo - Get system information
timestomp - Remove/screw up timestamps if you are good enough this messes up audit tools
clearev - Clears event logs
hashdump - dump SAM file hashes for pass the hash or cracking
migrate [pid] - Move from exploited process into another process