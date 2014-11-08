

Using TCP dump to dump traffic to a pcap file for inspection later:
	tcpdump -i <interface> -s 65535 -w <some-file>

Spawning Shells

Sometimes when you pop a box, you’re left with something other than a full TTY shell. These commands can help you spawn one.
Shell Spawning

python -c 'import pty; pty.spawn("/bin/sh")'


echo os.system('/bin/bash')


/bin/sh -i


perl —e 'exec "/bin/sh";'


perl: exec "/bin/sh";



ruby: exec "/bin/sh"


lua: os.execute('/bin/sh')

(From within IRB) 

exec (’bin/sh’)
(From within vi) 
bash
(From within vi)
:set shell=/bin/bash:shell

(from within nmap)

(From http://netsec.ws/?p=337#more-337 )