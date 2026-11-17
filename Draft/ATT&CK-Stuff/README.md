# ATT&CK mappings

## Mitre Pre-ATT&CK Mappings
---------------------------
* MITRE Pre-ATT&CK Framework ([MITRE ATT&CK Framework](https://attack.mitre.org/pre-attack/index.php/Main_Page) for attackers.
* This is a copy of the mappings with links to techniques and background information.
- [Adversary Opsec](Pre-ATT%26CK/Adversary_OPSEC.md)
- [Build Capabilities](Pre-ATT%26CK/Build_Capabilities.md)
- [Organization Informational Gathering](Pre-ATT%26CK/Organizationa_%20Information_Gathering.md)
- [Organizational Weakness](Pre-ATT%26CK/Organizational_Weakness.md)
- [People Information Gathering](Pre-ATT%26CK/People_Information_Gathering.md)
- [People Weakness Identification](Pre-ATT%26CK/People_Weakness_Identification.md)
- [Persona Development](Pre-ATT%26CK/Persona_Development.md)
- [Priority Definition Planning](Pre-ATT%26CK/Priority_Definition%20_lanning.md)
- [Priority Definition Directive](Pre-ATT%26CK/Priority_Definition_Directive.md)
- [Stage Capabilities](Pre-ATT%26CK/Stage_Capabilities.md)
- [Target Selection](Pre-ATT%26CK/Target_Selection.md)
- [Technical Information Gathering](Pre-ATT%26CK/Technical_Information_Gathering.md)
- [Test Capabilities](Pre-ATT%26CK/Test_Capabilities.md)






## MITRE ATT&CK Framework Mappings 
---------------------------
* MITRE ATT&CK Framework ([MITRE ATT&CK Framework](https://attack.mitre.org/wiki/Main_Page)) for attackers.
* This is a copy of the mappings with links to techniques and background information rather than APT reports.
	* If you want to test your defenses against a lot of these things:
		* [Atomic Red Team - Small and highly portable detection tests mapped to the Mitre ATT&CK Framework.](https://github.com/redcanaryco/atomic-red-team)
* [Collection](ATT%26CK/Collection.md)
* [Command and Control](ATT%26CK/Command_and_Control.md)
* [Credential Access](ATT%26CK/Credential_Access.md)
* [Defense Evasion](ATT%26CK/Defense_Evasion.md)
* [Discovery](ATT%26CK/Discovery.md)
* [Execution](ATT%26CK/Execution.md)
* [Exfiltration](ATT%26CK/Exfiltration.md)
* [Initial Access](ATT%26CK/Initial_Access.md)
* [Lateral Movement](ATT%26CK/Lateral%20Movement.md)
* [Persistence](ATT%26CK/Persistence.md)
* [Privilege Escalation](ATT%26CK/Privilege_Escalation.md)
* If you want to test your defenses against a lot of these things:
	* [Atomic Red Team - Small and highly portable detection tests mapped to the Mitre ATT&CK Framework.](https://github.com/redcanaryco/atomic-red-team)
	* [Caldera](https://github.com/mitre/caldera)
		* CALDERA is an automated adversary emulation system that performs post-compromise adversarial behavior within enterprise networks. It generates plans during operation using a planning system and a pre-configured adversary model based on the Adversarial Tactics, Techniques & Common Knowledge (ATT&CK™) project. These features allow CALDERA to dynamically operate over a set of systems using variable behavior, which better represents how human adversaries perform operations than systems that follow prescribed sequences of actions.
	* [Metta](https://github.com/uber-common/metta)
		* An information security preparedness tool to do adversarial simulation. This project uses Redis/Celery, python, and vagrant with virtualbox to do adversarial simulation. This allows you to test (mostly) your host based instrumentation but may also allow you to test any network based detection and controls depending on how you set up your vagrants. The project parses yaml files with actions and uses celery to queue these actions up and run them one at a time without interaction.








