-Maps, Models, and Martial Arts-

- (Been on my todo list for almost x years now, felt it wasn't necessary after seeing Jackson T's initial blogposts, and then his followups, but recently changed my mind after rewatching Casey Smith's talk on Cyber Cartography. ([Link](https://www.youtube.com/watch?app=desktop&v=Z0ohI8-XkZ0).
- This is being posted/shared publicly more as intellectual candy than anything else to be clear.
- Nothing said here is new, and arguably(not really arguable, just saying) Jackson did a much better of describing roughly the same/similar concepts([Link](https://jackson_t.gitlab.io/operational-mental-models.html)). So, YMMV.


Gist: By taking a 10/100k foot overview look at the application of OODA loops, US military strategic doctrine, and martial arts to create a loose methodology to help define strategic goals, and tactics to achieve them during 'operations'
	Further:
			Operating in a 'combat space' where the 'land'/area of operations is a known, understandable, observable and verifiable quantity.
			There may be areas of unknown, but it does not expand once the engagement has begun, nor does it diminish. It's size and scope remains constant.
			In this case, the area of operation is the domain of computing hardware and software.
- _
	- For this, I make several statements as a foundation:
		1. Computer operations occur inside a constrained space. All variables/context is capable of being known, there are no 'unknown' values from an _objective_ PoV(if you have full access to a machine, you can see and understand all parts of it, not practically guaranteed, but it is possible)
		
		2. As such, it is possible to take into consideration all operations and tactics that may be used by an attacker/defender at each point during an action.
		
		3. With this in mind, it is beneficial to understand the full context of the system which an operation is taking place, so that operations may be more efficient when making tactical choices. Idea being you understand the implications of each action, and what doors open/close upon performing each.

		4. With a full understanding of the context of the system in which operations are taking place, it is possible to model the entire system for approximating impact and results of various tactics - (analogy is cuboidal space in a physical altercation)

		5. One can use then use OODA loops to help choose the most 'correct' action given that the system is modeled and understood, one can be more specific/nuanced in their decision of actions.

		6. Stepping back, we have modeled the 'field of operations' and are using OODA loops to help augment decision making. We then add in the '5 Ds' (https://foreignpolicy.com/2013/04/12/the-five-deadly-ds-of-the-air-forces-cyber-arsenal/) and apply that concept to the operations performed, to augment our overall strategy. (Or insert whatever overall strategy you wish, going for US because am US citizen :p)

		7. We also pull in the concept of 'negative space'([Link](https://en.wikipedia.org/wiki/Negative_space)) and Newton's 4th law ([Link](https://www.physicsclassroom.com/class/newtlaws/Lesson-4/Newton-s-Third-Law) - `For every action, there is an equal and opposite reaction.`
			- Reasons being that operations are designed with the idea that all actions will entail a chain of actions, all of which should be expected, planned for, and understood. The goal being that this is taken into consideration during planning and is used as a means of defense or obfuscation in an attempt to mislead the analysis of the operation/maneuver

		8. Summing it all up with creating a 'simple methodology' for walking through the process before and during an operation (for defense and offense); using OODA loops to make it 'simple'

Links for context:
OODA loops talk by Jackson T: http://jackson-t.ca/ooda-loops.html
Definition of strategy i'm using: https://hbr.org/books/playing-to-win
Negative Space: https://en.wikipedia.org/wiki/Negative_space
The 5 Ds: https://foreignpolicy.com/2013/04/12/the-five-deadly-ds-of-the-air-forces-cyber-arsenal/


Since this was never fully fleshed out, and was shared in a private conversation, I have included the discussion as I feel it helps flesh out my thinking and approach. Names redacted for politeness.


Convo:
```
Person A:
- I agree in theory that all possible actions in a digital space are knowable, but in practice, classifying more advanced actions into benign and malicious ones tends to be non-trivial for both offense and defense.
- Being able to model and simulate the system is definitely helpful and possible. Can you elaborate on your analogy?
- With the 5 D's, would you consider those outside of the OODA loop or within it?

It's awesome seeing your thought process around this. If you don't mind me asking, what led you to this style of thinking and is that something you get to apply in your current role?
```
My response:
```
Sure, np!

1. Absolutely. I plan to adopt a 21pt scale, similar to the one espoused in "Applied Network Security Monitoring", using ranges of 7 for 'low-med-high', with 7pts being assigned per each to help with the variance. The goal is not to be necessarily precise but approximate.
It is not like ATT&CK where the idea is to map techniques to specific phases, or document specific techniques. That would be separate/additional to this.
An example would be 'I decided that in the context of situation A, the best course of action to reach the goal was action Z, which was determined by the operator to have a risk of 15. I say this because of HIJ.' and then expanding on each of those statements to a 'reasonable' degree; I'm aiming more for an analysis framework than a hard and fast end-to-end comprehensive methodology.
2. Sure, so the idea is that without a model of an environment or concept, it is a free form idea. There are no immediate constraints to it, beyond that which is inherent to the idea. So by creating a model, you place constraints on it, and force them to be recognized. This can help re-inforce pre-existing conditions which must be understood and operated around.
An example of this would be your talk in discussing the '<snip>' tool. My takeaway was that you created/helped create that tool after creating a model for the operations an EDR performs within the greater context of the Windows User environment. By studying that model which you created/built, you were then able to build a tool based off of the model you created. You also now have a model of EDR operations and techniques, to help in further studies/operations.
Taking the application to the framework would be modeling the routes an individual/operator might take to achieve the stated goal based on their understanding. So a very loose example could be modeling the network with VMs and software, creating a full simulation, or doing the same with paper. Creating a diagram to show the network, noting each node with specific information about it, and applying a general template across. The idea being of performing something like a tabletop against the network in preparation.
In doing so, you would need to go a certain depth in the simulation bit, such that you would choose or state a specific technique and the implications thereof, what artifacts it might leave, and why you believe it is 'safe' or worthwhile to perform. This would then be checked against the endpoint/target information (assuming its not already available) and contrasted to see the 'theoretical' effectiveness of the technique/tactic. This would be backed up by actual testing within a lab, so that the stated claims are validated and proven.
You would continue this, until the goal is reached. (so pretty much a tabletop)
Alternatively, a smaller example would be your assumed work on the <snip> tool, you studied how EDRs worked, modeled their operation, and looked to see how you might undermine it. Taking a step back from that, and instead saying, let's model the process execution environment in windows, so that we can understand the entirety of the holistic process, and be better able to identify means of undermining and reinforcement. 
Once that has been modeled, you can then use that model in your larger model for host-based operations, and be better equipped to understand what tactics will be most effective in X situation. You did this in your OODA loop talk/paper with EDR systems.
The longer version of the analogy I prefer to use is in terms of physical combat, with two combatants facing off against one another, and the ideas of Timing, Distance, Angles, and Leverage. Each item can be measured and monitored, and therefore, 'expected' in a certain way. One can know how long it takes to move x distance, or punch z distance. With this in mind, you can make your movements much more nuanced and efficient, as you understand how to 'properly' move. 
Taking that idea and applying it to computers. Using modeling like you demonstrated in understanding EDR operations. Being able to justify and explain courses of action in terms of expected/observed conditions to a degree beyond, "I ran the binary through shellter because how else am I gonna evade AV?" The goal is to avoid that and work towards creating an understanding there rather than a lack of deeper knowledge.

3. I would consider those as embedded within the entire process. I subscribe to the "Playing to Win" definition/approach to strategy, (https://www.flowresulting.nl/wp-content/uploads/2017/10/figuur1-vijf-keuzes.png) and as such, I feel that the 5Ds are more (sub)goals than processes. They are something to be asked of during the selection of a task/procedure vs during the middle of a task/procedure. Similar to a 'feeling', it is omni-present or 'ethereal' in its existence. They should be included in the performance/planning of tasks/operations such that the entire operations/task fulfills or takes into credence all of them, and focusing on whichever is the most appropriate at the time.
```

