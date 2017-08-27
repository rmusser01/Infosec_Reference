So, you want to be a darknet drug lord...
by nachash
nachash@observers.net
 
[The advice in this article can be adapted to suit the needs of other
hidden services, including ones which are legal in your jurisdiction.
The threat model in mind is that of a drug market. The tone is that of a
grandfather who is always annoyingly right, who can't help but give a
stream-of-consciousness schooling to some whippersnapper about the way
the world works. If this article inspires you to go on a crime spree and
you get caught, don't come crying to me about it.]
 
You've decided that you're bored with your cookie-cutter life of working
at a no-name startup, getting paid in stock options and empty promises.
You want a taste of the good life. Good for you, kid. I used to run a
fairly popular hidden service (DOXBIN) that was seized by the FBI after
3 1/2 years of spreading continuous butthurt, then subsequently
repossessed from the feds. Because I managed to not get raided, I'm one
of the few qualified to instruct others on hidden services and security,
simply because I have more real-world experience operating hidden
services than the average tor user. In other words, very little of this
advice is of the armchair variety, as you'll often find in abundance the
Internet. But enough about me. Let's talk about your future as an
internet drug lord.
 
1. Legal/Political
 
First things first, you need to cover the legal, historical and
political angles. Read up on various drug kingpins and cartels from the
20th century. Learn everything you can about how they rose and fell (
you can safety ignore all the parts about intelligence agencies backing
one drug cartel over another, because that's not going to happen to
you). Once you've got a good command of that, read everything you can
about busted drug market operators and branch out into cybercrime
investigations as well. It wouldn't hurt to make yourself familiar with
law enforcement and intelligence agency tactics either. You'll find that
virtually all drug kingpins either get murdered or go to prison. Let
those lessons sink in, then find a good drug lawyer and make plans for
being able to pay them when The Man seizes everything you own. While
you're dreaming big about making fat stacks of fake internet money, do
some research on Mutual Legal Assistance Treaties and extradition treaties.
 
Mutual Legal Assistance Treaties (MLATs) are self-explanatory. Country A
will help Country B do whatever it takes to aid a cybercrime
investigation should some aspect of the crime bleed over into Country A.
Figure out which countries don't provide legal assistance to your
country in these cases, then find hosting services that are based there.
You'll shorten this list by determining which hosts allow tor, or at
least don't explicitly forbid it in their Terms of Service (you don't
care about exit bandwidth. You just want relays. Remember this for later
in the article). Last but not least, sort out which hosts accept payment
options that don't make you sweat bullets over the fact that the NSA has
been monitoring global financial transactions since at least the 1970s.
You will want to avoid any host that advertises itself as bulletproof --
they'll probably kit your box and siphon everything of value, in
addition to overcharging you for the privilege of running on older
hardware -- and any host which sells a cheap VPS and promises to
guarantee your privacy.
 
Extradition treaties mean that if you're in Country A and do something
that makes Country B want to prosecute you, Country A is most likely
going to give you a one way ticket to Country B. If or when your box
gets seized and you know the heat is on, you're going to want to beat it
to a place that won't send you back, where you will presumably live out
the rest of your days. Just make sure you've made enough money to grease
all the right palms in your new life, or the road ahead may be extremely
bumpy. If you're smart, you'll permanently move to this country well
before you have any trouble with law enforcement.
 
One last thing before moving on: Don't be so stupid as to attempt to
hire a hitman to kill anyone. Murder-related charges have no statute of
limitations, which means you won't get to write a tell-all book about
what a sly bastard you are when this wild ride is a distant memory. If
you've reached a point in your new career where murdering people makes
sense, it's time to walk away. Don't get corrupted like Dread Pirate
Roberts.
 
2. Technical
 
This section tries to be as operating system independent as possible.
You'll want to consult the documentation of your OS for specifics. The
technical side of running a hidden service and not getting owned by cops
is a lot harder than just installing stuff and crossing your fingers.
The recommendations in this section WILL NOT protect you from 0days in
the wild, but should help somewhat with damage control. Remember, if
they want to own your hidden service, it will probably happen eventually.
 
Before you even think about installing bitwasp and tor, you need to
really understand how tor works. Go to freehaven.net and read the white
papers until your eyes glaze over, then continue reading until you're
out of papers to read. Pay particular attention to the hidden service
papers. If you feel like you didn't understand something, come back to
that paper again when you have more knowledge. A lot of the papers
explain some of the same concepts with slight differences in the intros.
Don't skim over them, because you might read someone's rewording that
will clarify an idea for you. Check back with freehaven regularly. Once
you're up to speed, a good next step is to keep up with the tor
project's mailing lists. [1]
 
While you're doing all of this reading, it's (mostly) safe to go ahead
and install tor on a box on your local network, purely for
experimentation. Keep in mind that the NSA will start scooping up all of
your packets simply because you visited torproject.org. That means don't
post code questions related your drug market on Stack Exchange, if you
want to avoid giving The Man morsels he can use for parallel
construction. Once you've gotten hidden services working for http and
ssh, you're going to take the first baby step towards evading casual
discovery: Bind your hidden services to localhost and restart them.
 
The next step in your journey towards changing the drug business forever
is to grab the transparent proxying firewall rules for your operating
system to make sure they work. [2] They will guard against attacks that
cause your box to send packets to a box the attacker controls, which is
useful in thwarting attempts to get the box IP. You may wish to have a
setup similar to an anonymous middle box, preferably without public IPs
where possible, so if your application gets rooted tor isn't affected.
 
Speaking of applications, do everything you can to ensure that the
application code you use to power your hidden service isn't made of
Swiss cheese and used bandaids. To protect against other types of
attacks, you will want to identify any pre-compiled software that your
users will touch and compile it yourself with hardening-wrapper or it's
equivalent, plus any custom flags you want to use. If you keep
vulnerabilities from the application and server to a minimum, your
biggest worries will be tor-related.
 
You will only connect to your production box via a hidden service. It's
a good idea to get into that habit early. The only time deviating from
this pattern is acceptable is when you have to upgrade tor, at which
time you'll want to have a script ready that drops your firewall rules
and unbinds ssh from localhost just long enough for you to login, do the
upgrade, re-apply the firewall rules and bind ssh to localhost again. If
you're not ready to deal with the latency, you're not ready to do any of
this. Don't forget to transparently proxy the machine you use too, so
you don't slip up by mistake.
 
On the subject of the machine, you need to automate the process of both
setting up your hidden service and of destroying it. Proactively change
servers every few months, in order to frustrate law enforcement attempts
to locate and seize your site. Your creation script should install
everything your site needs as well as all configuration files. Your
clean-up script needs to destroy all evidence, preferably with a tool
like srm.
 
Regarding time-related issues: Always select either UTC or a time zone
that doesn't match the box's location. You will also do this to the box
you use to interact with your hidden service every day. If you read the
whitepapers, you will probably note a recurring theme of clock
skew-related attacks, mostly directed at clients, in some of the older
papers. Tor won't even start if the clock skew is off by too much.
 
If you want to have some fun at the expense of business in the short
term, intentionally take your service offline periodically in order to
mess up attempts to match your downtime with public information. If
you're the kind of person with access to botnets, you could DDoS
(Distributed Denial of Service) some provider at the same time on the
off chance that someone might connect the dots. This counter-measure
will only work on researchers looking at public info, not nation state
actors with an ax to grind.
 
I've saved some of the hardest stuff for the last part of this section.
It's hard because you have to make choices and it's unclear which of
those choices are the best. It's a bit like a Choose Your Own Adventure
book. In that spirit, all I can do is lay out the possibilities in as
much of a Herodotus-like way as possible.
 
One thing you have to consider is whether you want to run your hidden
service as a relay or not. If it's a relay, you'll have extra cover
traffic from other innocent tor users. But if your relay goes down at
the same time as your hidden service, it will be far more likely to be
noticed. Federal criminal complaints make a big deal of seized hidden
services not being relays, but three relays were taken down at around
the same time as Operation Onymous, so that's not a guaranteed defense.
The choice is yours.
 
Remember when I said to take note of hosts that don't ban tor outright?
This is the part where you give back to the community in the form of tor
relays or bridges. [3] The feel-good aspects of this move are along the
same lines as drug barons who build schools and hospitals, but this is
more immediately self-serving. You're going buy several servers to set
up strictly as relays or bridges, then configure your hidden service box
to use only those relays or bridges to enter the tor network. Here's
where things start to get theoretical.
 
If an adversary is running a guard node discovery attack -- in which an
attacker is able to determine the node you're using to enter the tor
network -- against your service and you're using your own relays as
entry nodes, the damage they can do will be limited to DoS (Denial of
Service) if your relays are not linkable to your identity. However, if
you're entering the tor network with bridge nodes, an attacker will
probably say "WTF?" at first unless they determine they've found a
bridge node. Bridge nodes don't use nearly as much bandwidth as relays
because there is not a public list of them, so an intelligence agency
would have less traffic to sift through, which makes correlation easier.
On the other hand, using bridge nodes also allows you to run obfsproxy
[4] on both the bridges and your hidden service. obfsproxy allows you to
make tor traffic appear to be another type of traffic, which is a good
defense against non-Five Eyes entities. For example, your hosting
provider may decide to monitor for tor traffic for their own reasons.
Just make sure your relays/bridges aren't linkable to you or to each other.
 
One last thing about guard node discovery attacks: The Naval Research
Lab published a paper in July 2014 about the "Sniper Attack," [5] which
in short works like this: The attacker discovers your guard nodes, then
uses an amplified DoS trick to exhaust the memory on all of your nodes.
The attacker keeps doing this until your hidden service uses guard nodes
that they control. Then it's game over. If your hidden service's entry
nodes are all specified in your torrc file and they get DoSed, your
service will go offline. In this situation, if all of your relays are
down, you essentially have an early warning canary that you're being
targeted. In other words: This is the best possible time to book your
one-way ticket to your chosen non-extradition country. For those of you
with a background in writing exploits, this is similar in principle to
how stack smashing protection will render some exploits either unable to
function or will turn them into a DoS. Personally, I recommend an
ever-changing list of relays or bridges. Add a few new ones at a
pre-determined interval, and gradually let old ones go unpaid.
 
3. Operational Security
 
This section is critical, especially when things start to break down. If
everything else goes bad, following this section closely or not could be
the difference between freedom and imprisonment.
 
This is important enough to re-state: Transparently proxy your tor
computer. This is a good first line of defense, but it is far from the
only way to protect yourself.
 
Do not contaminate your regular identity with your Onion Land identity.
You're an aspiring drug kingpin. Go out and pay cash for another
computer. It doesn't have to be the best or most expensive, but it needs
to be able to run Linux. For additional safety, don't lord over your new
onion empire from your mother's basement, or any location normally
associated with you. Leave your phone behind when you head out to manage
your enterprise so you aren't tracked by cell towers. Last but not least
for this paragraph, don't talk about the same subjects across identities
and take counter-measures to alter your writing style.
 
Don't log any communications, ever. If you get busted and have logs of
conversations, the feds will use them to bust other people. Logs are for
undercover cops and informants, and have no legitimate use for someone
in your position. Keep it in your head or don't keep it at all.
 
At some point, your enterprise is going to have to take on employees.
Pulling a DPR move and demanding to see ID from high-volume sellers and
employees will just make most people think you're a fed, which will
leave your potential hiring pool full of dumbasses who haven't even
tried to think any of this out. It will also make it easier for the feds
to arrest your employees after they get done arresting you. If your
enterprise is criminal in nature -- whether you're selling illegal goods
and services or you're in a repressive country that likes to re-educate
and/or kill dissidents -- an excellent way of flushing out cops is to
force them to get their hands not just dirty, but filthy, as quickly as
possible. Don't give them time to get authorization to commit a crime
spree. If there's a significant amount of time between when they're
given crimes to commit and the commission of those crimes, you need to
assume you've got an undercover cop on your hands and disengage. If they
commit the crime(s) more or less instantly, you should be fine unless
you've got the next Master Splynter on your trail. [6]
 
Disinformation is critical to your continued freedom. Give barium meat
tests to your contacts liberally. [7] It doesn't matter if they realize
they're being tested. Make sure that if you're caught making small talk,
you inject false details about yourself and your life. You don't want to
be like Ernest Lehmitz, a German spy during World War II who sent
otherwise boring letters about himself containing hidden writing about
ship movements. He got caught because the non-secret portion of his
letters gave up various minor personal details the FBI correlated and
used to find him after intercepting just 12 letters. Spreading
disinformation about yourself takes time, but after a while the tapestry
of deceptions will practically weave itself.
 
Ensure that your communications and data are encrypted in transit and at
rest whenever applicable. This means PGP for e-mail and OTR for instant
messaging conversations. If you have to give data to someone, encrypt it
first. For the tor-only box you use for interacting with your hidden
service, full disk encryption is required. Make a password that's as
long and complex as you can remember ("chippy1337" is not an example of
a good password). Last but not least, when you're done using your
dedicated tor computer, boot into memtest86+. Memtest86+ is a tool for
checking RAM for errors, but in order to do that it has to write into
each address. Doing so essentially erases the contents of the RAM.
Turning your computer off isn't good enough. [8] If you're planning to
use TAILS, it will scrub the RAM for you automatically when you shut
down. Once your RAM is clean, remove the power cord and any batteries if
you're feeling extra paranoid. The chips will eventually lose any
information that is still stored in them, which includes your key. The
feds can do a pre-dawn raid if they want, but if you follow this step
and refuse to disclose your password, you'll make James Comey cry like a
small child.
 
Use fake info when signing up for hosting services. Obfuscate the money
trail as much as possible and supply fake billing info. I prefer
registering as criminals who are on the run, high government officials,
or people I dislike. If your box gets seized and your hosting company
coughs up the info, or if a hacking group steals your provider's
customer database (It happens more often than you'd think), your hosting
information needs to lead to a dead end. All signs in Operation Onymous
point to operators being IDed because they used real info to register
for hosting service and then their box got decloaked.
 
Speaking of money, you're going to have to figure out how to launder
your newfound assets, and we're not talking about using a couple bitcoin
laundering services and calling it a day. You also shouldn't go out and
buy a Tesla. Living beyond your means is a key red flag that triggers
financial and fraud investigations. Remember, money is just another
attack vector. Washing ill-gotten gains is a time-honored drug business
tradition and one that you would be a fool not to engage in. You can
only use your hard-won profits to send shitexpress.com packages to
people you don't like so many times.
 
Take-away: If you rely only on tor to protect yourself, you're going to
get owned and people like me are going to laugh at you. Remember that
someone out there is always watching, and know when to walk away. Do try
to stay safe while breaking the law. In the words of Sam Spade, "Success
to crime!"
 
 
 
Sources:
[1] https://lists.torproject.org/cgi-bin/mailman/listinfo
[2] https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy
[3] https://www.torproject.org/docs/bridges
[4] https://www.torproject.org/projects/obfsproxy.html.en
[5]
http://www.nrl.navy.mil/itd/chacs/biblio/sniper-attack-anonymously-deanonymizing-and-disabling-tor-network
[6] http://www.pcworld.com/article/158005/article.html
[7] https://en.wikipedia.org/w/index.php?title=Canary_trap&oldid=624932671
[8] https://freedom-to-tinker.com/blog/felten/new-research-result-cold-boot-attacks-disk-encryption/