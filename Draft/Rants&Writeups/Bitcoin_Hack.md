```
Hi.  Thanks for passing this along so it gets some attention.  I was worried if I posted this somewhere it would mostly go unnoticed.  Also, I'm trying to stay anonymous because I don't want to be accused of being the person who came up with this exploit or be blamed by any company for any damages.  It's an interesting technical story so I thought I would share it.
 
 
-------- story begins here ----------------
 
 
I returned 9 BTC to reddit user fitwear who recently claimed were stolen from their blockchain.info wallet.
 
I have evidence that some bitcoin address generation code in the wild is using private keys that can easily be discovered on a regular basis. This is either intentional or by mistake. Some wallets have been compromised by what is probably an innocent looking piece of code.  Furthermore, someone has been siphoning bitcoin on a regular basis since 2014 from them. Whether they discovered this by accident (like I did) or are the ones who installed the code themselves, I don't know.  It looks like either a clever exploit or a coding error. It could also be yet another piece of malware, however as I explain below, I feel this is less likely the case. In order to fully understand how this works and how I discovered it, please read on.
 
Some Background
---------------
 
I've been following bitcoin since I first heard of it in 2011. One of the things that fascinated me was the ability for someone to create private keys from just about anything using Sha256 (i.e. Sha256(password/phrase)).  This, of course, is NOT a recommended way of obtaining a private key since if YOU can think of the word/phrase, someone else can too and the likelihood of your bitcoins being stolen is quite high. The most secure private keys are generated randomly. The probability of someone else being able to generate the same sequence of 32 random bytes is so close to 0, it is highly improbable anyone ever will (given the expected lifespan of the universe).
 
If you peer into the blockchain, you will find that people have 'played' with the chain by sending small amounts of bitcoins to addresses corresponding to private keys generated using Sha256.  For example, Sha256 of each word in the entire /usr/dict/words file found on most UNIX systems has had a small amount sent to it.  There was a site called brainwallet.org that made it easy for you to convert a phrase into a private key + public address.  (The code is still available on GitHub but has since been removed from the Internet).  Try using phrases like "i find your lack of faith disturbing", "these aren't the droids you're looking for" or "satoshi nakamoto" as inputs to Sha256.  You'll find the addresses corresponding to those private keys have had small amounts sent to them (and transferred out).  It's quite obvious these were _meant_ to be found. It turns out there are a lot of these addresses. (Keep looking and you will easily find some.)  This is nothing new and has been known to the bitcoin community for a while.
 
I always had the idea in the back of my mind to try and find other non-trivial examples of 'discoverable' private keys.  That is, something beyond Sha256(word/phrase). So I decided to try and hunt for buried bitcoin treasure.  Perhaps I could find some bitcoin intentionally hidden by someone that hadn't yet been discovered?  In the first couple weeks of June 2017, I finally devoted some time to the task. I honestly didn't expect to find much but I was amazed at what I ended up discovering.  I began by writing a program to scan every block in the blockchain and record every public address that had ever been used.  (Note: I didn't only store addresses for which the balance was greather than zero, I stored ALL of them which is why I believe I ended up accidentally discovering what I did.)  There were only about 290 million at the time so this wasn't a big deal.
 
The Experiments
---------------
 
What follows is a description of my experiments and what led me to discover what I believe is either a scam or really bad coding error.
 
Experiment 1
------------
 
My first experiment was to see if anyone used a block hash as a private key. That would actually be a nifty way to 'compress' 32 bytes in your head.  You would only have to remember the block height (which is only maybe 6 digits) and the corresponding larger 32 byte number would be saved for all time in the chain itself!
 
Results: Success! I found 46 addresses that had some amount of bitcoin sent to them between 2009 and 2016.  As expected, these all had 0 balances either because the owner had taken them back or they were discovered by someone else.
 
Here are two examples. You can use blockchain.info to see these hex values are actually block hashes from early in the chain.  This happened on/off up until mid-2016.
 
1Buc1aRXCqdh6r7PRYWPAy3EtVFw5Ue5dk 000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd
1KLZnkqU94ZKpgtcWCRs1mhqtF23jTLMgr 000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485
 
Nothing really alarming so far.
 
Experiment 2
------------
 
Similar to my first experiment, I then searched for addresses that were generated from the merkle root used as a private key.  (BTW, I searched for both compressed/uncompressed keys, so each 32 bytes resulted in two address look-ups from my database).
 
Results: Yes! I found 6 addresses again up until mid-2016.  Even though every address I found had a 0 balance (again expected), I was having fun with my success!
 
Example:
 
13bkBdHRovsBkjM4BUsbcDNr9DCTDcpy9W 6c951c460a4cfe5483863adacafad59e5de7e55876a21857733ca94049d7d10c
 
Similar to merkle root and block hashes, transaction ids (hashes) also seem to have been used as private keys. Still nothing alarming to me thus far.
 
Experiment 3
------------
I wondered at this point if anyone might have used repeated Sha256 on words.  Why stop at just one iteration when you can easily do one million?  Also, it becomes less likely to be discovered the more iterations you do.  I found a bunch.  Here are a few:
 
Sha256('sender') x 2
 
18aMGf2AxQ3YXyNv9sKxiHYCXcBJeJv9d1 098f6d68ce86adb2d8ba672a06227f7d177baca3568092e4cda159acca5eb0c7
 
Sha256('receiver') x 2
1C3m5mFx6SjBCpw6qLqzM8izZArVYQ9B5u 6681b4b6aa44318e55a724d7135ff23d76eb75847802cd7d220ecaa8427b91d4
 
Sha256('hello') x 4
 
17UZ4iVkmNvKF9K2GWrGyMykX2iuAYbe1X 28b47e9b141279ea00333890e3e3f20652bbd7abc2b66c62c5824d4d6fe50ac9
 
Sha256('hello') x 65536
 
1Mi5mVANRNAetbJ21u2hzs28qCJC19VcXY 52fa8b1d9fbb264d53e966809ce550c3ab033248498da5ac0c5ab314ab45198e
 
Sha256('password') x 1975 (This one's my favorite, someone's birth year?)
 
13mcYPDDktHdjdq9LwchhU5AqkRB1FD6JE 6e8cdae20bef63d33cb6d5f1c6c9c954f3148bfc88ef0aa1b51fd8b12fa9b41c
 
People were obviously burying bitcoin in the chain. Whether they expected the coins to be taken or not, we'll never know.  But these methods were still highly 'discoverable' in my opinion.
 
Experiment 4
------------
 
My last experiment is the one that led me to believe someone was siphoning bitcoin from some service on a regular basis and has been since 2014.
 
Take a look at this private key:
 
    KyTxSACvHPPDWnuE9cVi86kDgs59UFyVwx2Y3LPpAs88TqEdCKvb
 
The public address is:
 
    13JNB8GtymAPaqAoxRZrN2EgmzZLCkbPsh
 
The raw bytes for the private key look like this:
 
    4300d94bef2ee84bd9d0781398fd96daf98e419e403adc41957fb679dfa1facd
 
Looks random enough. However, these bytes are actually sha256 of this public address!
 
    1LGUyTbp7nbqp8NQy2tkc3QEjy7CWwdAJj
 
I discovered this by performing Sha256 on all the public addresses I had collected from the setup of my experiments and then seeing if those addresses (from the generated private keys) were ever used.  Bingo!  Lots were coming up.  I searched a fraction of the chain and found dozens.  I also found these addresses had bitcoin sent to them very recently (within weeks/days of when I discovered them.)
 
I asked myself, "Why would someone do this?"
 
At first, I thought this was someone who thought they could get away with having to remember only one piece of information rather than two.  Maybe they have one favorite address/private key combo and derived another from that one?  I thought it was possible.  You could keep doing this in a chain and derive as many as you wanted and only ever have to remember the first one.  But I ruled this out for one simple reason; bitcoins transferred into those addresses were being transferred out within minutes or SECONDS. If someone generated these private keys for themselves, then why would the coins be almost immediately transferred out in every case I looked at?
 
Here are some more (complete list at end of this doc):
 
16FKGvEtu5KPMZqiTK4yjmsSZsJLyxz9fr from Sha256(1CRWfJdgVrfKLRS4G3vTMRhEQrCZZyHNMo)
1HwxL1vutUc42ikh3RBnM4v2dVRHPTrTve from Sha256(1FfmbHfnpaZjKFvyi1okTjJJusN455paPH)
1FNF3xfTE53LVLQMvH6qteVqrNzwn2g2H8 from Sha256(1H21ndKEuMqZbeMMCqrYArCdV8WeicGehB)
 
In every case I looked at, the coins were moved away within minutes or seconds.
 
It was much more likely that a bot was waiting for those coins to show up. Also, transactions are STILL happening to this day on those addresses!  But how can that bot know in advance that address was about to receive bitcoins?
 
A Scam or a mistake?
--------------------
 
It is at this point I formed a theory on what was really happening. It is likely that someone installed malicious code into the backend system of a mining pool, an exchange, or possibly wallet generation code. They are using public information so that they can discover the private keys easily and steal the coins on the side.
 
But why would they use Sha256(public_address)?  Why not do Sha256(public_address + some super hard to guess random sequence) or just use a hard-coded address?
 
Well, I have a theory on that too.  It can't be hard-coded or it would look suspicious in a source code repository.  It's likely the code was introduced by someone who works (or worked) for some company connected to bitcoin (exchange/mining pool/gambling site/wallet).  Code submitted by developers into source control systems usually goes through a code review process. It would be much easier to hide an innocent looking Sha256 operation inside the millions of lines of code that make up the backend.  Sha256 is used all over the place in bitcoin and it wouldn't look suspicious.  The function would be readily available.  However, if code were to be submitted that performed Sha256(address + "secret_password1234xyz"), that would look VERY suspicious.  My guess is someone has slipped in a routine that LOOKS harmless but is actually diverting bitcoin to their awaiting bot ready to gobble them up.
 
It's actually quite clever.  No one can know the destination address in advance.  You would have to keep performing Sha256 on all public addresses ever used to catch that one in a million transaction.  Someone would be able to capture those coins by simply watching for a transaction into an address that corresponds to a private key generated from Sha256 of one of the existing public addresses.  Keeping such a database is trivial and lookups are quick.
 
To be fair, I suppose this could be a coding error.  Anything is possible with a buffer overflow. I would love to see the code if this is ever found.
 
Transactions were STILL happening right up until a couple weeks before I made this discovery!  So I wrote a bot to try and 'catch' a transaction.
 
Mind Blown
----------
 
Within the FIRST 48 HOURS of my bot going live, on Jun 19, a whopping 9.5 BTC was transferred into an address for which I had the private key.  This was approximately worth $23,000 USD at the time.  I was shocked.
 
This is the address: 12fcWddtXyxrnxUn6UdmqCbSaVsaYKvHQp
 
The private key is: KzfWTS3FvYWnSnWhncr6CwwfPmuHr1UFqgq6sFkGHf1zc49NirkC
 
whose raw bytes are derived from Sha256 of:
 
16SH69WgJCXYXWV58sxjTxonhgBh5HCZTt (which appears to be some random address previously used in the chain)
 
BUT... I had failed to test my program sufficiently and it failed to submit the transaction!  The 9.5 BTC was sitting there for almost 15 minutes before being swept away by someone else.  I honestly didn't think the first amount to cross my radar would be so high.  The other samples I found from past transactions were for tiny amounts.  It is quite possible that whoever moved them later out of the poisoned address actually owned them.  Maybe someone else's sweeper bot only takes small amounts most of the time to avoid attention?
 
At this point, I was pretty confident I was on to something not yet discovered by anyone else.  I _could_ have taken those 9.5 BTC and if this was known to others. Also, if you look into the history of that account, 12 BTC was transferred into it (and out right away) only one month earlier.  No one has claimed any theft (to my knowledge) involving that address.
 
I fixed my program (actually tested it properly this time) and let it run again.  My program detected more transactions (2 within the next 48 hours). I coded my bot to ignore anything less than .1 BTC so I didn't move them.  I didn't want to tip off the anyone that I knew what they were doing (if that was indeed the case).
 
Another 3-4 days passed and the next hit my bot detected was for roughly .03 BTC (~$95USD).  For some reason, this was not transferred out immediately like the rest.  By this time it was July 4th weekend.  I let this one sit too and it took a full 7 days before it was moved (not by me).  It may have been the legitimate owner or a bot.  We'll never know.
 
The destination address was: 1LUqqMzaigWJTzaP79oxsD6zKGifokrh7p
The private key raw bytes were: c193edeeb4e7fb5c3e01c3aebd2ec5ac13f349a5a78ca4112ab6a4cbf8e35404
 
The plot thickens...
--------------------
 
I didn't realize it at the time but that last transfer was into an address for a private key not generated from another public address like the first one.  Instead, this address was generated from a transaction id!  I had forgotten that I seeded my database with private keys generated with transaction ids as part of one of my earlier experiments.  I didn't label them so I didn't know which were from Sha256(pub address) and which were from transaction ids.  I found some hits at the time but when I checked the balances for those accounts, they were all zero and I didn't think anything of it.  But now my database was detecting ongoing transfers into THOSE addresses (transacton id based) too!
 
Okay, someone was possibly using information from the blockchain itself to ensure private keys were discoverable for the addresses they were funelling bitcoin into.  The interesting thing is I found a link between the 12fcWddtXyxrnxUn6UdmqCbSaVsaYKvHQp address (via sha of a public address) AND the 1LUqqMzaigWJTzaP79oxsD6zKGifokrh7p transfer (via the tx id as a key).  In the history of both of these addresses, you can see the BTC eventually ended up into this address: 1JCuJXsP6PaVrGBk3uv7DecRC27GGkwFwE
 
Also, the transaction id was for the previous transaction to the one that put the BTC in the toxic (discoverable) address in the first place.  Now it became even more clear.  The malicious code sometimes used a recent transaction id as the private key for the doomed destination address. Follow the .03 BTC back and you will see what I mean, you eventually get to the txid = private key for that discoverable address.
 
The 1JCuJXsP6PaVrGBk3uv7DecRC27GGkwFwE address is ONE of the collection addresses.  I have reason to believe there have been many over the years.  This one only goes back to approximately March 2017.  You can see in the history of this one address when they consolidated their ill-gotten gains into one transaction back to themselves.
 
I let my bot run longer. The next hit I got was for block hashes that were used as private keys (see Experiment #1).  Sure enough, this address also had links to the 1JCuJXsP6PaVrGBk3uv7DecRC27GGkwFwE collection address!
 
And remember my merkle root experiment? I believe those were also part of this.  However, I have not linked those to this one particular collection address yet.  In the end, I found a total of four different 'discoverable' private key methods being used.
 
I made sure my database was filled with every block hash, merkle root, transaction id and Sha256(public address) for private keys and let my bot run.  Transactions for all four types were showing up, again for tiny amounts which I ignored. By this time, I was watching BTC getting taken in small amounts regularly. Sometimes, I saw as many as 6 transactions fly by in one day.
 
How fitwear lost (and got back) 9 BTC
-------------------------------------
 
On Nov 12, my program saw 9 BTC transferred into an address that my database had the private key for. I had searched for that address too to see if anyone was claiming ownership but I didn't see anything.  I decided to send a small amount to a well known puzzle address to give the transaction some public scrutiny in an anonymous way (1FLAMEN6, I'm still trying to solve this BTW).  Shortly after, I became aware of fitwear's reddit post claiming theft after someone noticed the prize amount had been topped off and linked the two events together.
 
I contacted fitwear privately and returned their coins minus the small amount I sent to the puzzle address.  Blockchain.info's original response to his support ticket, was that his system must have been compromised.  However, if you read his post, he took every precaution including typing in the key for his paper wallet instead of copy/paste and using 2FA.  
 
In his case, in Aug 2017, he imported the private key for his 1Ca15MELG5DzYpUgeXkkJ2Lt7iMa17SwAo paper wallet address into blockchain.info and submitted a test transaction.  At some point between then and Nov 12, the compromised 15ZwrzrRj9x4XpnocEGbLuPakzsY2S4Mit got into his online wallet as an 'imported' address.
 
Together, we contacted blockchain.info and I relayed the information I just outlined above to them.  Their security team investigated but found no evidence it was their system that was at fault. I suppose it's possible his system was somehow compromised back in August and managed to import a key into blockchain.info without him knowing it.  Or someone else logged into his account, imported the key, then waited.  I feel the malware/login explanations are much less likely because it looks like code attempting to 'hide in plain sight' to me.  You wouldn't need to use Sha256(address) or block hash or txid or merkleroot if you were malware or an unauthorized login.  You would at least salt or obscure the key with some bit of knowledge only you know so that only you could derive the private key (as mentioned earlier).  The fact that information from the blockchain itself is being used indicates it may be some transaction processing logic.  Also, fitwear took extreme precautions (you can read his reddit post for details).  The origin of these poison destination addresses remains a mystery.
 
If it's the case that some wallet generation code is doing this, then it may be the case that we're seeing 'change' transactions.  When you create a wallet, there maybe 20 addresses generated.  They are all supposed to be random keys.  If this rogue code creates one of them in this manner (based on the public address string of an earlier one), then at some point, your 'change' will get put back into it as the wallet 'round-robins' through the list.
 
fitwear's 15Z address sat unused until Nov 12 when fitwear transferred his 9 BTC into it using blockchain.info.
 
To see the connection, take a look at this:
 
echo -n "1Ca15MELG5DzYpUgeXkkJ2Lt7iMa17SwAo" | sha256sum
9e027d0086bdb83372f6040765442bbedd35b96e1c861acce5e22e1c4987cd60
 
That hex number is the private key for 15ZwrzrRj9x4XpnocEGbLuPakzsY2S4Mit !!!
 
fitwear insists he did not import the key for that address.  Did Blockchain.info generate it or was it added by mallicious browser code? We may never know.
 
See below for the complete list of other Sha256 based addresses that suffer from the same issue. I believe this is happening for others.  It's likely, that the small amounts usually taken are going unnoticed by the owners.
 
What does this mean for bitcoin?  Nothing probably. I believe the bitcoin network itself to be secure.  However, as long as humans are involved in the services that surround it (mining pools, exchanges, online/mobile wallets) there is always a chance for fraud or error.  The bitcoin network itself may be 'trustless', but anything humans touch around its peripheries is certainly not.  And you need to use those services to get in/out of the network.  So even with bitcoin, it still boils down to trust.
 
To be fair to blockchain.info, only Sha256(public address) (one in particular) was found to be present in one of their wallets. The other 3 methods I described above could be completely unrelated.  And they could all possibly be a (really weird) software bug.
 
Here are 100+ addresses that received bitcoins whose private keys are the bytes resulting from Sha256 of another public address.  Most of these came from a scan I did of old transactions, not while my bot was running.  Blockchain.info told me they do not appear to have been generated by their system.
 
Also, the list of addresses I"m providing are only the subset that have already had some BTC transacted through them.  There are likely hundreds more lying dormant inside people's wallets that have not been used yet.
 
Here is the list:
 
1G2rM4DVncEPJZwz1ubkX6hMzg5dQYxw7b Sha256(1PoHkMExsXDDBxpAwWhzkrM8fabmcPt6f4)
1Kap8hRf8G71kmnE9WKSBp5cJehvTEMVvD Sha256(1LdgEzW8WhkvBxDBQHdvNtbbvdVYbBB2F1)
1LsFFH9yPMgzSzar23Z1XM2ETHyVDGoqd5 Sha256(1FDWY63R3M87KkW2CBWrdDa4h8cZCiov9p)
13eYNM5EpdJS7EeuDefQZmqaokw21re4Ci Sha256(1E7kRki9kJUMYGaNjpvP7FvCmTcQSih7ii)
1CcSiLzGxXopBeXpoNSchagheK9XR61Daz Sha256(191XapdsjZJjReJUbQiWAH3ZVyLcxtcc1Y)
1J9Gtk5i6xHM5XZxQsBn9qdpogznNDhqQD Sha256(16fawJbgd3hgn1vbCb66o8Hx4rn8fWzFfG)
1A17F9NjArUGhkkiATyq4p8hVVEh2GrVah Sha256(1Je3tz5caVsqyjmGgGQV1D59qsCcQYFxAW)
1GGFXUL1GoHcEfVmmQ97getLvnv6eF98Uu Sha256(1DCfq8siEF698EngecE69GxaCqDmQ2dqvq)
14XxBoGgaJd1RcV3TP8M4qeKKFL9yUcef1 Sha256(1Frj1ADstynCYGethjKhDpgjFoKGFsm5w5)
18VZKyyjNR8pZCsdshgto2F1XWCznxs86P Sha256(1FEwM9bq3BnmPLWw5vn162aBKjoYYBfyyi)
12fcWddtXyxrnxUn6UdmqCbSaVsaYKvHQp Sha256(16SH69WgJCXYXWV58sxjTxonhgBh5HCZTt)
19T6HNnmMqEcnSZBVb1BNA6PrAKd5P2qZg Sha256(1Frj1ADstynCYGethjKhDpgjFoKGFsm5w5)
1MWBsFxWJrNtK2cN2Vt7j3a9r5ubfn41nx Sha256(16era4SgYEcbZD1pu6oCBXGXjK2wSrePe8)
1Ns55SngRhshA8kEnyuQ9ELZZPN7ubYfQJ Sha256(1NiNja1bUmhSoTXozBRBEtR8LeF9TGbZBN)
13CnacdjvuuTJkCWrZf33yMrQh5aVX5B14 Sha256(1KPDwnrzJAfD2V4oiPf55WBTAi6UJDvMjN)
1MG1dTqtWVNqq3Qht88Jrie7SXp2ZVkQit Sha256(1UvM3rBJ8Sa1anQ8Du1mj5QZapFmWF7vH)
1DBXjdbMWXmgt81E1W7AYRANVPiq12LsGd Sha256(1Poi5SE42WVR2GKPrwp9U3wYqEBLN6ZV1c)
1GUgTVeSFd2L5zQvpYdQNhPBJPi8cN3i4u Sha256(1EjWVhiTyCdpTa29JJxAVLq27wP4qbtTVY)
1JQ2shEPzkd3ZL3ZQx7gmmxFLvyhSg14cb Sha256(1KEkEmadjTYHCiqhSfourDXavUxaiwoX7f)
125PcPD4QXzgDwNPForSFji8PPZVDr2xkp Sha256(1GRdTKgSq5sY3B4PiALPjKTXSXPXs6Ak7X)
1kN83e7WRtsXD7nHn51fwdEAi51qk5dEe Sha256(1JcsBzKio1curbu9AtxTySxddvT4MKT3Da)
1L5pzdXL4hhtMHNxFXHjjdhhSidY9kJVRk Sha256(1V8tWZw4J3G5kBgafGsfoVSNQEgkxDmeA)
1cQH5XCsezkKt9zpwjHizz8YJZudDSwri Sha256(1AYKSUqCtDX1E34q4YoFnjwWSj41huWgGG)
1DHWP6UjSKBBUR8WzTviWAGNgLfDc6V6iL Sha256(1MbzspFCdXjtqAUx3t6A11vzrk5c847mvE)
1EqSvLnMhbRoqZkYBPapYmUjMS9954wZNR Sha256(1XAeTJCaYJgoBDwqC1rhPhu3oXiKuMs9C)
1MJKz1M7dEQCHPdV5zrLSQPa4BGFAuNJyP Sha256(1BxzenHnSuKwqANALE5THeTCSRZkv3ReRP)
18VZG5Dr8bYJWadHUgh7kC4RPS1VsvH4Ks Sha256(1qA59Na3WysruJbCPoomryDRCtJ4f4aLu)
1CoyRECWJ4LHNiZAgAz9719chFkrDJuNMC Sha256(19o4Yjrd74qnZ3z87C67BShbbF4fSNHy8W)
1ERKXYeaCy97KPdJTRbWjJDVzMbStJYqCm Sha256(1DMwZeQJXfWToRRHr5uRiKeucwDWkWLvkm)
1mbcQaPzsaBoaYP4V6uwCA74BRPhroK3r Sha256(1KzSULbG3fRVjWrpVNLpoB6J62xYL42AdN)
1gHad7cKWDcVKFeKcLRW4FhFAyw2R7FQZ Sha256(1LFCEek8FobJRXb5YrzWJ6M2y8Tx2Xg3NB)
1DvtF6X5b9cBrMZa4Yff9tARCLqP5ZyB47 Sha256(14nuZCWe76kWigUKAjFxyJLFHQyLTsKXYk)
1LzGrd5QX1rG5fk7143ps9isUTEwGyzRJE Sha256(19cMyj9KqVq78yZe32CNhgpyuGLMwM9X8S)
153jMRXn251WyxT9nmJW2XDsFUJ648jyY5 Sha256(1PF2gQPPAwQDfTrSuNX6t8J381D7s3bGFu)
1EFBsAdysTf81k72v9Zqsj3NMuo6KoWD2r Sha256(1BBBvd9G5YThYVVMSGSxJzQvQiQm3WxJC2)
14mRxKmeEw9DCBbpR596FYmfZVdBD8MJxh Sha256(1PLpQDyqDUcpK6fWpRhkkFVBw4tSK4sHkS)
1Hg9pi75XWAT9pB3faXQFKKZbh98cbM5m Sha256(1JoshVWQDa7DzXqN3wQ9dbig5WEfaAzHcM)
1PcExYX3mUJ1rwa4aTLNJUpxqRLU8MxPXm Sha256(1LTZ9kaxRHBZH43eSmZ2KoGLHHUBV3P2S5)
1J9SzdYMZFsLqunQfPAswzogLNBitbREMD Sha256(1A7grBEjor6Sapj8KRbEGj2UrbnNt1Usxo)
1FNF3xfTE53LVLQMvH6qteVqrNzwn2g2H8 Sha256(1H21ndKEuMqZbeMMCqrYArCdV8WeicGehB)
1Q2a1ytfujskCEoXBsjVi1FqKWHegfFKwD Sha256(1LzGrd5QX1rG5fk7143ps9isUTEwGyzRJE)
1PfcpvjYUGu4yvpkEHmAKgDXtsLfSNyzvV Sha256(153jMRXn251WyxT9nmJW2XDsFUJ648jyY5)
1M2uEGihcwUPiRGETE7vF8kUiS2Z4rtV2Q Sha256(1HqQBiqgFK6ChJ2Vq7kbWRCbc73cjyNXv5)
1Kka5bgXvpHTNDsPmhLPHae2qcK9mLS2qS Sha256(1E3D7NabEX971uV2gXT47rWQwPm3zbmvd8)
17hMEK4i8Nsi56huBU4i9N4Gjiw5G6X5iG Sha256(1Nk6a8ZfN86gaHJifcF8iGahx4scCKkwF5)
1DT4Q4ocUFgekXvBqBM6kFmvQYB6Y4PnHo Sha256(19aNbfFfZEWwstuy97C1GsHHELNCxZSEYV)
1CSMVivJfFynvbZRrLFHVGnehpXLUjdGRc Sha256(1p4gsrzTc3mFAgJKYqMzhm6UsJzhgy1KX)
17SaWquajZZBRF5qz6HuXMRt6gvnrDyoqE Sha256(1C1KjGATUXP6L6nnGTAh4LQcnSyLt13XyB)
16eePivj1nTVvLpBGkmFoeGxNyMU7NLbtW Sha256(1K79KaFs4D6wqz1wjP1QoYiY18fw8N3bZo)
1PF2gQPPAwQDfTrSuNX6t8J381D7s3bGFu Sha256(1J9Gtk5i6xHM5XZxQsBn9qdpogznNDhqQD)
1GSkK6KBVSycEU57iK6fRvSXYJ4dgkkuNt Sha256(1JZwnSQz64N3F9D3E24oS4oGhSxMWDsXYM)
12eGusvkCcJb2GWqFvvE1BLDJ8pVX49fQv Sha256(197HxXUSehthdqXM6aEnA1ScDSCR7tQmP3)
134Kia3XhZV6oXE4EUvjc1ES8S8CY7NioU Sha256(1PVn2gxgYB8EcjkpJshJHfDoBoG8BntZWM)
1HMGSkDB9ZhRoUbSEEG6xR7rs9iPT2Ns5B Sha256(1E4yLggKcgHcpSKX336stXWgheNU2serVz)
13qsbkaJM7TkA5F2dsvHeGVQ7kCo74eGxh Sha256(1FAv42GaDuQixSzEzSbx6aP1Kf4WVWpQUY)
1Jsz6mahqVMJn2ayWzN6TfeWTti9tqfbSM Sha256(18AsiEQoLLKaF4Co1z4rxHyzJu9oqTVbFE)
1BwjscJC3P47uW5GXR7tjeHkdXQk6CuAFb Sha256(1JuP7JXhHabGLVAqp9TJj5N171qLVHrcVq)
17kYPYbELyVfMSYihD4YETJSZq5yCs3diM Sha256(1HzJPqLEpbeXiYhyoA8M8cuuds3FEAnw3B)
1C9HtVz7H8NArfV613wQNHs4PrK2oLZEYh Sha256(1EGeEk4YUrXyDL4zNXpWdqJopoVxs2vExJ)
16bEBNuc7JQ4QzyoFAkmxdVvW4wJqicjVN Sha256(12GvGqEQuQTW4Rr8dZ1o397KAYCMGWPYkq)
141V8fK9Kuofit8AXh9SLV9N9bLTfftETA Sha256(15nXjzf8EXy8Lji3czM1HAVw14mEKoEiTw)
19cMyj9KqVq78yZe32CNhgpyuGLMwM9X8S Sha256(17FaMY613bKfwhrdTv5PHnucSGTJBcw3k5)
1CRq6nj3a7vXdJJN2YSWdW6fVwydr6kqWs Sha256(1J1ZPHbbEwgcwniH3F7AgBeFZxQXJoKCGf)
1BVNt39u32LLkxMvBeBHXXNaTJqWe1Xcu5 Sha256(17iLALAyra1W5KSUjjkGN5LeUsWdeoQQx3)
1Mpw88XWQzLTZnq1eNs5SegZYGJu5Epky8 Sha256(1LeuaozTUT5UJX6DD4Q1VJsHh6aHpZ3YRU)
1LkwU9xbVroLkH9EvxDfmMnsCikQzaUv9S Sha256(16bEpxSc1FDyQDXR7ZYKbyyDDxzyaaCnNS)
1D97u8Pet8YmNwKaCPUXLyi4zk1HnLF5RQ Sha256(137XrofaWZhaZW2uB7eDsPjcwCNMTXVLot)
1KyUNmmJu3JjauVEZQUYLUEBg48GXXS1ii Sha256(17S3XjtEFXQoGdXnUjJJtGB1D7PTa9SsLZ)
1HwxL1vutUc42ikh3RBnM4v2dVRHPTrTve Sha256(1FfmbHfnpaZjKFvyi1okTjJJusN455paPH)
137XrofaWZhaZW2uB7eDsPjcwCNMTXVLot Sha256(1JvaK7jYWFNbDsJZLarXnq1iVicFW4UBv5)
1FXi6kEJjnZUBqpwjVJKPsgVHKag86k6qq Sha256(1FEYXtchFFJft6myWc6PyxLCzgdd8EHVUK)
1Gj2uRnxDztM7dTDQEUQGfJg4z5RtAhECh Sha256(1ESkNMa9Z37of4QdJmncvibrXxZ7suPjYm)
1JhWnRjRm7AhbvSBtEifcFL8DkEKQiWRZw Sha256(13Q8rTtdGUUt8Q8ywcEffj4oiNrY6ui3cu)
131XQfvE7E1NzdRQnE8XFmtkxWVRXTsb9q Sha256(1FLeb3zCVG63NYAMBiUoqKYgW1tUwgMMfF)
167dyxowdWwBdofck3WuAwvUpVfn2ewx8Q Sha256(1FFAdm2BWoCfTkTwFLJ4o3b5xG7cuRxbWb)
1CVunYyUpeCFcGAYdHrDNrXcQFBVU8gyo9 Sha256(1BEYFim8uoJ7FAZG6m1E1hqLwKjfVwnWU1)
14XAGCAeUxieSzvGK3TX915PJLvX54n2Pd Sha256(17XQfW1R66aRBNYyJMwzn7zLf3D6sZgda3)
1M5jhEDKQCYbMCXHgcRUmaxwqYmcbrEfGD Sha256(1AixDffKCd1cV1tz1sp8fwJQDEAYCWzQcR)
1HPnYqbMvV4bGRcpSP28mMyekhjKiudcFY Sha256(1C91NNyzXE1dBC4dDKjx6y5VnhihifrpCY)
15XWgB1biKGd1JyuYecobfFtfBcVt6Jnok Sha256(1268xJ8iYUdRxK2vArkyoa5es6bR99hjhR)
1NHvPBaxKFuDec27mWcyCf7szUUvNnfimK Sha256(1LdgEzW8WhkvBxDBQHdvNtbbvdVYbBB2F1)
1AoocdeZC64PaQ15Gbv1kXyYYnN8FWXAST Sha256(1Et9zapAxsBLJ3bvY7LDTuHif5cH7mZiBE)
1NWCqz8nr8ZRZt1zEKidyWcZDyNtK3THps Sha256(17Xok12pBFkXxNcE8J4gTSm3YKkatyX4ad)
1Lv6T9RegiNHpES1DHu6AasDcUqp2SeqLb Sha256(1LDqitspsYaiLH6AMW5EzJYuZG5vTGzRNg)
16FKGvEtu5KPMZqiTK4yjmsSZsJLyxz9fr Sha256(1CRWfJdgVrfKLRS4G3vTMRhEQrCZZyHNMo)
14JpZ9Bogo4p83xt6cKS1Fh1rLSFRat8PN Sha256(1FBxoyGYaC9GEKLokfyrHUbZyoZmmm1ptJ)
1BEYFim8uoJ7FAZG6m1E1hqLwKjfVwnWU1 Sha256(1PfcpvjYUGu4yvpkEHmAKgDXtsLfSNyzvV)
1P9ZZGDG1npYd4d7jiCfPya6LQGkF5sFm7 Sha256(1LFGKkDZ21FZVsBh1A1S5Xr6aXuV3x9N4k)
1JvaK7jYWFNbDsJZLarXnq1iVicFW4UBv5 Sha256(1LdkWzq9DxopPkY1hCmQ3DezenP5PQLNC3)
15RjQKt6D4HBn87QqgbyvhKFNDDjXncp8Y Sha256(1PhmMsdwamJA6soKw5mNMXxzGomHEHWY5P)
1G7B5eVnAQgeuGrKxcRnrmEqPLsjRkgnVF Sha256(1D97u8Pet8YmNwKaCPUXLyi4zk1HnLF5RQ)
192qwAD31JB9jHiAwaTDkd6teb2hLAkY3b Sha256(1PhqA75qNM23aH9zV3uWvUhDbdwcab6q5L)
13mbvCyxCYvATNzranCkQdpCT19VGpMFZa Sha256(1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV)
1HJx3CqdaHAX6ZYRBHDvM5skg2Vh7GeZBD Sha256(1KrutzZZ7rth6D9wasfGz2oy9R6k1RCL9n)
1HBsFJ9VngvMjaKZjbFhNRaegkjF9NBEe Sha256(1CVunYyUpeCFcGAYdHrDNrXcQFBVU8gyo9)
1KiGdZ9TUeWyJ3DyHj7LQLZgjvMHd6j2DZ Sha256(18SV4DVmytRDYB5JBAFkewUbVAp6FRpi5c)
13FzEhD3WpX682G7b446NFZV6TXHH7BaQv Sha256(1E1rSGgugyNYF3TTr12pedv4UHoWxv5CeD)
1LVRWmpfKKcRZcKvi5ZGWGx5wU1HCNEdZZ Sha256(1CVPe9A5xFoQBEYhFP46nRrzf9wCS4KLFm)
1HhNZhMm4YFPSFvUXE6wLYPx63BF7MRJCJ Sha256(145Sph2eiNGp5WVAkdJKg9Z2PMhTGSS9iT)
1G6qfGz7eVDBGDJEy6Jw6Gkg8zaoWku8W5 Sha256(18EF7uwoJnKx7YAg72DUv4Xqbyd4a32P9f)
1MNhKuKbpPjELGJA5BRrJ4qw8RajGESLz6 Sha256(15WLziyvhPu1qVKkQ62ooEnCEu8vpyuTR5)
18XAotZvJNoaDKY7dkfNHuTrAzguazetHE Sha256(15SP99eiBZ43SMuzzCc9AaccuTxF5AQaat)
1HamTvNJfggDioTbPgnC2ujQpCj4BEJqu Sha256(14nuZCWe76kWigUKAjFxyJLFHQyLTsKXYk)
17iqGkzW5Y7miJjd5B2gP5Eztx8kcCDwRM Sha256(1MB3L1eTnHo1nQSN7Lmgepb7iipWqFjhYX)
15M7QfReFDY2SZssyBALDQTFVV1VDdVBLA Sha256(16bjY7SynPYKrTQULjHy8on3WENxCmK4ix)
1LgwKwv9kt8BwVvn6bVWj8KcqpP9JSP1Mh Sha256(1Q81rAHbNebKiNH7HD9Mh2xtH6jgzbAxoF)
1pmZwNDZjpuAqW3LjYYQCEjbQYBtSxzWc Sha256(13PctMqzyBKi5CpZnbastHQURrSRrow4yj)
1qA59Na3WysruJbCPoomryDRCtJ4f4aLu Sha256(1HBsFJ9VngvMjaKZjbFhNRaegkjF9NBEe)
19QBydCuMiY7aRTbkP2tb3KQJUWkTrr5Xi Sha256(1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T)
11EuerTwe9rxtT3T56ykX5K7J3AksPzU3 Sha256(14PnZgX8ZDABJZ8RnatkK7DQzdpkwRRPX2)
13JNB8GtymAPaqAoxRZrN2EgmzZLCkbPsh Sha256(1LGUyTbp7nbqp8NQy2tkc3QEjy7CWwdAJj)
1Ads6ZWgRbjSCZ37FUqcmk82gvup1gQurB Sha256(1NbBTJQ5azGEA1yhGnLh39fE8YoEbePpCm)
1LWU4SbnqnfctAMbtivp2L98i8hSSCm7u7 Sha256(1MVqDAJo8kbqKfTJWnbuzvfmiUXXBAmX3y)
12B1bUocw8rQefDcYNdckfSLJ6BsUwhRjT Sha256(1Pjg628vjMLBvADrPHsthtzKiryM2y46DG)
12GZz1D1kdX3Fj7M87RFvqubam8iGrK77R Sha256(1Lu49ZKmGoYmW1ji3SEqCGVyYfEw7occ86)
13wY5CtwQhd7LYprEpFpkt1g9R7ErMkAwT Sha256(1NPSWKXdnHa17NWTU3J6nVkyogZjmAh7N6)
1Kc324Y6UUMffeYdtuXgzVC28Kx3U8cqQk Sha256(1HAQB99WfrV2ttRjttUPMzRi4R1uC2ftMy)
1Gwz14Cty45h3hZ4nCEno6jSdxtQn5bc7h Sha256(1PDgY5PkpBNCZVWKKAq3cbGyqvwwN91z4g)
1L2a5n9ar7e2v3Wz6NDFnxisigvR6urGaY Sha256(1KxUVU9DKfdaTLMnXBLS5BZRf56cFnRosk)
1KwUfu3gGk7n8Wz969tAztvvM4Mp4ZY57s Sha256(12XuaKzEheWbFJBno9QiV6kPCWrnWpUYTK)
13JNB8GtymAPaqAoxRZrN2EgmzZLCkbPsh Sha256(1LGUyTbp7nbqp8NQy2tkc3QEjy7CWwdAJj)
12fcWddtXyxrnxUn6UdmqCbSaVsaYKvHQp Sha256(16SH69WgJCXYXWV58sxjTxonhgBh5HCZTt)
1MkaTR3642ofrstePom5bbwGHbuQJmrnGD Sha256(1BynBc2YUAoNcvZLWi24URzMvsk7CUe2rc)
114LdauSAu2FTaR2ChPsPTRRhjYD9PZzn2 Sha256(144BV4Y7tgnetk5tDKAYTGS4mjprA75zJz)
1NzWscae8v3sKmTVJYwq8yhkizK8hUS5qP Sha256(1ENCBKFsqxJVCqR2TS1WfDV3rDi6zA8J6Y)
1FjEL7TBazaJN7WyND4uwq9wiaWDzfizkP Sha256(1PeCGFsJgqz8CcjGugGq5bPBiRDXUZHLUH)
1FP8j4zUPoJkpKwYpd8zYGHVaKygRHzx3d Sha256(1ERdvKTCxP1gZvdNndLKtYotW7qpR3xhuQ)
16nXouTPm5gVedr4Betb8KRWLSBtmXGUbD Sha256(16oTV1jZPJ5wm3QLhN96xVF7DchihmpL1k)
15ZwrzrRj9x4XpnocEGbLuPakzsY2S4Mit Sha256(1Ca15MELG5DzYpUgeXkkJ2Lt7iMa17SwAo)
 
My bot moved coins from the last two addresses only.  (No one has claimed ownership from 16nX).  All other transfers were the result of other people who either figured this out or are the ones who planted the bad addresses themselves (since 2014).
 
And these are some recent examples of private keys that are based on other information from the blockchain itself (as stated, may be completely unrelated but still happening on a regular basis).
 
1LUqqMzaigWJTzaP79oxsD6zKGifokrh7p c193edeeb4e7fb5c3e01c3aebd2ec5ac13f349a5a78ca4112ab6a4cbf8e35404 txid
1FQ9AneLGfhFf9JT5m5sg5FaYFeJrGmJhS 00000000000000000045fa3492aee311171af6da7d05a76c6eaadab572dc1db9 Block Hash
1DhcPvYWBGwPFEsAJhXgdKtXX7FFGGeFVS 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048 Block Hash
198MRUHD2cvgUTBKcnroqmoTSs4b8xyLH9 7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff Markel Root
19FHVnoNYTmFAdC2VC7Az8TbCgrSWSP1ip 000000000000000000db717b4c076da2d1b9ff8ddbc94132e3a8d008a0fb62b9 Block Hash
1Lr2yEny7HYJkXdFgJ2D8zHyNH1uHMi4w4 2bedfd92a6136566bb858b2f0d223744a41a987c468356d069acc86f45bf68ac txid
1QBbjKxRk1jP36WYpFkJjgzhvVSDBMWjy2 f1599a1ced833d95a54aa38a1a64113d5f0a4db3cb613ef761180cab57155699 txid
1BFYNokepXjbb9Han2AGfSTNKNNU9vgAAn 533da7e41bd99550f63f152ef1e613f1a78e3bed12788664d536c6ec42b5e0aa txid
1MJtsgDNrrFWS3qxtrPr6BnQUdp1qPjyEm 216fb568589629b115b0ed8fc41fdf3219d9ab804c6ce5e53fbc581a88427c3f txid
14syDBvpGXS6PtWytkDJF2QACvSggEZ277 a7f4def1c7ff07d17b5dd58fc92f18ee2dbee6dc7654fd30a8653bd9d848f0a0 txid
1QBbjKxRk1jP36WYpFkJjgzhvVSDBMWjy2 f1599a1ced833d95a54aa38a1a64113d5f0a4db3cb613ef761180cab57155699 txid
1BkHAUcfrZLRLyXHiBn6XRoppPqSzuf8hE 805cd74ca322633372b9bfb857f3be41db0b8de43a3c44353b238c0acff9d523 txid
1CNgVFjAwHT7kc6uw7DGk42CXf1WbX4JQm 53d348ca871dc1205e778f4d8e66cfdadbd105782dba6688e9a0b4bdee4763e4 txid
1HjDAJiuJ8dda919xwKBqphhEwBVGfzMGt 0aad1b00a5227d9b03d33329a5a11af75c75c878a064c69b276063cbea677514 txid
1PDnrPSCw9eWTtJss4DhYoLTk4WUmZQdBi f87b08218888f97388218d3e2489962403f7eece98dd8b4733671edeb9ad1a7c txid
1MJp4z3ig498hNATfgHBAnLFhwoZpvw118 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f Block Hash
 
I think this information should be made public so that other backend systems plugged into crypto networks can guard against this sort of 'hide in plain sight' attack.  As stated earlier,  I honestly set out to look for buried treasure and stumbled upon someone else's exploit.  Thanks to yt_coinartist's assistance in making this public.
 
e8d064874c37ce44f13a880b93b548b83342c99e1530dd746322777f88397ed8
 
Going dark now....bye.

```
