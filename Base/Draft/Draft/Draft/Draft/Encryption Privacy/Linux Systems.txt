
Tcplay
From: https://github.com/bwalex/tc-play
tcplay is a free (BSD-licensed), pretty much fully featured (including multiple keyfiles, cipher cascades, etc) and stable TrueCrypt implementation. 
This implementation supports mapping (opening) both system and normal TrueCrypt volumes, as well as opening hidden volumes and opening an outer volume while protecting a hidden volume. There is also support to create volumes, including hidden volumes, etc. Since version 1.1, there is also support for restoring from the backup header (if present), change passphrase, keyfile and PBKDF2 PRF function. 
Since tcplay uses dm-crypt (or dm_target_crypt on DragonFly) it makes full use of any available hardware encryption/decryption support once the volume has been mapped. 
It is based solely on the documentation available on the TrueCrypt website, many hours of trial and error and the output of the Linux' TrueCrypt client. As it turns out, most technical documents on TrueCrypt contain mistakes, hence the trial and error approach.





Cryptsetup
From: https://code.google.com/p/cryptsetup/
Cryptsetup is utility used to conveniently setup disk encryption based on dm-crypt kernel module. 
These include plain dm-crypt volumes, LUKS volumes, loop-AES and TrueCrypt compatible format. 
Project also includes veritysetup utility used to conveniently setup dm-verity block integrity checking kernel module. 
LUKS is the standard for Linux hard disk encryption. By providing a standard on-disk-format, it does not only facilitate compatibility among distributions, but also provides secure management of multiple user passwords. In contrast to existing solution, LUKS stores all setup necessary setup information in the partition header, enabling the user to transport or migrate his data seamlessly. 
LUKS was designed according to TKS1, a template design developed in TKS1 for secure key setup. LUKS closely reassembles the structure recommended in the TKS1 paper, but also adds meta data for cipher setup management and LUKS also supports for multiple keys/passphrases. 4
Why LUKS?
compatiblity via standardization, 
secure against low entropy attacks, 
support for multiple keys, 
effective passphrase revocation, 
free 




From: https://code.google.com/p/cryptsetup/