---
tags: [ctf, writeup]
---

# LACTF 2023 - Forensics Writeup

## EBE

---

![](https://i.imgur.com/DuBlxYm.png)

we are given a packet capture with UDP traffic. The challenge is mentioning that someone applied RFC 3514 on the network traffic. 

So Let's check what is RFC 3514.

```
The evil bit is a fictional IPv4 packet header field proposed in RFC 3514, a humorous April Fools' Day RFC from 2003 authored by Steve Bellovin. The RFC recommended that the last remaining unused bit, the "Reserved Bit" in the IPv4 packet header, be used to indicate whether a packet had been sent with malicious intent, thus making computer security engineering an easy problem simply ignore any messages with the evil bit set and trust the rest.
```

I checked the flags of few packets and it was really interesting :-

![](https://i.imgur.com/Eu5zkf8.png)

So all we have to do is skip the packets with Evil bit, I made a script to do the job using scapy.

```py solve.py
from scapy.all import *
flag = b""

pkts = rdpcap("EBE.pcap")

for pkt in pkts:
    # RFC3514
    if pkt[IP].flags == "evil":
        continue
    else:
        flag += pkt.load

print(flag)
```

![](https://i.imgur.com/6fIl5rb.png)

Flag : `lactf{3V1L_817_3xf1l7R4710N_4_7H3_W1N_51D43c8000034d0c}`

## A Hacker's Note

---

![](https://i.imgur.com/anvBpey.png)

We are given a disk dump of encrypted Flash drive. Running `file` on the dd image file shows its a LUKS1 ecnrypted flash drive.

![](https://i.imgur.com/u6XQyD6.png)

We have to find the password for the LUKS encryption. We can see in challenge description that the `organization uses passwords in the format hacker### (hacker + 3 digits)`, with this clue we can do a Mask attack on LUKS encryption.

### Decrypt the LUKS Encryption

I used the [LuksHeader4Hashcat](https://github.com/paule965/LuksHeader4Hashcat) python script to extract LUKS header from the dd image file.

![](https://i.imgur.com/Cyqj0gP.png)

Chose the Active-Slot 0 and dumped the keyslot to `hackers-drive.dd_KeySlot0.bin`. Then I run the hashcat mask attack against the key file.

`hashcat -a 3 -m 14600 hackers-drive.dd_KeySlot0.bin hacker?d?d?d`

After a while, I got the LUKS password `hacker765` .

Then I simply mounted the dd image file with cryptsetup.

![](https://i.imgur.com/kAadFWO.png)

```note_to_self.txt
Note to self: delete notes and notes_normalized tables in .config/joplin/database.sqlite when not in use;<br>
allow encrypted sync to restore notes after
```

Hmm, Interesting. They are using Joplin, an OpenSource note-taking app with End-To-End Encryption. Looks like they have deleted all the synced notes from the local database.

```bash .bash_history
joplin
cd .config/joplin
ls -lah
sqlite3 database.sqlite 
ls
ls -lah
cat database.sqlite | grep lactf
cd ..
cd ..
ls
ls -lah
nano note_to_self.txt
ls -lah
ls
zerofree /dev/mapper/notes
exit
```

### Sync Encrypted Notes

At first I was unsure on what to do, Thanks to my teammate [N1tr0s](https://0xnitros.tech/) he suggested that its about syncing the `encrypted-notes`, I installed the Joplin app in my Android phone (Joplin is cross-platform) and copied the `encrypted-notes` folder to my phone storage, then setup the sync.

![](https://i.imgur.com/orb13Zt.jpg)

```
Synchronisation target : File system
# Depends on your folder location
Directory : /storage/emulated/0/encrypted-notes
```

While setting up the sync, it asked the Master Password. It is impossible to crack the E2E encryption, so we need to find another way to get the Master Key.

![](https://i.imgur.com/7WyWaIT.jpg)

I quickly googled Joplin Master Key and found an interesting discussion in their development forum.

![](https://i.imgur.com/TtsjhKH.png)

I quickly opened the `database.sqlite` found in .config/joplin/ directory. 

![](https://i.imgur.com/OBYVi1t.png)

Cool, Found a Master Key : `n72ROU9BqbjVOlXKH5Ju` in settings table. I entered it in my Phone and boom it was the correct password.

![](https://i.imgur.com/YbrK8Rh.jpg)

Flag : `lactf{S3cUr3_yOUR_C4cH3D_3nCRYP71On_P422woRD2}`