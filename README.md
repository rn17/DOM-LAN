DOM-LAN
=======

Intrusion Detection System in Linux


The recent research and development in the network technologies has resulted into numerous security threats in a network. 
Users tend to keep their systems out of virus but don’t give much focus to online security. 
A lot of research is going on in the area of intrusion detection and prevention systems.
The recent trends in intrusion detection have suggested that most of the malicious and abnormal activities can be 
identified by capturing the network traffic and analyzing them. Many research works in this area address only a 
particular problem focusing on a network attack or a behavioral pattern of certain kind of worms and Trojans, and 
propose a solution for that. This gives solution to only a particular type of intrusion detection and leaves 
the remaining problems apart.  There is a need for a kind of system which can handle different types of malicious
activities on the local area network. We have developed an IDS-like tool which focuses on detection of network attacks,
fixed signatures, behavioral methods and suspicious packets. Our tool addresses different intrusions pertaining to
different detection methods. The in-depth packet analysis of the packets incoming at our system makes us aware about
the security threats that might affect our system. In this project we develop a tool in libpcap in Linux which 
will analyze the packets on the incoming host for various kinds of malicious activities.
The stored packets are displayed in a log file while the malicious activities are displayed in an alert file. 
