# netbiox

## Purpose

A service that resolves netbios names based upon /etc/samba/lmhosts file. To be used when SAMBA is configured to have different configuration based on the virtual IP address of the server, allowing to consolidate a bunch of virtual SMB servers into a single place.

## Background

Since the beginning of time, Windows SMB client has been affected by a very disturbing annoyance. Once you login successfully on a shared folder (share) on a server (e.g. \\SERVER\SHARE1 as foo) you cannot login with different credentials on a different share on the same server (e.g. \\SERVER\SHARE2 as bar). This makes it really hard to configure a system where different shares have different level of access.

With SAMBA it was possible, through aliases, to have the same server impersonate different aliases, so that from a Windows client perspective they would be different servers altogether. See for example [here](https://www.samba.org/samba/docs/using_samba/ch06.html). The problem came out when new version of the protocol dropped Netbios altogether and the name is not passed in the request anymore.

I figured that I could assign multiple IP addresses to the same network interface and route the SAMBA configuration based upon the IP address (`%i` in Samba config) and this works. The problem is how to resolve names. I could set the configuration on the router but I felt like having the configuration split between different machines not ideal.

I then discovered that Windows still uses Netbios to resolve names, but the netbios server provided with Samba wouldn't use the lmhosts file at all and just limit the response to the hostname itself. I spoke with Samba developers and a fix might come down one day, but until then I decided to fix it my way. By disabling netbios resolution in Samba and create a deamon that does only one thing: reply to name resolution queries based upon the configuration in lmhosts. And thus netbiox was born.

## Instructions

Build the daemon with

`cc netbiox.c -o netbioxd`

Move it to /usr/sbin:

`sudo mv netbioxd /usr/sbin`

Move the service configuration file into \etc\init.d\netbiox

`sudo mv netbiox /etc/init.d/netbiox`

Create an lmhosts file:

`sudo nano /etc/samba/lmhosts`

Example:

`192.168.1.2	server`

`192.168.2.3	server2`

Refresh the services:

`sudo systemctl daemon-reload`

Enable the service to start at boot:

`sudo systemctl enable netbiox`

Start the netbiox daemon

`sudo service netbiox start`
