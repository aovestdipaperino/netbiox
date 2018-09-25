# netbiox

## Purpose:

A service that resolves netbios names based upon /etc/samba/lmhosts file. To be used when SAMBA is configured to have different configuration based on the virtual IP address of the server, allowing to consolidate a bunch of virtual SMB servers into a single place.

## Instructions: 

Build the daemon with

`cc netbiox.c -o netbioxd`

Move it to \usr\sbin:

`sudo mv netbioxd \usr\sbin`

Move the service configuration file into \etc\init.d\netbiox

`sudo mv netbiox \etc\init.d\netbiox`

Create an lmhosts file:

`sudo nano \etc\samba\lmhosts`

Example:

`192.168.1.2	server`

`192.168.2.3	server2`

Refresh the services:

`systemctl daemon-reload`

Start the netbiox daemon

`service netbiox start`
