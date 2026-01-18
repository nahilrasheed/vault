---
tags:
  - CyberSec/tools
  - CiscoEH
---
Enum4linux is a tool for enumerating information from Windows and Samba. Samba is an application that enables Linux and Apple clients to participate in Windows networks. It enables non-Windows clients to utilize the Server Message Block (SMB) protocol to access file and print services. Samba servers can participate in a Windows domain, both as a client and a server.
`Simple wrapper around the tools in the samba package to provide similar functionality to enum.exe (formerly from www.bindview.com).`

1. Most enum4linux commands must be run as root, so use the sudo su command to obtain persistent root access.
2. usage: `enum4linux.pl [options] [ip]`

Options are (like "enum"):
    -U        get userlist
    -M        get machine list*
    -S        get sharelist
    -P        get password policy information
    -G       get group and member list
    -d        be detailed, applies to -U and -S
    -i         Get printer information
    -o        Get OS information
    -u user   specify username to use (default "")  
    -p pass   specify password to use (default "")  
	-a        Do all simple enumeration (-U -S -G -P -r -o -n -i).
              This option is enabled if you don't provide any other options.

Some terms:
- Relative Identifier (RID): Uniquely identifies a user, group, system, or domain.
- Security Identifier (SID): Uniquely identifies users and groups within the local domain. Globally unique so can also work between domains.
- Domain Controller (DC): Domain controller is a server that manages network and identity security requests. It authenticates users and determines whether the users are allowed to access IT resources in the domain.
- Lightweight Directory Access Protocol (LDAP): a directory access protocol that enables services and clients that use LDAP naming services to communicate.
- Workgroup: a group of standalone computers that are independently administered.
