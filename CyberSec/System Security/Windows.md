## NTFS
The file system used in modern versions of  Windows  is the **New Technology File System** or simply  [NTFS](https://docs.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview) .

Before NTFS, there was  **FAT16/FAT32** (File Allocation Table) and **HPFS** (High Performance File System).

NTFS is known as a journaling file system. In case of a failure, the file system can automatically repair the folders/files on disk using information stored in a log file. This function is not possible with FAT.   

NTFS addresses many of the limitations of the previous file systems; such as: 

- Supports files larger than 4GB
- Set specific permissions on folders and files
- Folder and file compression
- Encryption ( [Encryption File System](https://docs.microsoft.com/en-us/windows/win32/fileio/file-encryption) or **EFS** )

On NTFS volumes, you can set permissions that grant or deny access to files and folders.

The permissions are:

- **Full control**
- **Modify**
- **Read & Execute**
- **List folder contents**
- **Read**
- **Write**

![[Windows-1763197416160.png]]

Another feature of NTFS is **Alternate Data Streams** ( **ADS** ).

Alternate Data Streams  (ADS) is a file attribute specific to Windows  NTFS  (New Technology File System).

Every file has at least one data stream ( `$DATA` ), and ADS allows files to contain more than one stream of data. Natively [Window Explorer](https://support.microsoft.com/en-us/windows/what-s-changed-in-file-explorer-ef370130-1cca-9dc5-e0df-2f7416fe1cb1) doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, but [Powershell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1) gives you the ability to view ADS for files.

From a security perspective, malware writers have used ADS to hide data.

## Windows Folder
The Windows folder ( `C:\Windows` ) is traditionally known as the folder which contains the Windows operating system. 

The folder doesn't have to reside in the C drive necessarily. It can reside in any other drive and technically can reside in a different folder.

The system  environment variable for the Windows directory is `%windir%` .

The System32 folder holds the important files that are critical for the operating system.

## UAC
User accounts can be one of two types on a typical local Windows system: **Administrator** & **Standard User**.
The user account type will determine what actions the user can perform on that specific Windows system. 

- An Administrator can make changes to the system: add users, delete users, modify groups, modify settings on the system, etc. 
- A Standard User can only make changes to folders/files attributed to the user & can't perform system-level changes, such as install programs.

There are several ways to determine which user accounts exist on the system.
- One way is to click the `Start Menu` and type `Other User`. A shortcut to `System Settings > Other users` should appear.
- Another way to access this information, and then some, is using **Local User and Group Management**. 
		Right-click on the Start Menu and click Run. Type `lusrmgr.msc`

A user doesn't need to run with high (elevated) privileges on the system to run tasks that don't require such privileges, such as surfing the Internet, working on a Word document, etc. This elevated privilege increases the risk of system compromise because it makes it easier for malware to infect the system. Consequently, since the user account can make changes to the system, the malware would run in the context of the logged-in user.

To protect the local user with such privileges, Microsoft introduced **User Account Control** (UAC). This concept was first introduced with the short-lived [Windows Vista](https://en.wikipedia.org/wiki/Windows_Vista)  and continued with versions of Windows that followed.

**Note** : UAC (by default) doesn't apply for the built-in local administrator account. 

How does UAC work? When a user with an account type of administrator logs into a system, the current session doesn't run with elevated permissions. When an operation requiring higher-level privileges needs to execute, the user will be prompted to confirm if they permit the operation to run.

