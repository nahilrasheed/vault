The Windows Registry is a central, hierarchical database storing critical low-level settings, configurations, and options for the Windows operating system, hardware, and installed applications.
Accessed via the `regedit` tool, it organizes data into keys and subkeys, holding user preferences, hardware info, and software settings
Key components
- Keys/Hives: Like folders, they group related settings (e.g., HKEY_LOCAL_MACHINE for system-wide settings).
- Subkeys: Further subdivisions within keys.
- Values: The actual data (text, numbers, binary) within keys and subkeys. 

|Hive Name|Contains|Location|
|---|---|---|
|SYSTEM|- Services<br>- Mounted Devices<br>- Boot Configuration<br>- Drivers<br>- Hardware|`C:\Windows\System32\config\SYSTEM`|
|SECURITY|- Local Security Policies<br>- Audit Policy Settings|`C:\Windows\System32\config\SECURITY`|
|SOFTWARE|- Installed Programs<br>- OS Version and other info<br>- Autostarts<br>- Program Settings|`C:\Windows\System32\config\SOFTWARE`|
|SAM|- Usernames and their Metadata<br>- Password Hashes<br>- Group Memberships<br>- Account Statuses|`C:\Windows\System32\config\SAM`|
|NTUSER.DAT|- Recent Files<br>- User Preferences<br>- User-specific Autostarts|`C:\Users\username\NTUSER.DAT`|
|USRCLASS.DAT|- Shellbags<br>- Jump Lists|`C:\Users\username\AppData\Local\Microsoft\Windows\USRCLASS.DAT`|

**Note:** The configuration settings stored in each hive listed above are just a few examples. Each hive stores more than these.

 Windows organizes all the Registry Hives into these structured **Root Keys**. Instead of seeing the Registry Hives, you would always get these registry root keys whenever you open the registry. 
 
 Registry keys with their respective Registry Hives.

|Hive on Disk|Where You See It in Registry Editor|
|---|---|
|SYSTEM|`HKEY_LOCAL_MACHINE\SYSTEM`|
|SECURITY|`HKEY_LOCAL_MACHINE\SECURITY`|
|SOFTWARE|`HKEY_LOCAL_MACHINE\SOFTWARE`|
|SAM|`HKEY_LOCAL_MACHINE\SAM`|
|NTUSER.DAT|`HKEY_USERS\<SID> and HKEY_CURRENT_USER`|
|USRCLASS.DAT|`HKEY_USERS\<SID>\Software\Classes`|
most of the Registry Hives are located under the `HKEY_LOCAL_MACHINE (HKLM)` key. The `SYSTEM`, `SOFTWARE`, `SECURITY`, and `SAM` hives are under the `HKLM` key. `NTUSER.DAT` and `USRCLASS.DAT` are located under `HKEY_USERS (HKU)` and `HKEY_CURRENT_USER (HKCU)`. 

**Note:** The other two keys (`HKEY_CLASSES_ROOT (HKCR)` and `HKEY_CURRENT_CONFIG (HKCC)`) are not part of any separate hive files. They are dynamically populated when Windows is running.

## Registry Forensics
Since the registry contains a wide range of data about the Windows system, it plays a crucial role in forensic investigations. 
**Registry forensics** is the process of extracting and analyzing evidence from the registry. 
In Windows digital forensic investigations, investigators analyze registry, event logs, file system data, memory data, and other relevant data to construct the whole incident timeline. 

The table below lists some registry keys that are particularly useful during forensic investigations.

|Registry Key|Importance|
|---|---|
|`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`|It stores information on recently accessed applications launched via the GUI.|
|`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`|It stores all the paths and locations typed by the user inside the Explorer address bar.|
|`HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths`|It stores the path of the applications.|
|`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`|It stores all the search terms typed by the user in the Explorer search bar.|
|`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`|It stores information on the programs that are set to automatically start (startup programs) when the users logs in.|
|`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`|It stores information on the files that the user has recently accessed.|
|`HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`|It stores the computer's name (hostname).|
|`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`|It stores information on the installed programs.|

Numerous other registry keys can be used for extracting important evidence from a Windows system during an incident investigation. The investigation of these registry keys during forensics cannot be done via the built-in Registry Editor tool. It is because the Registry analysis cannot be done on the system under investigation (due to the chance of modification), so we collect the Registry Hives and open them offline into our forensic workstation. However, the Registry Editor does not allow opening offline hives. The Register editor also displays some of the key values in binary which are not readable.

To solve this problem, there are some tools built for registry forensics. In this task you will use the [**Registry Explorer**](https://ericzimmerman.github.io/) tool which is a registry forensics tool. It is open source and can parse the binary data out of the registry, and we can analyze it without the fear of modification.
