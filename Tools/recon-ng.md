---
tags:
  - CyberSec/tools
  - CiscoEH
---
**_Recon-ng_** is a menu-based tool that can be used to automate the information gathering of OSINT. Recon-ng comes with Kali Linux and several other penetration testing Linux distributions, and it can be downloaded from [_https://github.com/lanmaster53/recon-ng_](https://github.com/lanmaster53/recon-ng).

Recon-ng is an OSINT framework that is similar to the Metasploit exploitation framework or the Social-Engineering Tooklit (SET). If consists of a series of modules that can be run in their own workspaces. The modules can be configured to run with option settings that are specific to the module. This simplifies running Recon-ng at the command line because options for the modules are independently set within the workspace. When you run the module, it uses these settings to perform its searches.

As the name suggests, Recon-ng is used to perform a wide range of reconnaissance activities on different settings that you provide. Some modules are available with the Kali installation and others are available for download and installation in the Recon-ng modules marketplace.

Recon-ng can query several third-party tools, including Shodan, as well as Twitter, Instagram, Flickr, YouTube, Google, GitHub repositories, and many other sites. For some of those tools and sources, you must register and obtain an API key. You can add the API key by using the Recon-ng **keys add** command. To list all available APIs that Recon-ng can interact with, use the **keys list** command
### Step 1: Create a workspace.
Recon-ng has auto complete. Press the tab button to complete commands and command options. Use the tab key twice to list the available commands and options at different places in the command line. This is very handy.
1. To run Recon-ng, open a new terminal window and enter **recon-ng**. You can also start the program by going to the Kali tools menu, searching for the app, and clicking the icon.
2. Note that the terminal prompt changes to indicate that you are working within the Recon-ng framework. Enter **help** to get a sense of the commands that are available.
3. Recon-ng uses workspaces to isolate investigations from one another. Workspaces can be created for different parts of a test or different customers for example. Type **workspaces help** to view options for the workspaces command.
How can you display the available workspaces?
Enter the `_workspaces list_` command.
How can you remove a workspace?
Enter the `_workspaces remove [workspace_name]_ command`.
4. Create a workspace named **test** by entering **workspaces create** followed by the workspace name. Note that the prompt has changed to indicate that you are in this workspace.
5. Type **help** to see the commands that are available within workspaces.
What command will exit the workspace and return to the main Recon-ng prompt?
The back command
### Step 2: Investigate modules.
Recon-ng is a modular framework. Modules are Python programs with different functions. They are stored in an external marketplace that permits developers to create their own modules and contribute them for use by others.
Return to the Recon-ng prompt. Enter the **modules search** command. This will display the currently installed modules.
How many modules are currently available to you?
No modules are installed.
### Step 3: Investigate the module marketplace.
Recon-ng will not function without modules. In this step, we will install modules from the Recon-ng marketplace. The module marketplace is a GitHub public repository. Search the web for **recon-ng-marketplace** to view the repository. Explore the folders to learn more about the modules.
1. In the terminal, view help for the **marketplace** command. Use the **search** option to list all the modules that are currently available.
`[recon-ng][default] > **marketplace search**`
2. Note that the modules are organized by their category and type. This appears as a path prepended to the name of the module. You can filter the output by adding a search term to the marketplace search command. Try a few different search terms that are related to OSINT information to get a sense of the modules that are available.
The module tables have columns for **D** and **K**. Search for shodan modules. What are the requirements for these modules?
They have dependencies (D) and require API keys (K). The dependencies refer to Python modules that must be installed on your computer to run the module.
3. To learn more about individual modules, use the **marketplace info** command followed by the full name of the module, including its category and type. It is easier to select the name of the module and copy and paste it into the command line.
### Step 4: Install a new module.
Recon-ng accesses modules from the Github repository and downloads them to Kali when they are installed.
1. Search the marketplace modules using **bing** as a search term. Locate a module that requires no dependencies or API keys.
Which module did you find?
recon/domains-hosts/bing_domain_web
2. View information for this module.
3. To install the module, copy the full name, including the path, to the clipboard.
4. Enter the **marketplace install** command followed by the full name of the module.
`[recon-ng][default] > **marketplace install recon/domains-hosts/bing_domain_web**`
5. After installation, enter the **modules search** command to verify that the new module is now available.
6. Repeat the process to install the **hackertarget** module.
### Step 5: Run the new modules
1. Create a new workspace. Name it as you wish.
2. To start working with a module, it must be initialized. Enter **modules load hackertarget** to begin working with the module. Note that the prompt changes to reflect the loaded module.
3. Each module is its own environment. The developers of recon-ng have taken care to keep the framework consistent, so the same commands are available for each module. However, the options can vary. Type **info** at the module prompt to view important details about the module.
What information is available for this module?
The name of the module, module version, name of the developer, a brief description, and information about the options.
What is the only option for this module?
SOURCE
4. Instead of passing options at the command line, in Recon-ng you set the options and then enter a simple command to execute the module. Use the **options set source** command to set the only option for this module. Complete the command by specifying the target as **hackxor.net**.
5. Verify the option setting with the **info** command.
6. Type **run** to execute the module.
7. Inspect the output of the command. The output is stored in a database so you can refer to it later. The data that is stored is specific to the workplace in which it was gathered.
8. Enter the **dashboard** command. This queries the Recon-ng database and provides a summary of the information that has been gathered. It is specific to this workspace.
What is the Recon-ng data label for the subdomains that have been listed? How many were discovered?
Recon-ng classifies the subdomains as “hosts.” Nine were discovered.
9. The **show** command displays the data for specific categories. Enter the **show hosts** command to display the list of hosts that were discovered.
10. Now repeat the process with the **bing** module. Compare the results with the **hackertarget** module.
How many subdomains did the module find? How does this compare to the **hackertarget** module?
Answers may vary. At the time of this writing, they both found 6 subdomains.
### Step 6: Investigate the web interface.
Recon-ng has a web interface that simplifies and improves viewing results that are stored in Recon-ng databases. It also allows easy export of the results tables for reporting purposes.
1. Open a new terminal.
2. Enter the **recon-web** command to start the Recon-ng server process. Note the command output.
3. In a new browser tab, access the webpage using the URL information provided in the output.
4. The web interface shows data from the default workspace when first opened. Click the orange workspace name at the top of the page to display data from different workspaces.




---

**Step 1: Start Recon-ng**

**Step 1: Start Recon-ng**

To start using Recon-ng, you simply run **recon-ng** from a new terminal window. Example 3-11 shows the command and the initial menu that Recon-ng starts with.

**_Example 3-11_** **_-_** _Starting Recon-ng_

```
 |--[omar@websploit]--[~] |--- $ recon-ng  [*] Version check disabled.      _/_/_/    _/_/_/_/    _/_/_/    _/_/_/    _/      _/            _/      _/    _/_/_/    _/    _/  _/        _/        _/      _/  _/_/    _/            _/_/    _/  _/          _/_/_/    _/_/_/    _/        _/      _/  _/  _/  _/  _/_/_/_/  _/  _/  _/  _/  _/_/_/  _/    _/  _/        _/        _/      _/  _/    _/_/            _/    _/_/  _/      _/  _/    _/  _/_/_/_/    _/_/_/    _/_/_/    _/      _/            _/      _/    _/_/_/                                                 /\                                          / \\ /\     Sponsored by...               /\  /\/  \\V  \/\                                  / \\/ // \\\\\ \\ \/\                                 // // BLACK HILLS \/ \\                                www.blackhillsinfosec.com                    ____   ____   ____   ____ _____ _  ____   ____  ____                  |____] | ___/ |____| |       |   | |____  |____ |                  |      |   \_ |    | |____   |   |  ____| |____ |____                                    www.practisec.com                        [recon-ng v5.1.2, Tim Tomes (@lanmaster53)]            [4] Recon modules [1] Discovery modules  [recon-ng][default] > 
```

expand_less

**Step 2. View available commands**

**Step 2. View available commands**

To get an idea of what commands are available in the Recon-ng command-line tool, you can simply type **help** and press Enter. Example 3-12 shows the output of the **help** command.

**_Example 3-12_** **_-_** _Recon-ng_ **_help_** _Command_

```
 [recon-ng][default] > help Commands (type [help|?] ): --------------------------------- back           Exits the current context dashboard      Displays a summary of activity db             Interfaces with the workspace's database exit           Exits the framework help           Displays this menu index          Creates a module index (dev only) keys           Manages third party resource credentials marketplace    Interfaces with the module marketplace modules        Interfaces with installed modules options        Manages the current context options pdb            Starts a Python Debugger session (dev only) script         Records and executes command scripts shell          Executes shell commands show           Shows various framework items snapshots      Manages workspace snapshots spool          Spools output to a file workspaces     Manages workspaces [recon-ng][default] > 
```

expand_less

**Step 3. Search for available modules.**

**Step 3. Search for available modules.**

Before you can start gathering information using the Recon-ng tool, you need to understand what modules are available. (You can see from the initial screen in Example 3-11 the current number of modules that are installed in Recon-ng.) Recon-ng comes with a “marketplace,” where you can search for available modules to be installed. You can use the **marketplace search** command to search for all the available modules in Recon-ng, as demonstrated in Example 3-13.

Scroll the output in Example 3-13 to the right to see the **D** and **K** columns The letter **D** indicates that the module has dependencies. The letter **K** indicates that an API key is needed in order to use the resources used in a particular module. For example, the module with the path recon/companies-contacts/censys_email_address has dependencies and needs an API key in order to query the Censys database. (Censys is a very popular resource for querying OSINT data.)

**_Example 3-13_** _- The Recon-ng Marketplace Search_

```
  [recon-ng][default] > marketplace search    +---------------------------------------------------------------------------------------------------+   |                        Path                        | Version |     Status    |  Updated   | D | K |   +---------------------------------------------------------------------------------------------------+   | discovery/info_disclosure/cache_snoop              | 1.1     | not installed | 2020-10-13 |   |   |   | discovery/info_disclosure/interesting_files        | 1.2     | not installed | 2021-10-04 |   |   |   | exploitation/injection/command_injector            | 1.0     | not installed | 2019-06-24 |   |   |   | exploitation/injection/xpath_bruter                | 1.2     | not installed | 2019-10-08 |   |   |   | import/csv_file                                    | 1.1     | not installed | 2019-08-09 |   |   |   | import/list                                        | 1.1     | not installed | 2019-06-24 |   |   |   | import/masscan                                     | 1.0     | not installed | 2020-04-07 |   |   |   | import/nmap                                        | 1.1     | not installed | 2020-10-06 |   |   |   | recon/companies-contacts/bing_linkedin_cache       | 1.0     | not installed | 2019-06-24 |   | * |   | recon/companies-contacts/censys_email_address      | 2.0     | not installed | 2021-05-11 | * | * |   | recon/companies-contacts/pen                       | 1.1     | not installed | 2019-10-15 |   |   |   | recon/companies-domains/censys_subdomains          | 2.0     | not installed | 2021-05-10 | * | * |   | recon/companies-domains/pen                        | 1.1     | not installed | 2019-10-15 |   |   |   | recon/companies-domains/viewdns_reverse_whois      | 1.1     | not installed | 2021-08-24 |   |   |   | recon/companies-domains/whoxy_dns                  | 1.1     | not installed | 2020-06-17 |   | * |   | recon/companies-hosts/censys_org                   | 2.0     | not installed | 2021-05-11 | * | * | <output omitted>   | reporting/csv                                      | 1.0     | not installed | 2019-06-24 |   |   |   | reporting/html                                     | 1.0     | not installed | 2019-06-24 |   |   |   | reporting/json                                     | 1.0     | not installed | 2019-06-24 |   |   |   | reporting/list                                     | 1.0     | not installed | 2019-06-24 |   |   |   | reporting/proxifier                                | 1.0     | not installed | 2019-06-24 |   |   |   | reporting/pushpin                                  | 1.0     | not installed | 2019-06-24 |   | * |   | reporting/xlsx                                     | 1.0     | not installed | 2019-06-24 |   |   |   | reporting/xml                                      | 1.1     | not installed | 2019-06-24 |   |   |   +---------------------------------------------------------------------------------------------------+    D = Has dependencies. See info for details.   K = Requires keys. See info for details.  [recon-ng][default] > 
```

expand_less

**Step 4. Refresh the marketplace.**

**Step 4. Refresh the marketplace.**

You can refresh the data about the available modules by using the **marketplace refresh** command, as shown in Example 3-14.

**_Example 3-14_** **_-_** _Refreshing the Recon-ng Marketplace Data_

```
 [recon-ng][default] > marketplace refresh [*] Marketplace index refreshed.  [recon-ng][default] >
```

expand_less

**Step 5. Search the marketplace.**

**Step 5. Search the marketplace.**

Let’s perform a quick search to find different subdomains of one of my domains (h4cker.org). We can use the module **bing_domain_web** to try to find any subdomains leveraging the Bing search engine. You can perform a keyword search for any modules by using the command **marketplace search <** _keyword_ **>**, as demonstrated in Example 3-15.

**_Example 3-15_** **_-_** _Marketplace Keyword Search_

```
 [recon-ng][default] > marketplace search bing [*] Searching module index for 'bing'...    +-----------------------------------------------------------------------------------------------+   |                      Path                      | Version |     Status    |  Updated   | D | K |   +-----------------------------------------------------------------------------------------------+   | recon/companies-contacts/bing_linkedin_cache   | 1.0     | not installed | 2019-06-24 |   | * |   | recon/domains-hosts/bing_domain_api            | 1.0     | not installed | 2019-06-24 |   | * |   | recon/domains-hosts/bing_domain_web            | 1.1     | installed     | 2019-07-04 |   |   |   | recon/hosts-hosts/bing_ip                      | 1.0     | not installed | 2019-06-24 |   | * |   | recon/profiles-contacts/bing_linkedin_contacts | 1.2     | not installed | 2021-08-24 |   | * |   +-----------------------------------------------------------------------------------------------+    D = Has dependencies. See info for details.   K = Requires keys. See info for details.  [recon-ng][default] > 
```

expand_less

**Step 6. Install a module.**

**Step 6. Install a module.**

Several results matched the bing keyword. However, the one that we are interested in is recon/domains-hosts/bing_domain_web. You can install the module by using the **marketplace install** command, as shown in Example 3-16.

**_Example 3-16_** **_-_** _Installing a Recon-ng Module_

```
 [recon-ng][default] > marketplace install recon/domains-hosts/bing_domain_web [*] Module installed: recon/domains-hosts/bing_domain_web [*] Reloading modules... [recon-ng][default] > 
```

expand_less

**Step 7. Show installed modules.**

**Step 7. Show installed modules.**

You can use the **modules search** command (as shown in Example 3-17) to show all the modules that have been installed in Recon-ng.

**_Example 3-17_** **_-_** _Recon-ng Installed Modules_

```
 [recon-ng][default] > modules search   Discovery   ---------     discovery/info_disclosure/interesting_files   Recon   -----     recon/domains-hosts/bing_domain_web     recon/domains-hosts/brute_hosts     recon/domains-hosts/certificate_transparency     recon/domains-hosts/netcraft [recon-ng][default] > 
```

expand_less

**Step 8. Load a module.**

**Step 8. Load a module.**

To load the module that you would like to use, use the **modules load** command. In Example 3-18, the bing_domain_web module is loaded. Notice that the prompt changed to include the name of the loaded module. After the module is loaded, you can display the module options by using the **info** command.

**_Example 3-18_** **_-_** _Loading an Installed Module in Recon-ng_

```
 [recon-ng][default] > modules load recon/domains-hosts/bing_domain_web [recon-ng][default][bing_domain_web] > info       Name: Bing Hostname Enumerator     Author: Tim Tomes (@lanmaster53)    Version: 1.1  Description:   Harvests hosts from Bing.com by using the 'site' search operator. Updates the 'hosts'    table with the results.  Options:   Name    Current Value  Required  Description   ------  -------------  --------  -----------   SOURCE  h4cker.org  yes      source of input (see 'info' for details)  Source Options:   default     SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL   <string>    string representing a single input   <path>      path to a file containing a list of inputs   query <sql> database query returning one column of inputs  [recon-ng][default][bing_domain_web] >
```

expand_less

**Step 9. Change the source.**

**Step 9. Change the source.**

You can change the source (the domain to be used to find its subdomains) by using the command **options set SOURCE**, as demonstrated in Example 3-19. After the source domain is set, you can type **run** to run the query. The highlighted lines show that four subdomains were found using the **bing_domain_web** module.

**_Example 3-19_** **_-_** _Setting the Source Domain and Running the Query_

```
 [recon-ng][default][bing_domain_web] > options set SOURCE h4cker.org SOURCE => h4cker.org [recon-ng][default][bing_domain_web] > run ---------- H4CKER.ORG ---------- [*] URL: https://www.bing.com/search?first=0&q=domain%3Ah4cker.org [*] Country: None [*] Host: bootcamp.h4cker.org [*] Ip_Address: None [*] Latitude: None [*] Longitude: None [*] Notes: None [*] Region: None [*] -------------------------------------------------- [*] Country: None [*] Host: webapps.h4cker.org [*] Ip_Address: None [*] Latitude: None [*] Longitude: None [*] Notes: None [*] Region: None [*] -------------------------------------------------- [*] Country: None [*] Host: lpb.h4cker.org [*] Ip_Address: None [*] Latitude: None [*] Longitude: None [*] Notes: None [*] Region: None [*] -------------------------------------------------- [*] Country: None [*] Host: malicious.h4cker.org [*] Ip_Address: None [*] Latitude: None [*] Longitude: None [*] Notes: None [*] Region: None [*] -------------------------------------------------- [*] Sleeping to avoid lockout... [*] URL: https://www.bing.com/search?first=0&q=domain%3Ah4cker.org+-domain%3Abootcamp.h4cker. org+-domain%3Awebapps.h4cker.org+-domain%3Alpb.h4cker.org+-domain%3Amalicious.h4cker.org  ------- SUMMARY ------- [*] 4 total (0 new) hosts found. [recon-ng][default][bing_domain_web] > 
```