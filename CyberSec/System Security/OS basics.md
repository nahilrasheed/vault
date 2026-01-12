---
tags:
  - GCPC
  - CyberSec
---
# Operating System
The interface between the computer hardware and the user
- The job of an OS is to help other computer programs run efficiently.
Applications send requests to the operating system, and the operating system directs those requests to the hardware. The hardware also sends information back to the operating system, and the operating system sends it back to applications.
## Booting the computer
When you boot, or turn on, your computer, either a BIOS or UEFI microchip is activated. The **Basic Input/Output System (BIOS)** is a microchip that contains loading instructions for the computer and is prevalent in older systems. The **Unified Extensible Firmware Interface (UEFI)** is a microchip that contains loading instructions for the computer and replaces BIOS on more modern systems.
The last instruction from the BIOS or UEFI activates the bootloader. The **bootloader** is a software program that boots the operating system. Once the operating system has finished booting, your computer is ready for use.
## Virtual Machines
A virtual machine (VM) is a virtual version of a physical computer.
Benefits:
- Security
- Efficiency
Hypervisors help users manage multiple virtual machines and connect the virtual and physical hardware. Hypervisors also help with allocating the shared resources of the physical host machine to one or more virtual machines.
Kernel-based Virtual Machine (KVM) is an open-source hypervisor that is supported by most major Linux distributions. It is built into the Linux kernel, which means it can be used to create virtual machines on any machine running a Linux operating system without the need for additional software.
## UI
A user interface is a program that allows a user to control the functions of the operating system.
A GUI (graphical user interface) is a user interface that uses icons on the screen to manage different tasks on the computer.
Basic GUI components
• Start menu
• Task bar
• Desktop with icons and shortcuts
The CLI (command-line interface) is a text-based user interface that uses commands to interact with the computer. These commands communicate with the operating system and execute tasks like opening programs.
The command-line interface allows for customization, which lets you complete multiple tasks simultaneously. 
# Linux
Linux is an open-source operating system. It was created in two parts. In the early 1990s, two different people were working separately on projects to improve computer engineering. The first person was Linus Torvalds. At the time, the UNIX operating system was already in use. He wanted to improve it and make it open source and accessible to anyone. What was revolutionary was his introduction of the Linux kernel. We're going to learn what the kernel does later.
Around the same time, Richard Stallman started working on GNU. GNU was also an operating system based on UNIX. Stallman shared Torvalds' goal of creating software that was free and open to anyone. After working on GNU for a few years, the missing element for the software was a kernel. Together, Torvalds' and Stallman’s innovations made what is commonly referred to as Linux.
## Linux Architecture
### User
The **user** is the person interacting with a computer. They initiate and manage computer tasks. Linux is a multi-user system, which means that multiple users can use the same resources at the same time.
### Applications
An **application** is a program that performs a specific task. A **package manager** is a tool that helps users install, manage, and remove packages or applications. A **package** is a piece of software that can be combined with other packages to form an application.
### Shell
The **shell** is the command-line interpreter. Everything entered into the shell is text based. The shell allows users to give commands to the kernel and receive responses from it. You can think of the shell as a translator between you and your computer. The shell translates the commands you enter so that the computer can perform the tasks you want.
### Filesystem Hierarchy Standard (FHS)
The **Filesystem Hierarchy Standard (FHS)** is the component of the Linux OS that organizes data. It specifies the location where data is stored in the operating system. 
A **directory** is a file that organizes where other files are stored. Directories are sometimes called “folders,” and they can contain files or other directories. The FHS defines how directories, directory contents, and other storage is organized so the operating system knows where to find specific data. 
### Kernel
The **kernel** is the component of the Linux OS that manages processes and memory. It communicates with the applications to route commands. The Linux kernel is unique to the Linux OS and is critical for allocating resources in the system. The kernel controls all major functions of the hardware, which can help get tasks expedited more efficiently.
### Hardware
The **hardware** is the physical components of a computer.
**Peripheral devices** are hardware components that are attached and controlled by the computer system.
**Internal hardware** are the components required to run the computer. : MB,CPU,RAM,HDD.
## Kali Linux
KALI LINUX™ is a trademark of Offensive Security and is Debian derived. This open-source distro was made specifically with penetration testing and digital forensics in mind
Penetration testing tools: Metaasploit,Burp Suite, John the Ripper
Digital Forensics tools: Wireshark, tcpdump,Autopsy
## Package Managers
A **package** is a piece of software that can be combined with other packages to form an application. Some packages may be large enough to form applications on their own.
Packages contain the files necessary for an application to be installed. These files include dependencies, which are supplemental files used to run an application.
A **package manager** is a tool that helps users install, manage, and remove packages or applications. Linux uses multiple package managers.
### Types of package managers
Certain package managers work with certain distributions. For example, the Red Hat Package Manager (RPM) can be used for Linux distributions derived from Red Hat, and package managers such as dpkg can be used for Linux distributions derived from Debian.
Different package managers typically use different file extensions. For example, Red Hat Package Manager (RPM) has files which use the .rpm file extension, such as `Package-Version-Release_Architecture.rpm`. Package managers for Debian-derived Linux distributions, such as dpkg, have files which use the .deb file extension, such as `Package_Version-Release_Architecture.deb`.
### Package management tools
In addition to package managers like RPM and dpkg, there are also package management tools that allow you to easily work with packages through the shell. Package management tools are sometimes utilized instead of package managers because they allow users to more easily perform basic tasks, such as installing a new package. Two notable tools are the Advanced Package Tool (APT) and Yellowdog Updater Modified (YUM).
#### Advanced Package Tool (APT)
APT is a tool used with Debian-derived distributions. It is run from the command-line interface to manage, search, and install packages.
#### Yellowdog Updater Modified (YUM)
YUM is a tool used with Red Hat-derived distributions. It is run from the command-line interface to manage, search, and install packages. YUM works with .rpm files.
## Shell
**shell** is the command-line interpreter. You can think of a shell as a translator between you and the computer system.
### Types of shells
The many different types of Linux shells include the following:
- Bourne-Again Shell (bash)
- C Shell (csh)
- Korn Shell (ksh)
- Enhanced C shell (tcsh)
- Z Shell (zsh)
### Input and output in the shell
Standard input: information received by the OS via the command line.
String data is data consisting of an ordered sequence of characters.
Standard output: information returned by the OS through the shell.
Standard error: contains error messages returned by the OS through the shell.
## Filesystem Hierarchy Standard (FHS)
**Filesystem Hierarchy Standard** **(FHS)** is the component of Linux that organizes data. The FHS is important because it defines how directories, directory contents, and other storage is organized in the operating system.
A **file path** is the location of a file or directory. In the file path, the different levels of the hierarchy are separated by a forward slash (/).
### Root directory
The **root directory** is the highest-level directory in Linux, and it’s always represented with a forward slash (/).  All subdirectories branch off the root directory. Subdirectories can continue branching out to as many levels as necessary.
### Standard FHS directories
- /home: Each user in the system gets their own home directory. 
- /bin: This directory stands for “binary” and contains binary files and other executables. Executables are files that contain a series of commands a computer needs to follow to run programs and perform other functions.
- /etc: This directory stores the system’s configuration files.
- /tmp: This directory stores many temporary files. The /tmp directory is commonly used by attackers because anyone in the system can modify data in these files.
- /mnt: This directory stands for “mount” and stores media, such as USB drives and hard drives.
### User-specific subdirectories
Under home are subdirectories for specific users. Each user has their own personal subdirectories.
**Note:** When the path leads to a subdirectory below the user’s home directory, the user’s home directory can be represented as the tilde (~).
The **absolute file path** is the full file path, which starts from the root.
The **relative file path** is the file path that starts from a user's current directory.
- [[Shell Commands]]
- [[Linux File permissions and ownership]]
## [[Linux authentication and authorization]]
