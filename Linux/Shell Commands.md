
## Create and Modify directories

### mkdir
The mkdir command creates a new directory. Like all of the commands presented in this reading, you can either provide the new directory as the absolute file path, which starts from the root, or as a relative file path, which starts from your current directory.

### **rmdir**
The rmdir command removes, or deletes, a directory. For example, entering rmdir /home/analyst/logs/network would remove this empty directory from the file system.
**Note**: The rmdir command cannot delete directories with files or subdirectories inside. For example, entering rmdir /home/analyst returns an error message. 

## Creating and modifying files
### **touch and rm**
The touch command creates a new file. This file won’t have any content inside. If your current directory is /home/analyst/reports, entering touch permissions.txt creates a new file in the reports subdirectory called permissions.txt.
The rm command removes, or deletes, a file. This command should be used carefully because it’s not easy to recover files deleted with rm. To remove the permissions file you just created, enter rm permissions.txt. 
**Pro Tip:** You can verify that permissions.txt was successfully created or removed by entering ls.

### **mv and cp**
You can also use mv and cp when working with files. The mv command moves a file or directory to a new location, and the cp command copies a file or directory into a new location. The first argument after mv or cp is the file or directory you want to move or copy, and the second argument is the location you want to move or copy it to.
To move permissions.txt into the logs subdirectory, enter mv permissions.txt /home/analyst/logs. Moving a file removes the file from its original location. However, copying a file doesn’t remove it from its original location. To copy permissions.txt into the logs subdirectory while also keeping it in its original location, enter cp permissions.txt /home/analyst/logs.
**Note**: The mv command can also be used to rename files. To rename a file, pass the new name in as the second argument instead of the new location. For example, entering mv permissions.txt perm.txt renames the permissions.txt file to perm.txt.

## nano text editor
**nano** is a command-line file editor that is available by default in many Linux distributions. Many beginners find it easy to use, and it’s widely used in the security profession. You can perform multiple basic tasks in nano, such as creating new files and modifying file contents. 
To open an existing file in nano from the directory that contains it, enter nano followed by the file name. For example, entering nano permissions.txt from the /home/analyst/reports directory opens a new nano editing window with the permissions.txt file open for editing. You can also provide the absolute file path to the file if you’re not in the directory that contains it.
You can also create a new file in nano by entering nano followed by a new file name. For example, entering nano authorized_users.txt from the /home/analyst/reports directory creates the authorized_users.txt file within that directory and opens it in a new nano editing window.
Since there isn't an auto-saving feature in nano, it’s important to save your work before exiting. To save a file in nano, use the keyboard shortcut Ctrl + O. You’ll be prompted to confirm the file name before saving. To exit out of nano, use the keyboard shortcut Ctrl + X.
**Note**: Vim and Emacs are also popular command-line text editors.

## Standard output redirection
There’s an additional way you can write to files. Previously, you learned about standard input and standard output. **Standard input** is information received by the OS via the command line, and **standard output** is information returned by the OS through the shell.
You’ve also learned about piping. **Piping** sends the standard output of one command as standard input to another command for further processing. It uses the pipe character (|). 
In addition to the pipe (|), you can also use the right angle bracket (>) and double right angle bracket (>>) operators to redirect standard output.
When used with echo, the > and >> operators can be used to send the output of echo to a specified file rather than the screen. The difference between the two is that > overwrites your existing file, and >> adds your content to the end of the existing file instead of overwriting it. The > operator should be used carefully, because it’s not easy to recover overwritten files.
When you’re inside the directory containing the permissions.txt file, entering echo "last updated date" >> permissions.txt adds the string “last updated date” to the file contents. Entering echo "time" > permissions.txt after this command overwrites the entire file contents of permissions.txt with the string “time”.
**Note:** Both the > and >> operators will create a new file if one doesn’t already exist with your specified name.
## Common commands for reading file content
- we can use 'echo' command to write text 
### **cat**
The cat command displays the content of a file. For example, entering cat updates.txt returns everything in the updates.txt file.

### **head**
The head command displays just the beginning of a file, by default 10 lines. The head command can be useful when you want to know the basic contents of a file but don’t need the full contents. Entering head updates.txt returns only the first 10 lines of the updates.txt file.

**Pro Tip**: If you want to change the number of lines returned by head, you can specify the number of lines by including -n. For example, if you only want to display the first five lines of the updates.txt file, enter head -n 5 updates.txt.

### **tail**
The tail command does the opposite of head. This command can be used to display just the end of a file, by default 10 lines. Entering tail updates.txt returns only the last 10 lines of the updates.txt file.

**Pro Tip**: You can use tail to read the most recent information in a log file.

### **less**
The less command returns the content of a file one page at a time. For example, entering less updates.txt changes the terminal window to display the contents of updates.txt one page at a time. This allows you to easily move forward and backward through the content. 
Once you’ve accessed your content with the less command, you can use several keyboard controls to move through the file:
- Space bar: Move forward one page
- b: Move back one page
- Down arrow: Move forward one line
- Up arrow: Move back one line
- q: Quit and return to the previous terminal window
## Filtering for information
## grep
The **grep** command searches a specified file and returns all lines in the file containing a specified string or text. The **grep** command commonly takes two arguments: a specific string to search for and a specific file to search through.
For example, entering **grep** **OS** **updates**.**txt** returns all lines containing **OS** in the **updates**.**txt** file. In this example, **OS** is the specific string to search for, and **updates.txt** is the specific file to search through.
Let’s look at another example: **grep error time_logs.txt**. Here grep is used to search for the text pattern. **error** is the term you are looking for in the **time_logs.txt** file. When you run this command, grep will scan the time_logs.txt file and print only the lines containing the word **error**.

## Piping
The pipe command is accessed using the pipe character (|). **Piping** sends the standard output of one command as standard input to another command for further processing. As a reminder, **standard output** is information returned by the OS through the shell, and **standard input** is information received by the OS via the command line. 
The pipe character (|) is located in various places on a keyboard. On many keyboards, it’s located on the same key as the backslash character (\). On some keyboards, the | can look different and have a small space through the middle of the line. If you can’t find the |, search online for its location on your particular keyboard.
When used with grep, the pipe can help you find directories and files containing a specific word in their names. For example, ls /home/analyst/reports | grep users returns the file and directory names in the reports directory that contain users. Before the pipe, ls indicates to list the names of the files and directories in reports. Then, it sends this output to the command after the pipe. In this case, grep users returns all of the file or directory names containing users from the input it received.
**Note:** Piping is a general form of redirection in Linux and can be used for multiple tasks other than filtering. You can think of piping as a general tool that you can use whenever you want the output of one command to become the input of another command.

## find
The find command searches for directories and files that meet specified criteria. There’s a wide range of criteria that can be specified with find. For example, you can search for files and directories that
- Contain a specific string in the name,
- Are a certain file size, or
- Were last modified within a certain time frame.
When using find, the first argument after find indicates where to start searching. For example, entering find /home/analyst/projects searches for everything starting at the projects directory.
After this first argument, you need to indicate your criteria for the search. If you don’t include a specific search criteria with your second argument, your search will likely return a lot of directories and files. 
Specifying criteria involves options. **Options** modify the behavior of a command and commonly begin with a hyphen (-). 

### **-name and -iname**

One key criteria analysts might use with find is to find file or directory names that contain a specific string. The specific string you’re searching for must be entered in quotes after the -name or -iname options. The difference between these two options is that -name is case-sensitive, and -iname is not. 

For example, you might want to find all files in the projects directory that contain the word “log” in the file name. To do this, you’d enter find /home/analyst/projects -name "*log*". You could also enter find /home/analyst/projects -iname "*log*".

In these examples, the output would be all files in the projects directory that contain log surrounded by zero or more characters. The "*log*" portion of the command is the search criteria that indicates to search for the string “log”. When -name is the option, files with names that include Log or LOG, for example, wouldn’t be returned because this option is case-sensitive. However, they would be returned when -iname is the option.

**Note**: An asterisk (*) is used as a wildcard to represent zero or more unknown characters.

### **-mtime**

Security analysts might also use find to find files or directories last modified within a certain time frame. The -mtime option can be used for this search. For example, entering find /home/analyst/projects -mtime -3 returns all files and directories in the projects directory that have been modified within the past three days. 

The -mtime option search is based on days, so entering -mtime +1 indicates all files or directories last modified more than one day ago, and entering -mtime -1 indicates all files or directories last modified less than one day ago. 

**Note:** The option -mmin can be used instead of -mtime if you want to base the search on minutes rather than days.

## Installing and update

`sudo apt update && upgrade`

- we can also use the tool [pimpmykali](https://github.com/Dewalt-arch/pimpmykali) to update and setup our kali instance

> *when installing tools, install it to the opt folder*

## Integrated Linux support
Linux also has several commands that you can use for support.
### man
The man command displays information on other commands and how they work. It’s short for “manual.” To search for information on a command, enter the command after man. For example, entering man chown returns detailed information about chown, including the various options you can use with it. The output of the man command is also called a “man page.”
>_You can output more information one line at a time by pressing the **ENTER** key or output the next page of the manual by pressing the space bar._

### apropos
The apropos command searches the man page descriptions for a specified string. Man pages can be lengthy and difficult to search through if you’re looking for a specific keyword. To use apropos, enter the keyword after apropos. 
You can also include the -a option to search for multiple words. For example, entering apropos -a graph editor outputs man pages that contain both the words “graph" and "editor” in their descriptions.
### whatis
The whatis command displays a description of a command on a single line. For example, entering whatis nano outputs the description of nano. This command is useful when you don't need a detailed description, just a general idea of the command. This might be as a reminder. Or, it might be after you discover a new command through a colleague or online resource and want to know more.

## Shell operators

| Symbol / Operator | Description                                                                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| &                 | This operator allows you to run commands in the background of your terminal.                                                                     |
| &&                | This operator allows you to combine multiple commands together in one line of your terminal.                                                     |
| >                 | This operator is a redirector - meaning that we can take the output from a command (such as using cat to output a file) and direct it elsewhere. |
| >>                | This operator does the same function of the `>` operator but appends the output rather than replacing (meaning nothing is overwritten).          |

Let's cover these in a bit more detail.
![[command-line-cheat-sheet-large01.avif]]![[command-line-cheat-sheet-large02.avif]]
