- `lsb_release -a`  - distro info
- `printenv` - list all environment variables

- `where` - Reports all known instances of a command.  It could be an executable in the PATH environment variable, an alias, or a shell builtin.
- `whereis` - Locate the binary, source, and manual page files for a command.
- `which` - Locate a program in the user's path.
- `whatis` - Display one-line descriptions from manual pages.
- `locate` - find files by name, quickly
- `stat`: Displays file or file system status, providing detailed information. 
    - `stat <filename>`
    - `stat -f <path_to_filesystem_mount_point>`
- `file` : show file information 

- `lsblk` - disk/partition info
- `df` - shows storage info
- `lshw`: List Hardware. Provides detailed information about the machine's hardware configuration. [https://linux.die.net/man/1/lshw](https://linux.die.net/man/1/lshw)
    - `sudo lshw`
    - `sudo lshw -c <class>` (e.g., `sudo lshw -c cpu`, `sudo lshw -c memory`, `sudo lshw -c network`, `sudo lshw -c disk`)
- `lsof` (List Open Files): Lists information about files opened by processes. [https://linux.die.net/man/8/lsof](https://linux.die.net/man/8/lsof)
    - `lsof`
    - `sudo lsof -i :<port_number>` (e.g., `sudo lsof -i :22`)

- `top` - display linux processes
- `journalctl` - view logs
- 	- `journalctl -u [service]` - view logs of a specific service
- 	- `journalctl -fu [service]`  - follow mode. (live)'
- `rsync` - transfer and sync files

- `watch`: Executes a program periodically, showing its output and errors. [https://linux.die.net/man/1/watch](https://linux.die.net/man/1/watch)
    - `watch [options] <command>` (e.g., `watch -n 0.5 nvidia-smi`)

- `systemd-analyze blame`: Prints a list of all running units, ordered by the time they took to initialize during boot. [https://www.freedesktop.org/software/systemd/man/systemd-analyze.html](https://www.freedesktop.org/software/systemd/man/systemd-analyze.html)
    - `systemd-analyze blame`
- `systemd-analyze critical-chain`: Prints a tree of the time-critical chain of units during boot. [https://www.freedesktop.org/software/systemd/man/systemd-analyze.html](https://www.freedesktop.org/software/systemd/man/systemd-analyze.html)
    - `systemd-analyze critical-chain [unit_name...]`

