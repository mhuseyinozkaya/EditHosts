# EditHosts

Just edits hosts file. I wrote this script to make it easier to edit DNS resolutions for Hackviser, HackTheBox, etc. 

## Usage

First if the script was not executable, type this command in your shell

```bash
chmod +x edithosts.sh
```

This scripts needs privilege permission to run (use sudo), and if you want to use the script easily, you can run the script with the '-i' argument to install the script system-wide

```bash
sudo ./edithosts -i # This installs script to /usr/local/lib/EditHosts directory
```

```bash
# Usage :
sudo edithosts -tr # Tests hosts and removes unreachable hosts from hosts file
sudo edithosts 10.10.10.10 # Finds hostnames from the specified IP address, if finds then writes to hosts file
sudo edithosts 10.0.0.10 my-cool-hostname.me # This writes IP and hostname to hosts file
```

The script replaces old hosts with new hosts if the hostnames are already exist in the file