# P-Minecraft

Quick deployment of a docker-based personal Minecraft server

The project is based on [itzg/docker-minecraft-server] - docker image that provides a Minecraft Server that will automatically download selected version at startup

## Installation

his script is meant for quick & easy install via:  

`curl -sSL https://bit.ly/p-minecraft-install | sh`  
or:  
`wget -qO- https://bit.ly/p-minecraft-install | sh`   


To reinstall, or specify additional script execution arguments, you need to add the `-s -` key to `sh`, for example:

`curl -sSL https://bit.ly/p-minecraft-install | sh -s - --force`  
or:  
`wget -qO- https://bit.ly/p-minecraft-install | sh -s - -f`  

### P-Minecraft Server Installer CLI Overview

You can also see this information by running  
`curl -sSL https://bit.ly/p-minecraft-install | sh -s - --help`  
or  
`wget -qO- https://bit.ly/p-minecraft-install | sh -s - -h`  
from the command line.

```text
Installing a docker-based personal Minecraft server

Usage:
  install.sh [-d <arg>...] [-q] [--mc-mode <mode>...] [options]
  install.sh -h|--help

Options:
  -h, --help
        Display this help and exit.
  -q, --quiet
        This tries its best to reduce output by suppressing the script's own
        messages and passing "quiet" arguments to tools that support them.
  -f, --force
        Reinstalling the P-Minecraft service if it is already installed.
  -d, --dest DEST
        P-Minecraft installation directory, default '\${HOME}/p-minecraft'.

  -ss, --services-subnet SERVICES_SUBNET
        The IPv4 network range for P-Minecraft modules, default '10.45.0.0/24'.
  -ml, --mc-local-ip MC_LOCAL_IP
        IPv4 local address of the Minecraft server, by default '10.45.0.3'.
  -mp, --mc-port MC_PORT
        Minecraft server port for connecting clients, by default '25565'.
  -mw, --mc-whitelist MC_WHITELIST
        List of allowed players on the server, separated by commas.
  -mo, --mc-ops MC_OPS
        List of operators on the server, separated by commas.
  -mi, --mc-init-memory MC_INIT_MEMORY
        Initial memory allocated to the server, by default '4G'.
  -mm, --max-memory MC_MAX_MEMORY
        Maximum memory allocated to the server, by default '8G'.
  -m, --mc-mode MC_MODE
        Minecraft server mode, by default 'survival'.
        Possible values : creative, survival, adventure, spectator
  -md, --mc-difficulty MC_DIFFICULTY
        Minecraft server difficulty, by default 'easy'.
        Possible values : peaceful, easy, normal, hard

  -wf, --without_firewall
        Without installing 'firewalld' and opening ports.
       
```
