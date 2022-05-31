#!/bin/sh -e
#
# P-Minecraft installation script.
#
# Repository: https://github.com/pprometey/p-minecraft
#
# This script is meant for quick & easy install via:
#   'curl -sSL https://bit.ly/p-minecraft-install | sh'
# or:
#   'wget -qO- https://bit.ly/p-minecraft-install | sh'
#
# Arguments (use `... | sh -s - ARGUMENTS`)
#
# -h: Show help message.
# -q: reduce script's output
# -f: force over-write even if 'p-minecraft' already installed
# -d DESTDIR: change destination directory
#
# Copyright (c) 2018 Alexei Chernyavski. Released under the MIT License

REPO_URL="https://github.com/pprometey/p-minecraft.git"
PROJECT_NAME="p-minecraft"
DEFAULT_DEST="${HOME}/${PROJECT_NAME}"
ENV_FILENAME=".env"
DEST="" # -d|--dest _
FORCE="" # -f|--force
QUIET="" # -q|--quiet
TEMP_DIR=

SERVICES_SUBNET="10.45.0.0/24" # -ss|--services-subnet _

MC_LOCAL_IP="10.45.0.3" # -ml|--mc-local-ip _
MC_PORT="25565" # -mp|--mc-port _
MC_WHITELIST= # -mw|--mc-whitelist _
MC_OPS= # -mo|--mc-ops _
MC_MODE="survival" # -m|--mc-mode _
MC_INIT_MEMORY="4G" # -mi|--mc-init-memory _
MAX_MEMORY="8G" # -mm|--max-memory _
MC_DIFFICULTY="easy" # -md|--mc-difficulty _

WITH_FIREWALL="true" # -wf|--without_firewall

MC_VERSION="LATEST"
MC_PVP="false"
MC_FORCE_GAMEMODE="false"
SPAWN_PROTECTION=0

# -------------------------------------------------------------------------------

# print a message to stdout unless '-q' passed to script
info() {
  if [ -z "$QUIET" ] ; then
    echo "$@"
  fi
}

# print a message to stderr and exit with error code
die() {
  echo "$@" >&2
  exit 1
}

# print a separator
print_separator() {
  info ""
  info "----------------------------------------------------------------"
  info ""
}

to_lowercase() {
  echo $1 | sed 's/./\L&/g'
}

to_uppercase() {
  echo $1 | sed 's/./\U&/g'
}

generate_password() {
  echo $(tr -cd '[:alnum:]' < /dev/urandom | fold -w30 | head -n1)
}

get_env_value() {
  grep "${1}" ${2} | cut -d'=' -f2
}

get_subnet_prefix() {
  echo ${1%.*}
}

# creates a temporary directory, which will be cleaned up automatically
# when the script finishes
make_temp_dir() {
  TEMP_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t ${PROJECT_NAME})"
}

# cleanup the temporary directory if it's been created.  called automatically
# when the script exits.
cleanup_temp_dir() {
  if [ -n "$TEMP_DIR" ] ; then
    rm -rf "$TEMP_DIR"
    TEMP_DIR=
  fi
}

# get in which directory this script is run
get_run_path() {
  readlink -f $0 | xargs dirname
}

# -------------------------------------------------------------------------------

# Adds a 'sudo' prefix if sudo is available to execute the given command
# If not, the given command is run as is
# When requesting root permission, always show the command and never re-use cached credentials.
sudocmd() {
  reason="$1"; shift
  if command -v sudo >/dev/null; then
    echo "Running command as root for $reason."
    echo "     $@"
    sudo "$@"
  else
    "$@"
  fi
}

# Check whether the given command exists
has_cmd() {
  command -v "$1" > /dev/null 2>&1
}

# Check whether 'sudo' command exists
has_sudo() {
  has_cmd sudo
}

# Check whether 'perl' command exists
has_perl() {
  has_cmd perl
}

# Check whether 'wget' command exists
has_wget() {
  has_cmd wget
}

# Check whether 'curl' command exists
has_curl() {
  has_cmd curl
}

# Check whether 'lsb_release' command exists
has_lsb_release() {
  has_cmd lsb_release
}

# Check whether 'getconf' command exists
has_getconf() {
  has_cmd getconf
}

has_apt_get() {
  has_cmd apt-get
}

has_docker() {
  has_cmd docker
}

has_gnupg() {
  has_cmd gnupg
}

has_git() {
  has_cmd git
}

has_unzip() {
  has_cmd unzip
}

has_timedatectl() {
  has_cmd timedatectl
}

has_systemctl() {
  has_cmd systemctl
}

has_firewalld() {
  has_cmd firewalld
}

has_systemd_detect_virt() {
  has_cmd systemd-detect-virt
}

has_dialog() {
  has_cmd dialog
}

# -------------------------------------------------------------------------------

get_public_ip() {
  if ! has_curl && ! has_wget ; then
    if ! try_install_pkgs curl wget; then
      die "Neither wget nor curl is available, please install one to continue."
    fi
  fi
  public_ip=$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || \
    curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")

  if ! echo $public_ip | grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
    die "Could not determine public IP address."
  fi
}


# Check for 'curl' or 'wget' and attempt to install 'curl' if neither found,
# or fail the script if that is not possible.
check_dl_tools() {
  if ! has_curl && ! has_wget ; then
    if ! try_install_pkgs curl wget; then
      die "Neither wget nor curl is available, please install one to continue."
    fi
  fi
}

# Download a URL to file using 'curl' or 'wget'.
dl_to_file() {
  check_dl_tools
  if ! wget ${QUIET:+-q} "-O$2" "$1"; then
    info "wget download failed: $1, try download with curl..."
    if ! curl ${QUIET:+-sS} -L -o "$2" "$1"; then
      die "curl download failed: $1"
    fi
  fi
}

dl_to_stdout() {
  if ! has_curl ; then
    if ! try_install_pkgs curl ; then
      die "curl is not available, please install one to continue."
    fi
  fi
  if ! curl -fsSL "$1" 2>/dev/null; then
    die "curl download failed: $1"
  fi
}

unzip_to_dir() {
  if ! has_unzip ; then
    if ! try_install_pkgs unzip ; then
      die "unzip is not available, please install one to continue."
    fi
  fi
  if ! unzip ${QUIET:+-q} -o "$1" -d "$2" ; then
    die "unzip failed: $1 to $2"
  fi
}

# -------------------------------------------------------------------------------

show_help() {
  help_file=${TEMP_DIR}/.help
cat << EOF > $help_file
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
  -mm, --max-memory MAX_MEMORY
        Maximum memory allocated to the server, by default '8G'.
  -m, --mc-mode MC_MODE
        Minecraft server mode, by default 'survival'.
        Possible values : creative, survival, adventure, spectator
  -md, --mc-difficulty MC_DIFFICULTY
        Minecraft server difficulty, by default 'easy'.
        Possible values : peaceful, easy, normal, hard

  -wf, --without_firewall
        Without installing 'firewalld' and opening ports.

EOF

cat $help_file | more
}

show_error_invalid_argument_value() {
  echo "For argument $1, value $2 is invalid" >&2
  exit 1
}

validate_timezone() {
  timedatectl list-timezones --no-pager | grep -q "$1"
}

set_timezone() {
  if has_timedatectl ; then
    if validate_timezone $1 ; then
      TIME_ZONE=$1
    else
      return 1
    fi
  else
    die "timedatectl not available."
  fi
}

validate_port() {
 if echo "$1" | grep -Eq '^[0-9]{1,5}$'; then
     if [ $1 -gt 1 ] && [ $1 -lt 65535 ] ; then
       return 0
     else
       return 1
     fi
 else
   return 1
 fi
}

set_mc_port() {
  if validate_port $1 ; then
    MC_PORT=$1
  else
    return 1
  fi
}

validate_subnet() {
  echo $1 | grep -Eq '(^[0-2][0-5]{1,2}?\.|^[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?\/|[3-9][0-9]?\/)([1-9]|[1-2][\d]|3[0-2])$'
}

set_service_subnet() {
  if validate_subnet $1 ; then
    SERVICE_SUBNET=$1
  else
    return 1
  fi
}

validate_ipv4() {
  echo $1 | grep -Eq '(^[0-2][0-5]{1,2}?\.|^[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?$|[3-9][0-9]?$)'
}

set_mc_local_ip() {
  if validate_ipv4 $1 ; then
    MC_LOCAL_IP=$1
  else
    return 1
  fi
}

validate_mc_mode() {
 echo $1 | grep -Eq '^(creative|survival|adventure|spectator)$'
}

set_mc_mode() {
  if validate_mc_mode $1 ; then
    MC_MODE=$1
  else
    return 1
  fi
}

validate_mc_difficulty() {
 echo $1 | grep -Eq '^(peaceful|easy|normal|hard)$'
}

set_mc_difficulty() {
  if validate_mc_mode $1 ; then
    MC_DIFFICULTY=$1
  else
    return 1
  fi
}

validate_domain_name() {
  echo "$1" | grep -Eq '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
}

set_mc_whitelist() {
  MC_WHITELIST=$1
}

set_mc_ops() {
  MC_OPS=$1
}

set_mc_init_memory() {
  MC_INIT_MEMORY=$1
}

set_mc_max_memory() {
  MAX_MEMORY=$1
}

# -------------------------------------------------------------------------------

# Install packages using apt-get
apt_get_install_pkgs() {
  missing=
  for pkg in $*; do
    if ! dpkg -s $pkg 2>/dev/null | grep '^Status:.*installed' >/dev/null; then
      missing="$missing $pkg"
    fi
  done
  if [ "$missing" = "" ]; then
    info "Already installed!"
  elif ! sudocmd "install required system dependencies" apt-get install -y ${QUIET:+-qq}$missing; then
    die "\nInstalling apt packages failed.  Please run 'apt-get update' and try again."
  fi
}

# Attempt to install packages using whichever of apt-get, dnf, yum, or apk is
# available.
try_install_pkgs() {
  if has_apt_get ; then
    apt_get_install_pkgs "$@"
  # elif has_dnf ; then
  #   dnf_install_pkgs "$@"
  # elif has_yum ; then
  #   yum_install_pkgs "$@"
  # elif has_apk ; then
  #   apk_install_pkgs "$@"
  else
    return 1
  fi
}

# -------------------------------------------------------------------------------

# determines the the CPU's instruction set
get_isa() {
  if arch | grep -Eq 'armv[78]l?' ; then
    echo arm
  elif arch | grep -q aarch64 ; then
    echo aarch64
  else
    echo x86
  fi
}

# determines 64- or 32-bit architecture
# if getconf is available, it will return the arch of the OS, as desired
# if not, it will use uname to get the arch of the CPU, though the installed
# OS could be 32-bits on a 64-bit CPU
get_arch() {
  if has_getconf ; then
    if getconf LONG_BIT | grep -q 64 ; then
      echo 64
    else
      echo 32
    fi
  else
    case "$(uname -m)" in
      *64)
        echo 64
        ;;
      *)
        echo 32
        ;;
    esac
  fi
}

# exits with code 0 if arm ISA is detected as described above
is_arm() {
  test "$(get_isa)" = arm
}

# exits with code 0 if aarch64 ISA is detected as described above
is_aarch64() {
  test "$(get_isa)" = aarch64
}

# exits with code 0 if a x86_64-bit architecture is detected as described above
is_x86_64() {
  test "$(get_arch)" = 64 -a "$(get_isa)" = "x86"
}

# Attempts to determine the running Linux distribution.
# Prints "DISTRO;VERSION" (distribution name and version)"."
distro_info() {
  parse_lsb() {
    lsb_release -a 2> /dev/null | perl -ne "$1"
  }

  try_lsb() {
    if has_lsb_release ; then
      TL_DIST="$(parse_lsb 'if(/Distributor ID:\s+([^ ]+)/) { print "\L$1"; }')"
      TL_VERSION="$(parse_lsb 'if(/Release:\s+([^ ]+)/) { print "\L$1"; }')"
      echo "$TL_DIST;$TL_VERSION"
    else
      return 1
    fi
  }

  try_release() {
    parse_release() {
      perl -ne "$1" /etc/*release 2>/dev/null
    }

    parse_release_id() {
      parse_release 'if(/^(DISTRIB_)?ID\s*=\s*"?([^"]+)/) { print "\L$2"; exit 0; }'
    }

    parse_release_version() {
      parse_release 'if(/^(DISTRIB_RELEASE|VERSION_ID)\s*=\s*"?([^"]+)/) { print $2; exit 0; }'
    }

    TR_RELEASE="$(parse_release_id);$(parse_release_version)"

    if [ ";" = "$TR_RELEASE" ] ; then
      if [ -e /etc/arch-release ] ; then
        # /etc/arch-release exists but is often empty
        echo "arch;"
      elif [ -e /etc/centos-release ] && grep -q "\<6\>" /etc/centos-release ; then
        # /etc/centos-release has a non-standard format before version 7
        echo "centos;6"
      else
        return 1
      fi
    else
      echo "$TR_RELEASE"
    fi
  }

  try_issue() {
    case "$(cat /etc/issue 2>/dev/null)" in
      "Arch Linux"*)
        echo "arch;" # n.b. Version is not available in /etc/issue on Arch
        ;;
      "Ubuntu"*)
        echo "ubuntu;$(perl -ne 'if(/Ubuntu (\d+\.\d+)/) { print $1; }' < /etc/issue)"
        ;;
      "Debian"*)
        echo "debian;$(perl -ne 'if(/Debian GNU\/Linux (\d+(\.\d+)?)/) { print $1; }' < /etc/issue)"
        ;;
      *"SUSE"*)
        echo "suse;$(perl -ne 'if(/SUSE\b.* (\d+\.\d+)/) { print $1; }' < /etc/issue)"
        ;;
      *"NixOS"*)
        echo "nixos;$(perl -ne 'if(/NixOS (\d+\.\d+)/) { print $1; }' < /etc/issue)"
        ;;
      "CentOS"*)
        echo "centos;$(perl -ne 'if(/^CentOS release (\d+)\./) { print $1; }' < /etc/issue)"
        ;;
      *)
    esac
    # others do not output useful info in issue, return empty
  }

  try_lsb || try_release || try_issue
}

get_distro_name() {
  echo "$(distro_info | cut -d';' -f1)"
}

# -------------------------------------------------------------------------------


apt_open_ports() {
  if [ $WITH_FIREWALL = "true" ]; then
    if ! sudocmd "open tcp port $MC_PORT" firewall-cmd --permanent --zone=public --add-port=$MC_PORT/tcp ${QUIET:+-q}; then
      die "\nOpening port for Minecraft failed."
    fi

    if ! sudocmd "restart firewall" firewall-cmd --reload ${QUIET:+-q}; then
      die "\nRestarting firewall failed."
    fi
  fi
}

apt_close_ports() {
  if ! sudocmd "close tcp port $2" firewall-cmd --permanent --zone=public --remove-port=$2/tcp ${QUIET:+-q}; then
    die "\nClosing port failed. Please run 'sudo firewall-cmd --permanent --zone=public --add-port=$2/tcp' and try again."
  fi

  if ! sudocmd "restart firewall" firewall-cmd --reload ${QUIET:+-q}; then
    die "\nRestarting firewall failed. Please run 'sudo firewall-cmd --reload' and try again."
  fi
}

set_blank_dest() {
    [ "${DEST}" = "" ] && DEST=$DEFAULT_DEST
}

apt_clone_repository() {
  if ! has_git ; then
    info "Installing git..."
    info ""
    apt_get_install_pkgs git
  fi

  set_blank_dest

  if [ -d ${DEST} ]; then
    die "\nDestination folder is exist. Remove folder and try again. \n'rm -rf ${DEST}'"
  fi

  info "Cloning repository..."
  info ""
  if ! git clone ${REPO_URL} ${DEST} ${QUIET:+-q}; then
    die "\nCloning repository failed. "
  fi
}

create_env_file() {
  if [ -d ${DEST} ]; then
cat << EOF > ${DEST}/${ENV_FILENAME}
TIME_ZONE=${TIME_ZONE}
SERVICES_SUBNET=${SERVICES_SUBNET}
MC_LOCAL_IP=${MC_LOCAL_IP}
MC_PORT=${MC_PORT}
MC_WHITELIST=${MC_WHITELIST}
MC_OPS=${MC_OPS}
MC_MODE=${MC_MODE}
MC_INIT_MEMORY=${MC_INIT_MEMORY}
MAX_MEMORY=${MAX_MEMORY}
MC_DIFFICULTY=${MC_DIFFICULTY}
MC_PVP=${MC_PVP}
MC_VERSION=${MC_VERSION}
MC_FORCE_GAMEMODE=${MC_FORCE_GAMEMODE}
SPAWN_PROTECTION=${SPAWN_PROTECTION}
EOF
fi
}


run_services() {
  if [ -d ${DEST} ]; then
    info "Running services..."
    info ""
    create_env_file
    if sudocmd "run services" docker compose -f "${DEST}/docker-compose.yml" up -d ${QUIET:+--quiet-pull}; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

# Download packages information from all configured sources
apt_update_packges_info() {
  if ! sudocmd "update packages list" apt-get update -y ${QUIET:+-qq}; then
    die "\nUpdating package list failed.  Please run 'apt-get update' and try again."
  fi
}

is_docker_active() {
  if has_docker; then
    if systemctl show --property ActiveState docker | grep -q 'ActiveState=active'; then
      return 0
    else
      return 1
    fi
  else
    return 1
  fi
}

apt_docker_install() {
  add_docker_repository() {
    add_docker_gpg_key() {
      save_docker_gpg_key() {
        if ! sudocmd "add Docker’s official GPG key" gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg ; then
          die "\nAdding Docker’s official GPG key failed."
        fi
      }

      dl_to_stdout "https://download.docker.com/linux/$(get_distro_name)/gpg" | save_docker_gpg_key
    }

    add_docker_source_list_file() {
      save_docker_source_list() {
        if ! sudocmd "add Docker repository" tee /etc/apt/sources.list.d/docker.list > /dev/null ; then
          die "\nAdding Docker repository failed."
        fi
      }
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
https://download.docker.com/linux/$(get_distro_name) $(lsb_release -cs) stable" | save_docker_source_list
    }

    [ ! -e "/usr/share/keyrings/docker-archive-keyring.gpg" ] && add_docker_gpg_key
    [ ! -e "/etc/apt/sources.list.d/docker.list" ] && add_docker_source_list_file
  }

  if ! has_docker ; then
    info ""
    info "Installing docker..."
    info ""
    add_docker_repository
    apt_update_packges_info
    apt_get_install_pkgs docker-ce docker-ce-cli containerd.io docker-compose-plugin

    if  ! is_docker_active ; then
      if ! sudocmd "activate docker" systemctl start docker ; then
        die "\nStarting docker failed. Please run 'sudo systemctl start docker' and try again."
      fi
    fi
  fi
}

apt_firewalld_install() {
  is_enabled_firewalld() {
    if [ "$(systemctl is-enabled firewalld)" = "enabled" ]; then
      return 0
    else
      return 1
    fi
  }

  is_active_firewalld() {
    if [ "$(systemctl is-active firewalld)" = "active" ]; then
      return 0
    else
      return 1
    fi
  }

  if [ $WITH_FIREWALL = "true" ]; then
    if ! has_firewalld; then
      info ""
      info "Installing firewalld..."
      info ""
      apt_update_packges_info
      apt_get_install_pkgs firewalld
    fi

    if ! is_enabled_firewalld; then
      info ""
      info "Enabling firewalld..."
      info ""
      if ! sudocmd "enable firewalld" systemctl enable firewalld ${QUIET:+-q}; then
        die "\nEnabling firewalld failed. Please run 'sudo systemctl enable firewalld' and try again."
      fi
    fi

    if ! is_active_firewalld; then
      info "Starting firewalld..."
      info ""
      systemctl start firewalld
      if ! sudocmd "start firewalld" systemctl start firewalld ${QUIET:+-q}; then
        die "\nStarting firewalld failed. Please run 'sudo systemctl start firewalld' and try again."
      fi
    fi
  fi
}

apt_upgrade() {
  if ! sudocmd "upgrade OS" apt-get upgrade -y ${QUIET:+-qq}; then
    die "\nUpdating package list failed.  Please run 'apt-get upgrade' and try again."
  fi
}

# Install dependencies for distros that use Apt
apt_install_dependencies() {
    if ! has_curl  || \
       ! has_gnupg  || \
       ! has_lsb_release  || \
       ! has_git  || \
       ! has_unzip ; then
      info ""
      info "Installing dependencies..."
      info ""
      apt_update_packges_info
      apt_get_install_pkgs dialog
      apt_upgrade
      apt_get_install_pkgs ca-certificates curl gnupg lsb-release git unzip dnsutils net-tools nano screen
    fi
}

do_apt_install() {
  install_dependencies() {
    apt_install_dependencies
    apt_firewalld_install
    apt_docker_install
  }

  install_sevices() {
    print_separator
    install_dependencies
    print_separator
    apt_clone_repository
    print_separator
    run_services
    print_separator
    apt_open_ports
  }

  if is_x86_64 || is_aarch64 ; then
    install_sevices
  # elif is_arm ; then
    #install_dependencies
  else
    die "Sorry, currently only 64-bit (x86_64, aarch64) Linux binary is available."
  fi
}

# Attempt to install on a Linux distribution
do_distro() {
  if ! has_perl; then
    if ! try_install_pkgs perl; then
      #TODO: remove dependence on 'perl', which is not installed by default
      #on some distributions (Fedora and RHEL, in particular).
      die "This script requires 'perl', please install it to continue."
    fi
  fi

  IFS=";" read -r DISTRO VERSION <<GETDISTRO
$(distro_info)
GETDISTRO

  if [ -n "$DISTRO" ] ; then
    info ""
    info "Detected Linux distribution: $DISTRO"
  fi

  case "$DISTRO" in
    ubuntu|linuxmint|elementary|neon|pop)
      do_apt_install "$VERSION"
      ;;
    debian|kali|raspbian|mx)
      do_apt_install "$VERSION"
      ;;
    fedora)
      # do_fedora_install "$VERSION"
      ;;
    centos|rhel|redhatenterpriseserver)
      # do_centos_install "$VERSION"
      ;;
    alpine)
      # do_alpine_install "$VERSION"
      ;;
    *)
      # do_sloppy_install
  esac
}

linux_can_install() {
  if has_systemd_detect_virt; then
    if [ "$( systemd-detect-virt )" = "openvz" ]; then
        die "OpenVZ virtualization is not supported"
    fi
  fi
}

# Determine operating system and attempt to install.
do_os() {
  case "$(uname)" in
    "Linux")
      linux_can_install
      do_distro
      ;;
    # "Darwin")
    #   do_osx_install
    #   ;;
    *)
      die "Sorry, this installer does not support your operating system: $(uname)."
  esac
}

has_installed() {
  if ! has_sudo; then
    die "This script requires 'sudo' installed."
  fi
  if has_docker && is_docker_active; then
      if sudocmd "get a list of running docker containers" docker ps | grep -q 'wg-access-server'; then
        return 0
      else
        return 1
      fi
  else
    return 1
  fi
}

get_installed_path() {
  location=$(dirname $(sudo docker container inspect $1 --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}'))
  if [ ! -d "$location" ]; then
    die "Error getting installation path"
  fi
  echo $location
}

remove_old_installation() {
  info "Removing old installation..."
  location=$(get_installed_path "minecraft")
  # Close ports
  env_file="$location/$ENV_FILENAME"

  # Close ports
  if [ -f $env_file ]; then
    mc_port=$(get_env_value "MC_PORT" $env_file)
    apt_close_ports $mc_port
  fi

  # Remove running containers
  if ! sudocmd "stop running docker service containers" docker compose -f "${location}/docker-compose.yml" down -v; then
    die "n\Error removing old docker container, please remove them manually, run \n'sudo docker compose -f ${location}/docker-compose.yml down -v"
  fi

  # Remove installation folder
 if ! sudocmd "remove old installation folder" rm -rf $location; then
    die "\nError removing old installation folder, please remove it manually, run \n'rm -rf $location'"
  fi
}

check_installed() {
  if has_installed; then
    info "P-Minecraft is already installed."

    if [ "$FORCE" = "true" ] ; then
      print_separator
      info "Forcing reinstallation."
      remove_old_installation
    else
      die "Run script with --force (or -f) option to reinstall. \n 'curl -sSL https://bit.ly/p-minecraft-install | sh -s - -f'"
    fi
  else
    info "P-Minecraft is not installed."
  fi
}

validate_params() {
  subnet_prefix=$(get_subnet_prefix "$SERVICES_SUBNET")
  mc_prefix=$(get_subnet_prefix "$MC_LOCAL_IP")

  if [ "$subnet_prefix" != "$mc_prefix" ]; then
    die "The specified local address ${MC_LOCAL_IP} does not belong to the specified network ${SERVICES_SUBNET}"
  fi
}

trap cleanup_temp_dir EXIT

make_temp_dir

if echo $@ | grep -qw -e "\-\-help" -e "\-h"; then
  show_help
  exit 0
fi

while [ $# -gt 0 ]; do
  case "$1" in
    -q|--quiet)
      # This tries its best to reduce output by suppressing the script's own
      # messages and passing "quiet" arguments to tools that support them.
      QUIET="true"
      shift
      ;;
    -f|--force)
      FORCE="true"
      shift
      ;;
    -d|--dest)
      DEST="$2"
      shift 2
      ;;
    -tz|--time-zone)
      if set_timezone "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -ss|--services-subnet)
      if set_service_subnet "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -ml|--mc-local-ip)
      if set_mc_local_ip "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -mp|--mc-port)
      if set_mc_port $2 ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -mw|--mc-whitelist)
      if set_mc_whitelist "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -mo|--mc-ops)
      if set_mc_ops "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -m|--mc-mode)
      if set_mc_mode "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -mi|--mc-init-memory)
      if set_mc_init_memory "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -mm|--max-memory)
      if set_mc_max_memory "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    -md|--mc-difficulty)
      if set_mc_difficulty "$2" ; then
        shift 2
      else
        show_error_invalid_argument_value "$1" "$2"
      fi
      ;;
    --wf|--without_firewall)
      WITH_FIREWALL="false"
      shift
      ;;
    *)
      echo "Invalid argument: $1" >&2
      echo "Run '$0 --help' for more information." >&2
      exit 1
      ;;
  esac
done

validate_params
check_installed
do_os
