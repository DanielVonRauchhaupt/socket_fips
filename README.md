# Bachelor Thesis

# Introduction
This is the repository for the bachelor thesis:  "Design and Implementation of a new Inter-Process Communication Architecture for Log-based HIDS for 100 GbE Environments".
The following, will provide an overview over the contents of the repository and the measurement setup.
More detailed information on background, design, implementation and measurements can be found in the thesis.

# Directories
- `experiments/` Measurement data and jupyter notebooks for data visualization
- `external/` External libraries used for building
- `latex/` Latex files for thesis and presentation slides
- `src/` Source files for implementation, scripts and configuration

# External Dependencies
These libraries are required to be installed on the system, in order for cmake to build
successfully. 
- [liburing](https://github.com/axboe/liburing) version (0.7-3)
- [hyperscan](https://github.com/intel/hyperscan) version (5.4.0-2) (and its [dependencies](https://intel.github.io/hyperscan/dev-reference/getting_started.html#)) 

On Debian, they can be installed via: `apt install liburing-dev libhyperscan-dev` 

# Build
When the repository has been cloned for the first time, it is necessary to load the submodules in the external folder first. 
This can be done with `git submodule update --init --recursive`.
The project can then be built using `./cmake.sh`, once all external dependencies are satisfied. The binaries will be located in `build/`

# Experimental Setup

The experiments 1-4 described in the thesis, were conducted using two machines. Machine 1 is the device under test (DUT)
running Fail2ban or Simplefail2ban. Machine 2 is the traffic generator (attacker in the Denial-of-Service scenario).

# Traffic Generator Setup
To generate traffic, the traffic generator [TRex](https://trex-tgn.cisco.com/) needs to be installed on machine 2. An installation guide can be found [here](https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_download_and_installation). 

Once TRex has been successfully installed, the server can be started with:

`./t-rex 64 -i -c <number of cores>`

The console can be started with:

`./trex-console`

In the console, traffic can be started, using the scripts in `src/scripts/traffic_gen/` with the command:

`start -f <path to script>.py -d <duration (seconds)> -t --ppsi <invalid traffic (pps)> --ppsv <valid traffic (pps)>`

The traffic can be stopped by writing `stop` to the console, or killing the TRex server process.

The scripts used in the experiments are:
- `udp_testsvr_traffic_v4.py` IPv4 traffic only, 65534 clients sending invalid traffic
- `udp_testsvr_traffic_v6.py` IPv4 traffic only, 65534 clients sending invalid traffic
- `udp_testsvr_traffic_v4_v6.py` IPv4 & IPv6 traffic, 131068 clients sending invalid traffic

The number of clients can be adapted via changing the `IP_RANGE` constants at the top of the script. 
Source and destination IP addresses also may have to be adapted to the test environment.

# DUT Setup

The applications required for experiments 1-4 (chapter 4 in the thesis) are `udp_server`, `fail2ban`, `simplefail2ban` and `simplelogstash`.

`fail2ban` can be found [here](https://github.com/fail2ban/fail2ban) or alternatively installed via a packet manager, such as apt.
The configuration files for fail2ban can be found in `src/fail2ban-config`. The contents of `jail.local` need to be copied into
`/etc/fail2ban/jail.local`. `udp-testsvr.conf` needs to be copied to `/etc/fail2ban/filter.d/`. Subsequently, fail2ban should be restarted.

`udp_server`,`simplefail2ban` and `simplelogstash` can be found in `/build`, after building successfully.

`udp_server` is a simple UDP-based server, that sends one byte replies to incoming packets. It logs certain requests, based on their payload and supports both file and shared memory based logging. `udp_server` can be run with the following options:
- `-f, --file[=LOGFILE]`       Specifies logfile as ipc type for logging (optional: specify path to logfile)
- `-l, --logshort`             Enable short logging (will only log a clients IP
                             address)
-  `-n, --nlines=NUM`          Specifies the number of lines per segment for the    shared memory ring buffer
-  `-o, --overwrite`            Enables overwrite option for shared memory
-  `-p, --port=PORT`            Specifies the port for the server to listen at
-  `-r, --nreaders=N`           Specifies the maximum number of readers for shared memory
-  `-s, --shm[=KEY]`            Specifies shared memory as ipc type for logging
-  `-t, --threads[=N]`          Specifies the number of threads used to receive packets
-  `-?, --help`                 Prints available options

`simplefail2ban` is a minimal intrusion prevention system, modelled after Fail2ban.
It needs to be parameterized with the interface, that the eBPF program for packet filtering is supposed
to run on: `./simplefail2ban <INTERFACE>`
It can additionally be run with the following options
- `-b, --bantime=N`            Specifies the number of seconds a client should be banned
- `-f, --file[=FILE]`          Specifies logifle as the chosen ipc type for receiving log messages (optional:
                             specify path to logfile)
- `-l, --limit=N`              Specifies the necessary number of matches before a client is banned
- `-m, --match[=REGEX]`        Activates regex matching on logstrings (optional:
                             specify match regex to use)
- `-s, --shm[=KEY]`            Specifies shared memory as the ipc type for receiving log messages (optional:
                             specify file for shared memory key)
- `-t, --threads[=N]`          Enables multi-threading for monitoring log messages (optional: set number of
                             banning threads to use)
- `-v, --verbose`              Enables debug output for eBPF functions
- `-w, --steal`                Enables workload stealing for shared memory reading
- `-?, --help`                 Prints available options

For the experimental setup, `udp_server` needs to be started before `simplefail2ban` or `simplelogstash`,
when using shared memory as the ipc type. All applications can be orderly terminated 
with `control+c`.

Additionally, neighbor cache entries, for the client IP addresses used by TRex, will have to be added to the neighbor table of the DUT. This can be done using the script:
`add_arp.sh` in `src/scripts/dut`. Parameters of the script may have to be adapted 
to the test environment. For IPv6, a custom route may have to be added, to route IPv6 replies to the device running TRex.


# Measurement
The measurement during the experiments 1-4 was conducted with the program `ebpf_cmdline` in `src/ebpf-helpers`. 

To start a measurement call:
`./ebpf_cmdline --stats --write`
The measurement can be terminated with `control+c` and the results will be written to a .csv file within the current directory.

Unfortunately, I have lost the source code for `ebpf_cmdline`. However, the program is only a slightly adapted version of the `xdp_ddos01_blacklist_cmdline` program, from
the master thesis of Florian Mikolajczak, which can be used instead.

# Known Bugs
The are two major known bugs for the implementation. 

When the `BPF_F_NO_PREALLOC`
flag is specified in the `ip_the blacklist.bpf.c` eBPF program, memory allocation for 
new map entries may fail, when larges amount of addresses are added in a short time frame. This causes `simplefail2ban` to display an error message for both the write to the eBPF map, as well as the subsequently failing removal from eBPF map and the hash table by the banning thread. 
However, performance and functionality did not appear to be heavily impacted by this during measurements. The error can be prevented by unspecifiying the the `BPF_F_NO_PREALLOC`flag in `ip_the blacklist.bpf.c`.

Unorderly detachment of readers or the writer from the shared memory ring buffer, results in a corrupted header, as the attachment filed are not cleared.
When this occurs, all processes should be detached from the buffer, so that it can be reinitialized. If all attached programs detach unorderly, the shared memory segment has to be destroyed with: `icprm -m <id>`, before the buffer can be reinitialized.



