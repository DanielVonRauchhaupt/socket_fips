# Project Overview
This repository is part of the bachelor thesis "Design and Implementation of a high performance IPC for Intrusion Prevention using Socket API" by Daniel von Rauchhaupt.
The purpose of this research is to determine which IPC type performs best when used by the intrusion prevention system `simplefail2ban`.
The IPC types of interest are UNIX domain sockets and shared memory.
For details, please refer to that thesis.


# Relevant directories
- `experiments/` – Measurement data and jupyter notebooks for data visualization
- `external/` – External libraries used for building
- `latex_vonRauchhaupt/` – Latex files for thesis and presentation slides
- `src/` Source files for implementation, scripts, and configuration of the project
- Once the project has been built successfully, all applications will be located in `build/`

This project was built on the foundation provided by Paul Raatschen.
Currently remnants of his bachelor thesis can be found in these directories.
Directories will contain their own READMEs which will elaborate further on their contents.


# Installation Instructions
Installation instructions can be found in `HOWTOINSTALL.md`


# Usage Guide
The main functional applications in this project are: `udp_server`, `simplefail2ban` and `fail2ban`.
The configuration files for `fail2ban` are located in `src/fail2ban-config`.
The contents of `jail.local` need to be copied into `/etc/fail2ban/jail.local`.
`udp-testsvr.conf` needs to be copied to `/etc/fail2ban/filter.d/`.
Afterwards, restart `fail2ban`.

The application `udp_sever` is a UDP-based server that sends one byte replies to incoming packets.
It simulates a service using the `simplefail2ban` and `fail2ban` applications.
It logs certain requests, differentiating between valid and invalid traffic based on the payload it receives.
Reporting clients to the IPS `simplefail2ban` is possible via either file, shared memory or socket based logging.
Following options can be used when running `udp_server`:
-  `-f, --file[=LOGFILE]`	Specifies logfile as ipc type for logging (optional: specify path to logfile)
-  `-l, --logshort`		    Enable short logging (will only log a clients IP address)
-  `-n, --nlines=NUM`		Specifies the number of lines per segment for the    shared memory ring buffer
-  `-o, --overwrite`		Enables overwrite option for shared memory
-  `-p, --port=PORT`		Specifies the port for the server to listen at
-  `-r, --nreaders=N`		Specifies the maximum number of readers for shared memory
-  `-s, --shm[=KEY]`		Specifies shared memory as ipc type for logging
-  `-u, --sock`			    Specifies unix domain socket as ipc type for logging
-  `-t, --threads[=N]`		Specifies the number of threads used to receive packets
-  `-?, --help`			    Prints available options

In its current implementation, setting a custom path for any sockets created by the application is not possible via the options provided here.
Instead, modify the default variables found in `src/lib/include/sock_comm.h`.


The application `simplefail2ban` is a minimal intrusion prevention system.
It is modelled after, and can be considered a lightweight version of, `fail2ban`.
It needs to be parameterized with the interface, that the eBPF program for packet filtering is supposed to run on:

`./simplefail2ban <INTERFACE>`

It can additionally be run with the following options
-  `-b, --bantime=N`		Specifies the number of seconds a client should be banned
-  `-f, --file[=FILE]`		Specifies logifle as the chosen ipc type for receiving log messages (optional: specify path to logfile)
-  `-l, --limit=N`		    Specifies the necessary number of matches before a client is banned
-  `-m, --match[=REGEX]`	Activates regex matching on logstrings (optional: specify match regex to use)
-  `-s, --shm[=KEY]`		Specifies shared memory as the ipc type for receiving log messages (optional: specify file for shared memory key)
-  `-u, --sock`			    Specifies unix domain socket as ipc type for receiving log messages
-  `-t, --threads[=N]`		Enables multi-threading for monitoring log messages (optional: set number of banning threads to use)
-  `-v, --verbose`		    Enables debug output for eBPF functions
-  `-w, --steal`		    Enables workload stealing for shared memory reading
-  `-?, --help`			    Prints available options

The application using `simplefail2ban` as its IPS needs to started first.
All applications can be orderly terminated with `control+c`.


# Experimental Setup
The provided experiments were conducted using two machines.
Machine 1 is the device under test (DUT) running `fail2ban` and `simplefail2ban`. Machine 2 is the traffic generator (simulating an attacker).

The traffic generator used on machine 2 for the experiments was [TRex](https://trex-tgn.cisco.com/).
An installation guide can be found [here](https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_download_and_installation).

Once TRex has been successfully installed, the server can be started with:

`./t-rex 64 -i -c <number of cores>`

The console used to specify the traffic generated by TRex can be called with:

`./trex-console`

There, traffic can be started with the scripts found in `src/scripts/traffic_gen_vonRauchhaupt/` with the command: 

`start -f <path to script>.py -d <duration (seconds)> -t --ppsi <invalid traffic (pps)> --ppsv <valid traffic (pps)>`

The traffic can be stopped by writing `stop` to the console, or killing the TRex server process with `control+c`.

The number of clients can be adapted via changing the `IP_RANGE` constant at the top of the script.
Source and destination IP addresses also may have to be adapted to the test environment.

The DUT, machine 1,  needs to first start the application utilizing the IPS services.
Here, that would be `udp_server`.
Afterwards, start the IPS service of choice.
In this thesis, only `simplefail2ban` will be required for the experiments.


# Measurement
The measurements were conducted with the program `ebpf_cmdline` in `src/ebpf-helpers`.
To start a measurement call:

`./ebpf_cmdline --stats --write`

The measurement can be terminated with `control+c` and the results will be written to a .csv file within the current directory.

The program is a slightly adapted version of the `xdp_ddos01_blacklist_cmdline` program, from the master thesis of Florian Mikolajczak, modified by Paul Raatschen.


# Known bugs

When the `BPF_F_NO_PREALLOC` flag is specified in the `ip_the blacklist.bpf.c` eBPF program, memory allocation for new map entries may fail when large amounts of addresses are added in a short time frame.
This causes `simplefail2ban` to display an error message for both the write to the eBPF map, as well as the subsequently failing removal from eBPF map and the hash table by the banning thread. 
However, performance and functionality did not appear to be heavily impacted during measurements.
The error can be prevented by unspecifiying the the `BPF_F_NO_PREALLOC` flag in `ip_the blacklist.bpf.c`.

Unorderly detachment of readers or the writer from the shared memory ring buffer results in a corrupted header as the attachment files are not cleared.
When this occurs, all processes should be detached from the buffer, so that it can be reinitialized.
If all attached programs detach unorderly, the shared memory segment has to be destroyed with: `icprm -m <id>`, before the buffer can be reinitialized.

Using the socket IPC, attaching multiple readers at once can result in each of them trying to claim the same unix domain socket as their own.
This is caused by the fact that determining which socket is still available is not synchronized between readers, resulting in a race condition.

When utilizing the socket IPC, terminating one writer process using the function `sock_finalize` will result in all unix domain sockets being closed.
While insignificant in the scope of this thesis, which only ever uses one writer process at a time, this behavior was still not intended.

# Acknowledgments
This repository reuses code from both Paul Raatschen and Florian Mikolajczak.
The bachelor thesis (and this repository) was made with guidance of Prof. Dr. Bettina Schnor and Max Schrötter.