# Installation Instructions

The following libraries are required to be installed on the system. Without them, cmake will fail to build the project:
- [liburing]( https://github.com/axboe/liburing) version 0.7-3
- [hyperscan]( https://github.com/intel/hyperscan) version 5.4.0-2 and its [dependencies]( https://intel.github.io/hyperscan/dev-reference/getting_started.html#)
On Debian, they can be installed via: `apt install liburing-dev libhyperscan-dev`.

Installing `fail2ban` is also necessary for the build process.
It can be found [here](https://github.com/fail2ban/fail2ban) or installed via a packet manager.

When building this project for the first time, load its submodules in the external folder first.
Use `git submodule update --init --recursive`.
Once all external dependencies are satisfied, using `./cmake.sh` in the main directory will build the project.
The binaries can be found in ‘build/’.

For the applications Simplefail2ban, Fail2ban and udp_server to function correctly, please ensure that you have followed the required configuartion steps as outlined in `README.md`.