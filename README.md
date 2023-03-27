# Bachelorarbeit

# Introduction
There should be helpful information here

# Directories
- `experiments/` Experiment data and jupyter notebooks for data visualisation
- `external/` External libraries used for building
- `latex/` Latex files for thesis and presentation slides
- `src/` Source files for programs, scripts and configuration

# External Dependencies
These libraries are required to be installed on the system, in order for cmake to build
successfully. 
- [liburing](https://github.com/axboe/liburing) version (0.7-3)
- [hyperscan](https://github.com/intel/hyperscan) version (5.4.0-2) (and its [dependencies](https://intel.github.io/hyperscan/dev-reference/getting_started.html#)) 

On Debian, they can be installed via: `apt install liburing-dev libhyperscan-dev` 

