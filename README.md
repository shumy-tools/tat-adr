# tat-adr
Threshold Access Token for Anonymous Data Resources

## Dependencies
* rustc 1.36.0
* cargo 1.36.0

## Build
Build with release for optimal results.

```
cargo build --release
```

## Usage
This project is a tool to measure running times of the proposed TAT-ADR scheme. The tool accepts parameters to setup the threshold value (t) and number of runs (r).

```
Simulations for TAT-ADR 1.0
Micael Pedrosa <micaelpedrosa@ua.pt>
Simulations and measurements for (Threshold access token for anonymous data resources)

USAGE:
    tat-adr --runs <runs> --threshold <threshold>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -r, --runs <runs>              Sets the number of runs.
    -t, --threshold <threshold>    Sets the threshold number (t). The number of parties are set automatically to t+1.
```

with an example of an output:

```
Setup: (threshold: 4, runs: 100)
Stats: (start-net: 0.940ms, start-cli: 6.314ms, request-net: 1.647ms, request-cli: 3.499ms, verify: 5.071ms, total: 17.471ms)
```

* "init" is the initial setup of the client before starting the session
* "start-net" and "request-net" is the time for each individualy node
* "start-cli" and "request-cli" is the time for the client to process the t + 1 responses
* "verify" is the time for the token public verification
* "total" is the time for a full roundtrip (generation + verification)

## Results
Previous results for 100 runs. Experiments were carried out in a single machine running Linux (Ubuntu 18.04.1 LTS) with an Intel i7-7700HQ CPU @ 2.80GHz with 4 physical cores and 16GB of physical memory.

```
(threshold: 4)   - (init: 1.084ms, start-net: 1.181ms, start-cli:   6.508ms, request-net: 1.698ms, request-cli:  3.615ms, verify: 5.225ms, total:  19.311ms)
(threshold: 8)   - (init: 1.209ms, start-net: 1.216ms, start-cli:  11.673ms, request-net: 1.552ms, request-cli:  6.282ms, verify: 5.963ms, total:  27.895ms)
(threshold: 16)  - (init: 1.214ms, start-net: 1.168ms, start-cli:  20.895ms, request-net: 1.352ms, request-cli: 10.912ms, verify: 6.007ms, total:  41.548ms)
(threshold: 32)  - (init: 1.218ms, start-net: 1.136ms, start-cli:  39.182ms, request-net: 1.236ms, request-cli: 19.905ms, verify: 5.983ms, total:  68.660ms)
(threshold: 64)  - (init: 1.100ms, start-net: 0.996ms, start-cli:  67.297ms, request-net: 1.037ms, request-cli: 33.998ms, verify: 5.353ms, total: 109.781ms)
(threshold: 128) - (init: 1.053ms, start-net: 0.963ms, start-cli: 130.016ms, request-net: 0.988ms, request-cli: 65.381ms, verify: 5.186ms, total: 203.587ms)
```
