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

* "start-net" and "request-net" is the time for each individualy node
* "start-cli" and "request-cli" is the time for the client to process the t + 1 responses
* "verify" is the time for the token public verification
* "total" is the time for a full roundtrip (generation + verification)

## Results
Previous results for 100 runs. Experiments were carried out in a single machine running Linux (Ubuntu 18.04.1 LTS) with an Intel i7-7700HQ CPU @ 2.80GHz with 4 physical cores and 16GB of physical memory.

```
(threshold: 4)   - (start-net: 0.934ms, start-cli:   6.272ms, request-net: 1.645ms, request-cli:  3.477ms, verify: 5.061ms, total:  17.390ms)
(threshold: 8)   - (start-net: 0.932ms, start-cli:  10.107ms, request-net: 1.324ms, request-cli:  5.402ms, verify: 5.050ms, total:  22.815ms)
(threshold: 16)  - (start-net: 1.069ms, start-cli:  20.295ms, request-net: 1.304ms, request-cli: 10.563ms, verify: 5.807ms, total:  39.038ms)
(threshold: 32)  - (start-net: 0.961ms, start-cli:  34.089ms, request-net: 1.070ms, request-cli: 17.490ms, verify: 5.245ms, total:  58.854ms)
(threshold: 64)  - (start-net: 0.948ms, start-cli:  65.221ms, request-net: 1.006ms, request-cli: 32.932ms, verify: 5.162ms, total: 105.269ms)
(threshold: 128) - (start-net: 0.955ms, start-cli: 128.949ms, request-net: 0.983ms, request-cli: 64.987ms, verify: 5.181ms, total: 201.055ms)
```
