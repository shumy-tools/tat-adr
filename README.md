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
This project is a tool to measure running times of the proposed P-ID scheme. The tool accepts parameters to setup the number of parties (n) and the threshold value (t).

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
