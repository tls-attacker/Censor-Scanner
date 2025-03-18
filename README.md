# CensorScanner

Code of CensorScanner as used in the 2025 paper `Transport Layer Obscurity: Circumventing SNI Censorship on the TLS Layer` published in the 46th IEEE Symposium on
Security and Privacy.

Link to the paper: TODO

## Description

CensorScanner automatically analyzes censors and TLS-servers for their acceptance of circumvention strategies against SNI-based censorship.
To this end, CensorScanner implements various circumvention techniques on the TLS layer such as length field invalidations and TLS record fragmentation and sends their combinations against the tested implementation.
Censors and TLS-servers can be analyzed in conjunction or separately to determine working strategies.
Output is provided in .json and .txt formats under /results.

Depends on [TLS-Attacker](https://github.com/tls-attacker/) and Java 11!

## Usage

In apps:
`java -jar censor-fuzzer-1.0.0.jar` prints out the launch options.

```
Usage: <main class> [options]
  Options:
  * -connect
      Who to connect to. Syntax: ip:port
      Default: 127.0.0.1:443
    -debug
      Show extra debug output (sets logLevel to DEBUG)
      Default: false
    -enableCapturing
      If true, enables connection analysis with pcap4j. Java needs network 
      capabilities (or sudo) inthis case.
      Default: false
    -exclude
      Which (group of) strategies to exclude. Default is None (not present) - 
      indicates that all should be used. Add multiple groups by separating 
      them with commas.
      Default: [NONE]
    -h, -help
      Prints usage for all the existing commands.
    -interface
      Network Interface to capture traffic on
      Default: any
    -keyLogFile
      Location of the file key material will be saved to
      Default: <empty string>
    -outputFileIdentifier
      Identifier that the output files name of the analysis will be prepended 
      with. Default is results/unspecified_server, resulting in for example 
      results/unspecified-server_strength_2_results.txt 
      Default: results/unspecified-server
    -quiet
      No output (sets logLevel to NONE)
      Default: false
  * -scanType
      Whether to scan a TLS server or censorship to an ECHO server
      Default: DIRECT
      Possible Values: [DIRECT, ECHO, SIMPLE]
  * -serverName
      Server name for the SNI extension.
      Default: target.com
    -simpleScanServerAnswerBytes
      Bytes sent by a vantage point server for the SimpleScan type. Provide in 
      hex 
      Default: 6565656565
    -testStrength
      Test strength for the fuzzer
      Default: 3
    -testVectorInputFile
      If set, deserializes the given file into a set of Test vectors to use 
      instead of the generated default list. Overrides -excludeStrategies and 
      -testStrength. Optional, but if set fails on serialization errors.
    -threads
      How many threads to use in parallelized connections
      Default: 100
    -timeout
      The timeout used for the scans in ms (default 5000)
      Default: 5000
    -writeAllResultTypes
      If true, writes all result types into the file. Otherwise, unnecessary 
      result types for further analysis are not written.Examples for not 
      written types are already default and inapplicable.
      Default: false

```

Example execution

```shell
java -jar censor-fuzzer-1.1.0-SNAPSHOT.jar
 -testStrength 1
 -keyLogFile /tmp/key.log
 -enableCapturing
 -outputFileIdentifier results/example
 -scanType DIRECT
 -connect 127.0.0.1:443  
 -serverName target.com
 -threads 100
```

This scans the TLS-Server running at localhost:443 for its acceptance of TLS censorship circumventino techniques. The test strength is set to 1 for a fast execution in this example.

## Dockerfiles

A short proof-of-concept is supplied in `docker-compose.yml`

1. Starts a local TLS server
2. Starts CensorScanner (same as the example above)
3. Results are located in `results/example*`

Start the scan with

```sh
docker compose up -d nginx_2404
docker compose up fuzzer
```

after the scan remove the idle TLS server with

```sh
docker compose down
```

Results can be read with

```sh
cat ./results/example_results.txt
```

## Scan Methods

CensorScanner can scan 3 types of servers:

- You can launch a local TLS server using the provided docker file. You can also scan any live server with CensorScanner but beware that CensorScanner executes a number of connections exponential to the specified test strength. We discourage you from scanning servers that you do not own.
- You can launch and scan a local ECHO server for testing purposes over the provided docker compose file or in `python_util` with `python3 echo.py`.
- You can launch and scan a local SIMPLE server for testing purposes using the provided docker compose file.

# Features

- TLS censorship circumvention strategies
- Automatic combination of circumvention strategies by specifiable test strength
- Full TLS handshake / ECHO connections / simplified connection attempts with example server
- Automatic measurement of and determination of connection attempts (e.g. TCP RST)

