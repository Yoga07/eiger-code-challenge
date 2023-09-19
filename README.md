# Eiger Code Challenge

## Problem statement

Pick a publicly available P2P node (e.g. a blockchain one) implementation - which itself doesn't need to be written in Rust - and write a network handshake for it in Rust, and instructions on how to test it.

### Requirements
- Both the target node and the handshake code should compile at least on Linux.
- The solution has to perform a full protocol-level (post-TCP/etc.) handshake with the target node.
- The provided instructions should include information on how to verify that the handshake has concluded.
- The solution can not depend on the code of the target node (but it can share some of its dependencies).
- The submitted code can not reuse entire preexisting handshake implementations like libp2p_noise/XX.

### Non-requirements
- A lot of parameters can potentially be exchanged during the handshake, but only the mandatory ones need to be included.
- The solution can ignore any post-handshake traffic from the target node, and it doesn't have to keep the connection alive.
- Bonus points for non-Bitcoin implementations.
- The more broadly applicable the solution is (bi-directional, unfixed values, etc.), the better.

## Solution:

### Choice of P2P node:

Casper - https://github.com/casper-network/casper-node

#### Reasons:

- A novel P2P implementation that satifies the requirements(non-bitcoin) of this challenge.
- Has a robust and well-written networking mechanism that makes this challenge a even more interesting to solve.
- Employs multiple specially tailored serialization formats for it's messages.
- Well established handshake flows that separates Protocol payload from Network payload using the above mentioned serialization formats.

### Download binaries:

You can download the handshake binary and the casper-node binary from [provide link].

### Building from source:

To build the Handshake binary from source:

- Clone the repository
```
git clone https://github.com/Yoga07/eiger-code-challenge
```

- Build it with Rust
```
cargo build --release
```

### Running the binary:

- Run the eiger_node binary with:
```
target/release/eiger_node --our_address="127.0.0.1:5001" --chainspec="./resources/chainspec.toml"
```

Command line arguments:
```
USAGE:
    eiger_node [FLAGS] --chainspec <PATH> --our_address <SOCKET_ADDR>

FLAGS:
    -h, --help           Prints help information
    -l, --log_to_file    Writes logs to a file on a rolling basis
    -V, --version        Prints version information

OPTIONS:
    -c, --chainspec <PATH>             Path to chainspec.toml file
    -a, --our_address <SOCKET_ADDR>    SocketAddress for this to node to bind to.
```
### Testing Handshake with Casper

Casper's `casper-node` binary(built at their [latest commit](https://github.com/casper-network/casper-node/commit/f7d8228de3cb56a3fe705f5a787d3dbf03ff7998)) is bundled in the `resources` directory for testing purposes. 
After building the handshake node binary `eiger_node` from source, execute the `run.sh` script to start both binaries and their handshake flows.
```
sudo sh ./run.sh
```

Casper's logs will be written in the `casper.log` file and the Handshake node's logs will be written to stdout by default.
Monitor the logs to see the Handshake process. A successful handshake received will be logged as

```
2023-09-19T09:36:50.283610Z TRACE eiger_code_challenge::comms: Handshake { network_name: "casper-example", public_addr: 127.0.0.1:5001, protocol_version: ProtocolVersion(SemVer { major: 1, minor: 0, patch: 0 }), consensus_certificate: None, is_syncing: false, chainspec_hash: Some(e36d71d0af9a4a30e6062729e5f5950dad63354c1a0c62b8e287199f7b734189) }
```

As a proof of the handshake flow successfully concluding, we should soon start seeing **Heartbeat messages** and **Gossip messages** from Casper.

Heartbeat messages(in the form of `Ping`) are logged as:

```
2023-09-19T09:37:50.344732Z  INFO eiger_code_challenge::node: Received a Ping from Casper. Not going to send a Pong!
2023-09-19T09:37:50.344751Z TRACE eiger_code_challenge::node: Ping { nonce: Nonce(16131779324408800775) }
```

Whereas Gossip messages are **non-protocol** messages which undergo a **different serialization** than to protocol messages like Handshake and Ping therefore they'll be failed to deserialize at our Handshake node(checkout [this](https://github.com/casper-network/casper-node/blob/dev/node/src/components/network.rs#L1347) method in casper's network mechanism to learn more).

We can see those warnings of deserialization getting logged as:

```
2023-09-19T09:37:09.424731Z  WARN eiger_code_challenge::comms: Error deserializing Custom { kind: InvalidData, error: Custom("Slice had bytes remaining after deserialization") }
2023-09-19T09:37:09.424741Z  WARN eiger_code_challenge::comms: Received an internal message from Casper. Ignoring the deserialization error
```

Note: By default, the `eiger_node` binary logs to stdout, but if you write the logs to a file, kindly add ` -l` at the end of line no. 8 which makes the process to write the logs to a file on a rolling basis.

