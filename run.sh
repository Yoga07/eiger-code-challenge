#!/bin/bash

# Start the Casper node and write logs to `casper.log`
sudo RUST_LOG=trace resources/casper-node validator resources/config.toml > casper.log &
command_pid=$!

# Remove any old log files since they'll only be appended to
sudo rm -rf eiger_node.log.*

# Start Eiger handshake node
target/release/eiger_node --our_address="127.0.0.1:5001" --chainspec="./resources/chainspec.toml" -l

trap pkill command_pid EXIT