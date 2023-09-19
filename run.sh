#!/bin/bash

# Start the casper node and write logs to `casper.log`
sudo resources/casper-node validator resources/config.toml > casper.log
command_pid=$!

# Start eiger handshake node
target/release/eiger_node --our_address="127.0.0.1:5001" --chainspec="./resources/chainspec.toml"

trap pkill command_pid EXIT