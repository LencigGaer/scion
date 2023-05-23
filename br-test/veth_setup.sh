#!/bin/bash

# Create veth pairs
sudo ip link add veth0 type veth peer name veth1
sudo ip link add veth2 type veth peer name veth3
sudo ip link add veth4 type veth peer name veth5

# Configure IP addresses
sudo ip addr add dev veth0 10.127.0.1/24
sudo ip addr add dev veth1 10.127.0.2/24
sudo ip addr add dev veth2 10.127.1.1/24
sudo ip addr add dev veth3 10.127.1.2/24
sudo ip addr add dev veth4 10.127.2.1/24
sudo ip addr add dev veth5 10.127.2.2/24

# Bring interfaces up
sudo ip link set dev veth0 up
sudo ip link set dev veth1 up
sudo ip link set dev veth2 up
sudo ip link set dev veth3 up
sudo ip link set dev veth4 up
sudo ip link set dev veth5 up

# Load pass program
make -C xdp_pass > /dev/null
sudo make -C xdp_pass attach VETH=veth0 > /dev/null
sudo make -C xdp_pass attach VETH=veth2 > /dev/null
sudo make -C xdp_pass attach VETH=veth4 > /dev/null

# Disable checksum offload
sudo ethtool --offload veth0 rx off tx off > /dev/null
sudo ethtool --offload veth1 rx off tx off > /dev/null
sudo ethtool --offload veth2 rx off tx off > /dev/null
sudo ethtool --offload veth3 rx off tx off > /dev/null
sudo ethtool --offload veth4 rx off tx off > /dev/null
sudo ethtool --offload veth5 rx off tx off > /dev/null
