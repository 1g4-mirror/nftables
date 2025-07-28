#!/bin/bash

# check if netdev chains survive without a single device

unshare -n bash -c "ip link add d0 type dummy; \
	$NFT \"table netdev t { \
		chain c { \
			type filter hook ingress devices = { d0 } priority 0;\
		}; \
	}\"; \
	ip link del d0; \
	$NFT list chain netdev t c"
