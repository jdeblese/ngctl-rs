# ngctl-rs
Rust tool for manipulating the FreeBSD Netgraph.

This started as a tool for easily creating new ng_eiface nodes conneced to a named ng_bridge, for use as part of a custom jail setup with networking provided via Netgraph. Bindgen is used to wrap the Netgraph API, and and Rust wrappers have been written for part of the API. Given a Netgraph path, the tool will check that it is a bridge, find the first available link# hook, attach a new ng_eiface's ether hook to it, and return the interface name of the new ng_eiface. This interface can then be given to a jail via vnet, optionally renaming the interface and/or node for convenience.
