# Game LAN Emulator
A utility designed to emulate a LAN environment without needing a traditional VPN, by routing relevant network traffic through a proxy. 
Unlike a basic VPN, this tool intercepts traffic at the application level, capturing only the traffic intended for LAN broadcasts. 
Each client is assigned a unique, virtual IP address from the proxy server, allowing direct messages to be seamlessly transmitted between clients.

The client side is made possible by having the `gbe_proxy.dll` injected/loaded into the relevant application's memory space.