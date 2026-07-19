# macOS Volatility 3 Plugins

Needs an **ISF** matching the image's Darwin build.


### `mac_hostname`: system hostname

![mac_hostname output](photos/hostname.png)

### `mac_loginwindow_creds`: plaintext login credentials

![mac_loginwindow_creds output](photos/loginwindow_creds.png)

## building ISF 

Build the ISF with [`dwarf2json`](https://github.com/volatilityfoundation/dwarf2json) and drop it in `volatility3/symbols/mac/`.Re-encode and run `vol --clear-cache`.
Read[https://mooofin.github.io/portfolio/blog/s4nct1m0ny.html] for how to build .

working on => mac_jit_spray_detect , mac_dyld_maps , mac_machocarve

TODO: Rosetta 2 AOT translation caches[https://rewterz.com/threat-advisory/hackers-exploiting-x86-64-binaries-on-apple-silicon-to-distribute-macos-malware] , ObjC swizzling detection [https://ret0.dev/posts/macos-amfi-bypass-objc-runtime-swizzle/] and something for libdispatch (GCD) queues[https://www.macinternals.app/en/blog/libdispatch-internals]


NOTES:: https://app.notion.com/p/mac-volatility-plugins-3a2d4af5a795813d9a3ed1aff6a67087 
