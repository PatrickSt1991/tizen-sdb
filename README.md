# TizenSdb

A standalone client to connect with your Tizen TV

## Options

`--port <n>` sets the sdbd port to connect to (default `26101`). Use it to reach sdbd through the
Apps2Samsung TV-Store relay, which forwards a LAN port to the TV's own sdbd over loopback so the Host
PC IP never has to change (see Apps2Samsung/TV-Store#52). It may appear anywhere in the arguments, for
example `TizenSdb --port 26201 connect 192.168.2.50`.
