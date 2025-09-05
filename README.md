# Frida Fusion 

Hook your mobile tests with Frida.

```bash
 [ FRIDA ]—o—( FUSION )—o—[ MOBILE TESTS ] // v0.1.0
     > hook your mobile tests with Frida


optional arguments:
  -h, --help                                    show this help message and exit

Device selector:
  -D [ID], --device [ID]                        Connect to device with the given ID
  -U, --usb                                     Connect to USB device
  -R, --remote                                  Connect to remote frida-server
  -H [HOST], --host [HOST]                      Connect to remote frida-server on HOS

Application selector:
  -f [APP ID], --package [APP ID]               Spawn application ID
  -p [PID], --attach-pid [PID]                  Spawn application ID

General Setting:
  -s [path], --script-path [path]               JS File path or directory with Frida script
  --delay-injection                             Delay script injection
  --show-time                                   Display time
  -o [output file]                              Save output to disk (default: none)
  -l [level], --min-level [level]               Minimum log level to be displayed (V,D,I,W,E,F) (default: I)

Modules:
  --list-modules                                List available modules
  -m ENABLED_MODULES, --module ENABLED_MODULES  Enabled module by name. You can specify multiple values repeating the flag.
```

## Install

```
pip3 install frida-fusion
```

## Module engine

You can check available modules with `frida-fusion --list-modules` command.

```bash
frida-fusion --list-modules

 [ FRIDA ]—o—( FUSION )—o—[ MOBILE TESTS ] // v0.1.4
     > hook your mobile tests with Frida


Available modules
  Module Name     : Description
  Crypto          : Hook cryptography/hashing functions
```

### External modules

You can develop or download community modules and load into frida-fusion.

To pass to the Frida Fusion the external module path you can use the environment variable `FUSION_MODULES` with the full path of modules

At linux:

```bash
export FUSION_MODULES=/tmp/modules

# List all modules
frida-fusion --list-modules

# Using available module
frida-fusion -f [app_id] -U --script-path . -m [module_name]
```

At windows:

```bash
$env:FUSION_MODULES = "C:\extra_mods"

# List all modules
frida-fusion --list-modules

# Using available module
frida-fusion -f [app_id] -U --script-path . -m [module_name]
```

### Community modules

You can also use one of community developed modules

```bash
cd /tmp/
git clone https://github.com/helviojunior/frida-fusion-community-modules
export FUSION_MODULES=/tmp/frida-fusion-community-modules

# List all modules
frida-fusion --list-modules
```
