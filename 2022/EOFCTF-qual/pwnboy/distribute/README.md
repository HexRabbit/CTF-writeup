# Normal usage

## Install SDL2 library
`apt install libsdl2-2.0-0`

## Run the binary
To run the binary, make sure you have display/audio output!

`./jitboy /path/to/rom.gb`

# Setup service on local (if VM is too big for you)

## Install xinetd
`apt install xinetd`

## Run xinetd service
To run the service, make sure you have display/audio output!

- modify `xinetd/pwnboy`
    - `user`: your local username
    - `server`: where you place `run.sh` / `run_gameboy.py` / `jitboy`
- copy `xinetd/pwnboy` to `/etc/xinetd.d/pwnboy`
- modify the paths in `run.sh` and `run_gameboy.py`
- substitute `DISPLAY` variable in `run.sh` by the output of `echo $DISPLAY` (usually `:0`)
- reload service with `systemctl reload xinetd`
- service will listen on `0.0.0.0:13337`