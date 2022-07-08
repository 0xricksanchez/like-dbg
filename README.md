# LInux-KErnel DeBuGger (LIKE-DBG)

This repository aims at automating the boring steps when trying to set up a Linux kernel debugging environment.
The gist of it is that 


## Quick start

Make sure you have `tmux` and `docker` installed. 
If you have the compiler set to `clang` make sure you have the complete llvm toolchain available!

In theory, to tweak the environment you want to debug all you have to do is customize the `config.ini` to your needs.
Afterwards, executing the commands below should drop you into a 3-tile tmux configuration with a QEMU booted kernel, an attached
GDB debugger, and one terminal for free allocation.

```bash
python3 -m venv .like-dbg
source .like-dbg/bin.activate
python3 ./start_kgdb.py
```

### Tweaking the config

Most of the config fields should be self explanatory.



## To-dos

* [ ] FIXME: x86_64 does not break on `startup_64` 
    * [ ] QEMUs `--enable-kvm` is buggy?
* [x] Patch directory that is automatically applied to the kernel source
* [ ] Multi Arch kernel builds
    * [ ] arm64: Builds fail
* [x] Set custom compiler in config.ini
* [ ] Set additional kernel config parameters in config.ini
* [ ] Add android kernel as an option 


https://opensource.samsung.com/uploadList?menuItem=mobile&classification1=mobile_phone
