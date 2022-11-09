# README

This is a knowledge base about all things kernel debugging.
By curating various sources, the framework development as well as debugging kernel panics should become a lot easier.

## Tools of interest

* [drgn - Programmable debugger](https://github.com/osandov/drgn)
* [HadesDbg- The Linux x86/x86-64 last chance debugging tool](https://github.com/h311d1n3r/HadesDbg)

## General information

* [Ubuntu Debugging](https://wiki.ubuntu.com/Kernel/Debugging)
* [FreeBSD - Chapter 10. Kernel Debugging](https://docs.freebsd.org/en/books/developers-handbook/kerneldebug/)
  * [kgdb](https://www.freebsd.org/cgi/man.cgi?query=kgdb&sektion=1), [dumpon](https://www.freebsd.org/cgi/man.cgi?query=dumpon&sektion=8), [savecore](https://www.freebsd.org/cgi/man.cgi?query=savecore&sektion=8)

## Learning collection

* [Linux Kernel Teaching](https://linux-kernel-labs.github.io/refs/heads/master/)
* [Linux Kernel Learning](https://github.com/ocastejon/linux-kernel-learning)
* [Linux Kernel Hacking](https://github.com/xcellerator/linux_kernel_hacking)

## Write-Ups

Section to dump good write-ups that either feature an actual exploit, a new technique, or general vulnerability discovery.

### Vulnerability discovery

* [Ruffling the penguin! How to fuzz the Linux kernel](https://hackmag.com/security/linux-fuzzing/)

### Exploits

* [Writing a Linux Kernel Remote in 2022](https://blog.immunityinc.com/p/writing-a-linux-kernel-remote-in-2022/)
* [CVE-2022-0185 - Winning a $31337 Bounty after Pwning Ubuntu and Escaping Google's KCTF Containers](https://www.willsroot.io/2022/01/cve-2022-0185.html)
  * [CVE-2022-0185: Linux kernel slab out-of-bounds write: exploit and writeup](https://www.openwall.com/lists/oss-security/2022/01/25/14)
* [[corCTF 2022] CoRJail: From Null Byte Overflow To Docker Escape Exploiting poll_list Objects In The Linux Kernel](https://syst3mfailure.io/corjail)
* [[CVE-2022-1786] A Journey To The Dawn](https://blog.kylebot.net/2022/10/16/CVE-2022-1786/)
* [Four Bytes of Power: Exploiting CVE-2021-26708 in the Linux kernel](https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html)
  * [Improving the exploit for CVE-2021-26708 in the Linux kernel to bypass LKRG](https://a13xp0p0v.github.io/2021/08/25/lkrg-bypass.html)
* [Put an io_uring on it: Exploiting the Linux Kernel](https://www.graplsecurity.com/post/iou-ring-exploiting-the-linux-kernel)
* [Kernel Pwning with eBPF: a Love Story](https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story)
* [corCTF 2021 Fire of Salvation Writeup: Utilizing msg_msg Objects for Arbitrary Read and Arbitrary Write in the Linux Kernel](https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html)
* [[corCTF 2021] Wall Of Perdition: Utilizing msg_msg Objects For Arbitrary Read And Arbitrary Write In The Linux Kernel](https://syst3mfailure.io/wall-of-perdition)
* [[CVE-2021-42008] Exploiting A 16-Year-Old Vulnerability In The Linux 6pack Driver](https://syst3mfailure.io/sixpack-slab-out-of-bounds)
* [Anatomy of an Exploit: RCE with CVE-2020-1350 SIGRed](https://www.graplsecurity.com/post/anatomy-of-an-exploit-rce-with-cve-2020-1350-sigred)
