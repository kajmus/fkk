# links and resources

## inspiration

### watch mode
two submodes looking at the current open files like lsof and second by bpf monitoring opening and closing files

    lsof

## commands

for generating vmllinux.h file

    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

searching for entrypoints and functions

    sudo bpftrace -lv 'fentry:*security_file*'


### versioned linux source code
    https://elixir.bootlin.com

# temp ideas

## counting drops
- counting drops in bpf once and if user space is not keeping up we need a way to filer them for performance since i think its more likealy they will be skipped in user space like saving to file or printing but i don't knwo how much


## other todo
- add timestamps to watch
- add check if the program can even run (bpf is setup)
- add watch modes file output