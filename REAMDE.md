
# folder structure

    fguard/
    ├── README.md              what it is, how to build, how to run
    ├── LICENSE                user space: your choice; BPF code must be GPL-compatible
    ├── Makefile               one entry point: make, make test, make clean, make fmt
    ├── .gitignore             build/, generated skeleton, editor files
    ├── .clang-format          code style, enforced by make fmt
    ├── docs/
    │   ├── architecture.md    the diagram and flow from this document, kept up to date
    │   ├── decisions.md       one short entry per design decision, with the reason
    │   └── thesis-notes.md    measurements, observations, things to cite later
    ├── scripts/               VM helpers, demo scenarios, benchmark runners
    ├── src/
    │   ├── main.c             tiny: parse the subcommand, call the right mode
    │   ├── common/
    │   │   ├── event.h        THE contract between kernel and user space (section 6)
    │   │   └── limits.h       shared sizes (path length, comm length)
    │   ├── bpf/
    │   │   ├── monitor.bpf.c  the kernel programs (hooks)
    │   │   ├── helpers.bpf.h  path extraction, filter checks, drop counter
    │   │   └── vmlinux.h      generated type info, see section 8.5
    │   ├── loader/
    │   │   └── loader.c/.h    open, set parameters, load, attach, verify, destroy
    │   ├── core/
    │   │   ├── reader.c/.h    ring buffer polling, hands raw events to the pipeline
    │   │   ├── pipeline.c/.h  runs an event through the stages in order
    │   │   ├── enrich.c/.h    uid to name, cmdline cache, container id
    │   │   └── filter.c/.h    user-space filters (glob, comm, exclusions)
    │   ├── sinks/
    │   │   ├── sink.h         the output interface (section 7)
    │   │   ├── text.c         human-readable lines
    │   │   └── jsonl.c        one JSON object per line
    │   ├── cli/
    │   │   └── cli.c/.h       getopt_long, produces a plain options struct
    │   ├── modes/
    │   │   ├── modes.h        one function per mode
    │   │   ├── watch.c        wires everything for `fguard watch`
    │   │   ├── guard.c        (later)
    │   │   └── top.c          (later)
    │   ├── guard/             (later) config.c (libucl), rules.c, alerts.c, dedup.c
    │   ├── tui/               (later) ncurses code only
    │   └── util/
    │       ├── log.c/.h       diagnostics to stderr, levels
    │       ├── time.c/.h      boot-time nanoseconds to wall clock
    │       └── cache.c/.h     small bounded cache (uid names, cmdlines)
    ├── tests/
    │   ├── unit/              pipeline, filters, jsonl formatting, glob matching
    │   ├── fixtures/          recorded .jsonl event files for replay
    │   └── e2e/               shell scripts: run watch, touch a file, check output
    └── build/                 all generated files, never committed