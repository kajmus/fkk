file(REMOVE_RECURSE
  "CMakeFiles/generate_bpf_skeletons"
  "bpf_generated/vmlinux.h"
  "bpf_generated/watch.bpf.o"
  "bpf_generated/watch.skel.h"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/generate_bpf_skeletons.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
