import os

def main():
    base_name = "bootstrap"

    try:
        os.system(f"clang -target bpf -O2 -g -c {base_name}.bpf.c -o {base_name}.bpf.o")
        os.system(f"bpftool gen skeleton {base_name}.bpf.o > {base_name}.skel.h")
        os.system(f"gcc {base_name}.c -lbpf -lelf -lz -o {base_name}")
    except Exception as e:
        print(e)
        exit(1)



if __name__ == "__main__":
    main()
