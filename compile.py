import os

def main():
    base_name = "file"

    try:
        os.system(f"cd build && cmake .. ")
        os.system(f"cd build && cmake --build .")

    except Exception as e:
        print(e)
        exit(1)



if __name__ == "__main__":
    main()
