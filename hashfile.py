import hashlib


# get hash of a file
def hash_file(path_to_file):
    sha = hashlib.sha256()
    with open(path_to_file, 'rb') as f:
        while True:
            block = f.read(2**10)  # Magic number: one-megabyte blocks.
            if not block:
                break
            sha.update(block)
        return sha.hexdigest()


def main():
    hash_digest = hash_file("bootstrap.ini")
    print hash_digest
    hash_digest = hash_file("C:\Users\Bharathi\Downloads\\beast.jpg")
    print hash_digest

if __name__ == "__main__":
    main()
