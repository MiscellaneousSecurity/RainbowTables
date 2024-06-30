'''This is the password fetcher.'''
import lzma


def fetch_passwords(password_xz_file_name:str = "password-list.txt.xz") -> set[bytes]: 
    ''' '''
    with lzma.open(f"passwords/{password_xz_file_name}", 'rb') as pswf:
        pass_set = set(())
        for line in pswf.readlines():
            line = line.strip(b"\n")
            pass_set.add(line)
        return pass_set

if __name__ == '__main__':
    print(fetch_passwords())
