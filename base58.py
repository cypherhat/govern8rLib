import hashlib

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58_encode(n):
    result = ''
    while n > 0:
        result = b58[n % 58] + result
        n /= 58
    return result


def count_leading_chars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count


def base256_decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result


def base58_check_encode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leading_zeros = count_leading_chars(result, '\0')
    return '1' * leading_zeros + base58_encode(base256_decode(result))

