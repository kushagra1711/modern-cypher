import base64

alphas = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def to_base64(a):
    # return alphas[a % 64]
    if a // 26 == 0:
        return chr(ord("A") + a % 26)
    elif a // 26 == 1:
        return chr(ord("a") + a % 26)
    elif a // 26 == 2:
        if a % 26 <= 9:
            return chr(ord("0") + a % 26)
        elif a % 26 == 10:
            return "+"
        elif a % 26 == 11:
            return "/"


def from_base64(b):
    # return dict(zip(alphas, range(len(alphas))))[b]
    if ord(b) - ord("A") < 26 and ord(b) - ord("A") >= 0:
        return ord(b) - ord("A")
    elif ord(b) - ord("a") < 26 and ord(b) - ord("a") >= 0:
        return 26 + ord(b) - ord("a")
    elif ord(b) - ord("0") < 10 and ord(b) - ord("0") >= 0:
        return 52 + ord(b) - ord("0")
    elif b == "+":
        return 62
    elif b == "/":
        return 63


def substitute(a, b):
    return to_base64((from_base64(a) + from_base64(b)) % 64)


def inv_substitute(a, b):
    return to_base64((from_base64(a) - from_base64(b)) % 64)


def xor(a, b):
    return to_base64((from_base64(a) ^ from_base64(b)) % 64)


def print_table():
    print("  ", end="")
    for i in alphas:
        print(f"{i} ", end="")
    print()
    for i in alphas:
        print(f"{i} ", end="")
        for j in alphas:
            print(f"{substitute(i, j)} ", end="")
        print()
    print()


def setkeysize(key):
    key = key.encode()
    if len(key) < 12:
        key = key * (12 // len(key)) + key[: 12 % len(key)]
    elif len(key) > 12:
        key = key[:12]
    key = base64.b64encode(key)
    assert len(key) % 16 == 0
    return key.decode()


def encrypt(message, key):
    orig_len = len(message)
    message = message.encode()
    while len(message) % 12 != 0:
        message += chr(ord("a") + (len(message) % 26)).encode()
    message_len = str(orig_len)
    while len(message_len) % 12 != 0:
        message_len = chr(ord("a") + (len(message_len) % 26)) + message_len
    message += message_len.encode()

    key = setkeysize(key)

    encoded = base64.b64encode(message)
    print(f"Original: {message}\nEncoded: {encoded.decode()}")
    encrypted = ""
    blocks = []
    for i in range(len(encoded) // 16):
        block = encoded[i * 16 : i * 16 + 16].decode()
        blocks.append("")
        mixed = 0
        for byte in block:
            mixed ^= from_base64(byte)
        final = ""
        for i in block:
            final += to_base64(from_base64(i) ^ mixed)
        block = final
        for (x, y) in zip(block, key):
            blocks[-1] += substitute(x, y)

        key = key[1:] + key[:1]
        for byte in block:
            key = "".join(map(lambda x: xor(byte, x), key))

        encrypted = "".join(blocks)

    print(f"Encrypted: {encrypted}")
    encrypted = base64.b64decode(encrypted)

    return encrypted


def decrypt(encrypted, key):
    key = setkeysize(key)
    decrypted = base64.b64encode(encrypted)
    blocks = []
    for i in range(len(decrypted) // 16):
        block = decrypted[i * 16 : i * 16 + 16].decode()
        blocks.append("")
        for (x, y) in zip(block, key):
            blocks[-1] += inv_substitute(x, y)
        inv_block = blocks[-1]
        thing = [0 for i in range(16)]
        for i in range(16):
            for j in range(16):
                if i != j:
                    thing[i] ^= from_base64(inv_block[j])
        blocks[-1] = "".join(map(to_base64, thing))

        key = key[1:] + key[:1]
        for byte in blocks[-1]:
            key = "".join(map(lambda x: xor(byte, x), key))

    decrypted = "".join(blocks)
    print(f"Decrypted: {decrypted}")
    decrypted = base64.b64decode(decrypted.encode()).decode()
    orig_len = decrypted[-12:].lstrip("abcdefghijklmnopqrstuvwxyz")

    return decrypted[: int(orig_len)]


def main():
    message = input("Message: ")
    key = input("Key: ")

    encrypted = encrypt(message, key)
    # for byte in encrypted:
    #     print("0x{:02x}".format(byte), end=" ")
    # print()
    decrypted = decrypt(encrypted, key)
    print(f"Message: {decrypted}")


if __name__ == "__main__":
    main()
