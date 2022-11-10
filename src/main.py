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
    orig_len = len(message) #storing the length of the key
    message = message.encode() #we use encode to UTF-8
    while len(message) % 12 != 0:
        message += chr(ord("a") + (len(message) % 26)).encode() #padding the message with bytes
    message_len = str(orig_len)
    while len(message_len) % 12 != 0:
        message_len = chr(ord("a") + (len(message_len) % 26)) + message_len  # concatination of msg with padded text and msg_len
    message += message_len.encode() #UTF-8 encoding

    key = setkeysize(key)

    

    encoded = base64.b64encode(message)
    print(f"Original: {message}\nEncoded: {encoded.decode()}") #printing the padded message and the base64 encoded text
    encrypted = ""
    blocks = []
    for i in range(len(encoded) // 16): #breaking it into 16 bit blocks as 6bit turns to 8bit after base64 encoding
        block = encoded[i * 16 : i * 16 + 16].decode() #block is sliced in 16 character words and this decode just converts utf-8 string to normal string
        blocks.append("")  #blocks is an empty string that will store the base
        mixed = 0
        for byte in block:
            mixed ^= from_base64(byte) #calculating mixed wrt to the text in block of character, so unique every time
        final = ""
        for i in block:
            final += to_base64(from_base64(i) ^ mixed) #xoring all character w mixed to make an encrypted text
        block = final
        for (x, y) in zip(block, key): #zip corresponds to elements in the 2 lists into a single tuple
            blocks[-1] += substitute(x, y) # substitute is the vigenere cipher table substitution

        key = key[1:] + key[:1] #left circular shift
        for byte in block:
            key = "".join(map(lambda x: xor(byte, x), key)) #xor all the elements in block with corresponding character in key

        encrypted = "".join(blocks)

    print(f"Encrypted: {encrypted}")
    encrypted = base64.b64decode(encrypted)

    return encrypted


def decrypt(encrypted, key):
    key = setkeysize(key)
    decrypted = base64.b64encode(encrypted)
    blocks = []
    for i in range(len(decrypted) // 16):
        block = decrypted[i * 16 : i * 16 + 16].decode() #take 16 character blocks
        blocks.append("")
        for (x, y) in zip(block, key):
            blocks[-1] += inv_substitute(x, y) #find the inverse substitute of the key
        inv_block = blocks[-1]
        thing = [0 for i in range(16)]
        for i in range(16):
            for j in range(16):
                if i != j:
                    thing[i] ^= from_base64(inv_block[j]) #calculating the initial character before it was encrypted,converting to integer val of base64 char xoring again gives org. character
        blocks[-1] = "".join(map(to_base64, thing)) #converting back to original plaintext


        key = key[1:] + key[:1] #left circular shift
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
    # print_table()


if __name__ == "__main__":
    main()
