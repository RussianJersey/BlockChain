import hashlib
import base58
import codecs
import ecdsa
import binascii
import mnemonic
import bip32utils
from numpy import byte
import requests
import json
import random

base_url = "https://blockchain.info/balance?cors=true&active="


# Convert private key to public key
def privkey_to_pubkey(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    public_key_raw = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    public_key_bytes = public_key_raw.to_string()
    public_key_hex = codecs.encode(public_key_bytes, 'hex')
    public_key = (b'04' + public_key_hex).decode("utf-8")
    return public_key


# Convert public key to address
def pubkey_to_addr(public_key, compressed):
    if (compressed):
        if (ord(bytearray.fromhex(public_key[-2:])) % 2 == 0):
            public_key_compressed = '02'
        else:
            public_key_compressed = '03'

        public_key_compressed += public_key[2:66]

        hex_str = bytearray.fromhex(public_key_compressed)
    else:
        hex_str = bytearray.fromhex(public_key)

    sha = hashlib.sha256()
    sha.update(hex_str)

    rip = hashlib.new('ripemd160')
    rip.update(sha.digest())
    key_hash = rip.hexdigest()

    modified_key_hash = "00" + key_hash

    sha = hashlib.sha256()
    hex_str = bytearray.fromhex(modified_key_hash)
    sha.update(hex_str)

    sha_2 = hashlib.sha256()
    sha_2.update(sha.digest())

    checksum = sha_2.hexdigest()[:8]

    byte_25_address = modified_key_hash + checksum

    address = base58.b58encode(bytes(bytearray.fromhex(byte_25_address))).decode('utf-8')

    return address


# Convert private key to address
def privkey_to_addr(private_key, compressed):
    public_key = privkey_to_pubkey(private_key)
    address = pubkey_to_addr(public_key, compressed)
    return address


# Convert seed phrase to private key
def bip39(mnemonic_words):
    mobj = mnemonic.Mnemonic("english")
    seed = mobj.to_seed(mnemonic_words)

    bip32_root_key_obj = bip32utils.BIP32Key.fromEntropy(seed)
    bip32_child_key_obj = bip32_root_key_obj.ChildKey(
        44 + bip32utils.BIP32_HARDEN
    ).ChildKey(
        0 + bip32utils.BIP32_HARDEN
    ).ChildKey(
        0 + bip32utils.BIP32_HARDEN
    ).ChildKey(0).ChildKey(0)

    wif = bip32_child_key_obj.WalletImportFormat()
    private_key = wif_to_privkey(wif)

    return private_key


# Convert wif to private key
def wif_to_privkey(wif):
    first_encode = base58.b58decode(wif)
    private_key_full = binascii.hexlify(first_encode)
    private_key = private_key_full[2:-10]
    return private_key.decode("utf-8")


# Get balance of an address
def get_balance(compressedAddress="", uncompressedAddress=""):
    url = base_url + compressedAddress + "," + uncompressedAddress
    response = requests.get(url)
    response = json.loads(response.text)

    balance = 0

    if (compressedAddress != ""):
        balance += response[compressedAddress]["final_balance"]
    elif (uncompressedAddress != ""):
        balance += response[uncompressedAddress]["final_balance"]

    return balance


def get_balances(addresses):
    url = base_url
    for address in addresses:
        url += address + ","

    response = requests.get(url)

    response = json.loads(response.text)

    balances = 0

    for n in range(0, len(addresses)):
        balances += response[addresses[n]]["final_balance"]

    return balances


# Get total transactions of an address
def get_transaction(compressedAddress="", uncompressedAddress=""):
    url = base_url + compressedAddress + "," + uncompressedAddress
    response = requests.get(url)
    response = json.loads(response.text)

    tx = 0

    if (compressedAddress != ""):
        tx += response[compressedAddress]["n_tx"]
    elif (uncompressedAddress != ""):
        tx += response[uncompressedAddress]["n_tx"]

    return tx


# Convert bytes to hex
def bytes_to_hex(bytesArray):
    return ''.join('{:02x}'.format(byte) for byte in bytesArray)


# Convert hex to bytes
def hex_to_bytes(hex):
    return [int(hex[i:i + 2], 16) for i in range(0, len(hex), 2)]


# Get the next private key of a private key
def next_private_key(private_key):
    bytesArray = hex_to_bytes(private_key)
    index = 31
    bytesArray[index] += 1

    while (bytesArray[index] > 255):
        bytesArray[index] = 0
        index -= 1
        bytesArray[index] += 1

    private_key = bytes_to_hex(bytesArray)
    return private_key


# Get the previous private key of a private key
def previous_private_key(private_key):
    bytesArray = hex_to_bytes(private_key)
    index = 31
    bytesArray[index] -= 1

    while (bytesArray[index] < 0):
        bytesArray[index] = 255
        index -= 1
        bytesArray[index] -= 1

    for byte in bytesArray:
        if (byte > 255 or byte < 0):
            return ValueError("Invalid private key")

    valid = False

    for byte in bytesArray:
        if (byte != 0):
            valid = True
            break

    if (valid == False):
        raise ValueError("Invalid private key")

    private_key = bytes_to_hex(bytesArray)
    return private_key


# Get private key index inside the blockchain
def private_key_to_index(private_key):
    bytes = hex_to_bytes(private_key)

    # Reverse byte array
    bytes = bytes[::-1]

    lenBytes = 32
    index = 0

    for n in range(0, lenBytes):
        if (bytes[n] != 0):
            index += 256 ** (n) * bytes[n]

    return index


# Get private key by its index
def private_key_from_index(privateKeyIndex):
    total = privateKeyIndex
    bytes = []
    for n in range(0, 32):
        bytes.append(0)

    for n in range(31, 0, -1):
        value = 255 ** (n)

        while (total > value):
            total -= value
            bytes[n] += 1

    index = 0
    while (total > 0):
        if (bytes[index] == 0 and total >= 255):
            bytes[index] = 255
            total -= 255
        elif (bytes[index] < 255):
            bytes[index] += 1
            total -= 1
        else:
            bytes[index] = 0
            newIndex = index + 1

            while (bytes[newIndex] > 255):
                newIndex += 1

            bytes[newIndex] += 1;

            if (bytes[newIndex] == 255):
                bytes[newIndex] = 0
                bytes[newIndex + 1] += 1

            total -= 255 * newIndex

    # REVERSE BYTES ARRAY
    bytes = bytes[::-1]

    return bytes_to_hex(bytes)


# Generate random bytes
def random_bytes():
    bytesArray = []
    for n in range(0, 32):
        bytesArray.append(random.randint(0, 255))
    return bytesArray


# Generate random private key
def random_private_key():
    bytes = random_bytes()
    private_key = bytes_to_hex(bytes)
    return private_key


# Generate random seed phrase
def random_seed_phrase():
    file = open("./blockchain explorer/english.txt", "r")
    seed_phrase = ""
    words = []
    for word in file.readlines():
        words.append(word.rstrip("\n"))

    for n in range(0, 12):
        seed_phrase += words[random.randint(0, len(words))]
        if (n < 10):
            seed_phrase += " "

    return seed_phrase