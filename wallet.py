from blockchainexplorer import *


class Wallet:
    def __init__(self, private_key=None):
        if (private_key != None):
            self.private_key = private_key
        else:
            self.bytes = random_bytes()
            self.private_key = bytes_to_hex(self.bytes)

        self.public_key = privkey_to_pubkey(self.private_key)
        self.address_compressed = pubkey_to_addr(self.public_key, True)
        self.address_uncompressed = pubkey_to_addr(self.public_key, False)
        self.balance = None

        self.info = {}
        self.info["private_key"] = self.private_key
        self.info["public_key"] = self.public_key
        self.info["address_compressed"] = self.address_compressed
        self.info["address_uncompressed"] = self.address_uncompressed

    def get_info(self, private_key=True, public_key=True, address_compressed=True, address_uncompressed=True,
                 balance=True, transactions=True):

        response = {}

        if (private_key):
            response["private_key"] = self.private_key
        if (public_key):
            response["public_key"] = self.public_key
        if (address_compressed):
            response["address_compressed"] = self.address_compressed
        if (address_uncompressed):
            response["address_uncompressed"] = self.address_uncompressed

        if (balance):
            if (self.balance == None):
                response["balance"] = self.get_balance()
            else:
                response["balance"] = self.balance

        if (transactions):
            if (self.transactions == None):
                response["total transactions"] = self.get_transactions()
            else:
                response["total transactions"] = self.transactions

        return response

    def get_balance(self):
        self.balance = get_balance(self.address_compressed, self.address_uncompressed)
        self.info["balance"] = self.balance
        return self.balance

    def get_transactions(self):
        self.transactions = get_transaction(self.address_compressed, self.address_uncompressed)
        self.info["total transactions"] = self.transactions
        return self.transactions

    def next_wallet(self):
        next_priv_key = next_private_key(self.private_key)
        next_wallet = Wallet(next_priv_key)
        return next_wallet

    def previous_wallet(self):
        previous_priv_key = previous_private_key(self.private_key)
        previous_wallet = Wallet(previous_priv_key)
        return previous_wallet
