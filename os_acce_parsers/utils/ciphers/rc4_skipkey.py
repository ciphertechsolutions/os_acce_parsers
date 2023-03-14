import copy


class RC4SkipKey:
    """
    Custom RC4 implementation (skip decryption if key byte is same as data)

    :param bytes key: the encryption key
    """

    def __init__(self, key: bytes, auto_reset: bool = True, **kwargs):
        self.key = key
        self.auto_reset = auto_reset
        self.i = 0
        self.j = 0
        self._orig_S = self._key_scheduler()
        self.S = copy.copy(self._orig_S)

    def reset(self):
        self.S = copy.copy(self._orig_S)
        self.i = 0
        self.j = 0

    def _key_scheduler(self):
        S = list(range(256))
        j = 0
        ks = len(self.key)
        key = bytes(self.key)
        for i in range(256):
            j = (j + S[i] + key[i % ks]) & 0xff
            S[i], S[j] = S[j], S[i]
        return S

    def _crypt(self, data: bytes) -> bytes:
        """Performs RC4 encryption"""
        decrypted = bytearray()
        i = self.i
        j = self.j
        S = self.S

        for datum in data:
            i = (i + 1) & 0xff
            j = (j + S[i]) & 0xff
            S[i], S[j] = S[j], S[i]
            kb = S[(S[i] + S[j]) & 0xff]
            if datum == kb:
                decrypted.append(datum)
            else:
                decrypted.append((datum ^ kb) & 0xff)
        self.S = S
        self.i = i
        self.j = j
        return bytes(decrypted)

    def _encrypt(self, data: bytes) -> bytes:
        return self._crypt(data)

    def _decrypt(self, data: bytes) -> bytes:
        return self._crypt(data)

    def encrypt(self, data: bytes) -> bytes:
        """Performs encryption on the given data."""
        enc_data = self._encrypt(data)
        if self.auto_reset:
            self.reset()
        return enc_data

    def decrypt(self, data: bytes) -> bytes:
        """Performs decryption on the given data."""
        dec_data = self._decrypt(data)
        if self.auto_reset:
            self.reset()
        return dec_data
