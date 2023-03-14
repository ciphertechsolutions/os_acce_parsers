"""
Description: Stealc parser

"""
import base64
import binascii
import re
from typing import Iterable, Optional, Tuple

import regex

from mwcp import Parser, FileObject, metadata
import dragodis
from dragodis import Disassembler
from dragodis.interface import Function
from dragodis.interface.types import OperandType
import rugosa
from rugosa import Emulator

from os_acce_parsers.utils import log_bookends
from os_acce_parsers.utils.ciphers.rc4_skipkey import RC4SkipKey


class Stealer(Parser):
    DESCRIPTION = "Stealc Stealer"

    EXPECTED = "decrypted strings, an RC4 key, c2 url, and url paths"

    RC4 = re.compile(
        # 0d049f764a22e16933f8c3f1704d4e50 @ 0x00402f42
        br"""
            \x8b\x3d(?P<src>.{4})   # mov     edi, rc4_key
            \x8b\xcf                # mov     ecx, edi; a1
            \x33\xdb                # xor     ebx, ebx
            \x33\xf6                # xor     esi, esi
            \xe8.{4}                # call    get_strlen
            \x8b\xc8                # mov     ecx, eax
            \x33\xd2                # xor     edx, edx
            \x8b\xc6                # mov     eax, esi
            \xf7\xf1                # div     ecx
            \x89\xb4\xb5.{4}        # mov     [ebp+esi*4+var_410], esi
            \x46                    # inc     esi
            \x0f\xb6\x04\x3a        # movzx   eax, byte ptr [edx+edi]
            \x89\x84\xb5.{4}        # mov     [ebp+esi*4+var_814], eax
            \x81\xfe\x00\x01\x00{2} # cmp     esi, 100h
            \x7c\xdf                # jl      short loc_402F55
        """,
        re.DOTALL | re.VERBOSE
    )
    URLPATH_PTN = regex.compile("/[\w\d/]+(\.\w+)?")
    URL_PTN = regex.compile("https?://[\w\d]+.+?")

    @classmethod
    def identify(cls, file_object: FileObject) -> bool:
        """
        Validate input file is Stealc

        :param FileObject file_object: Input file

        :return: If input file is Stealc
        :rtype: bool
        """
        return bool(file_object.pe and cls.RC4.search(file_object.data))

    def get_function(self, xref: int, dis: Disassembler):
        """
        Acquire the function at the xref. If a function does not exist, attempt to create one.

        :param int xref:
        :param Disassembler dis: Dragodis disassembler

        :return: Function at xref
        :rtype: Function
        """
        try:
            return dis.get_function(xref)
        except dragodis.NotExistError as e:
            line = dis.get_line(xref)
            if line.is_code:
                start = None
                end = None
                for curr in dis.lines(xref, reverse=True):
                    if curr.is_code:
                        # If the code is already in another function then break
                        try:
                            _ = dis.get_function(curr.address)
                            break
                        except dragodis.NotExistError:
                            start = curr.address
                    else:
                        break
                for curr in dis.lines(xref):
                    if curr.is_code:
                        # If the code is already in another function then break
                        try:
                            _ = dis.get_function(curr.address)
                            break
                        except dragodis.NotExistError:
                            end = curr.address
                    else:
                        break
                if start and end and start != end:
                    if dis._ida_funcs.add_func(start, end):
                        return dis.get_function(xref)
                    self.logger.warning(
                        f"Failed to create function for 0x{xref:08x} using start address 0x{start:08x} and end "
                        f"address 0x{end:08x}"
                    )
            raise dragodis.NotExistError(e)

    def iter_xrefs(self, rc4_func: Function, dis: Disassembler) -> Iterable[int]:
        """
        Iterate calls to the string decryption function, which calls the RC4-SkipKey decryption function

        :param Function rc4_func: RC4-SkipKey decryption function
        :param Disassembler dis: Dragodis disassembler

        :yield: Xrefs to String decryption (Base64 + RC4-SkipKey)
        """
        # Iterate callers for the RC4-SkipKey function
        for func in rc4_func.callers:
            # Iterate xrefs to the string decryption function
            for xref in func.calls_to:
                try:
                    # Validate there is a function at the location before processing, primary functions likely
                    # haven't been created due to obfuscation
                    _ = self.get_function(xref, dis)
                    yield xref
                except dragodis.NotExistError:
                    self.logger.warning(f"Failed to acquire a function for xref to string decryption at 0x{xref:08x}")

    def get_rc4(self, dis: Disassembler, emu: Emulator) -> Optional[Tuple[RC4SkipKey, Function]]:
        """
        Acquire the RC4-SkipKey cipher and function, and report the key

        :param Disassembler dis: Dragodis disassembler
        :param Emulator emu: Rugosa emulator

        :return: RC4-SkipKey cipher and function
        :rtype: tuple
        """
        for match in rugosa.re.finditer(self.RC4, dis):
            addr = int.from_bytes(match.group("src"), "little")
            # Iterate xrefs to the global address used for the RC4 key to identify where it is populated
            for xref in dis.references_to(addr):
                mnem = dis.get_mnemonic(xref.from_address)
                # Validate population of the global address and acquire the key
                if mnem == "mov" and dis.get_operand_type(xref.from_address, 1) == OperandType.immediate:
                    try:
                        # Validate there is a function at the location before processing, primary functions likely
                        # haven't been created due to obfuscation
                        _ = self.get_function(xref.from_address, dis)
                        ctx = emu.context_at(xref.from_address)
                        src = ctx.operands[1].addr
                        if key := ctx.memory.read_data(src):
                            self.report.add(metadata.EncryptionKey(key, "RC4-SkipKey"))
                            return RC4SkipKey(key), dis.get_function(match.start())
                    except dragodis.NotExistError:
                        self.logger.warning(
                            f"Failed to acquire function at 0x{xref.from_address:08x} to acquire RC4 key, no "
                            f"further analysis can be performed."
                        )
        self.logger.warning(f"The RC4 decryption cipher was not identified, no further analysis can be performed.")

    def run(self, *args):
        """
        Acquire the RC4 cipher and function address, then iterate encrypted strings for decryption/reporting and
        evaluation for metadata reporting

        :return:
        """
        with log_bookends(self):
            # TODO: Evaluate Ghidra when functions can be reliably created
            with self.file_object.disassembly("ida") as dis:
                emu = rugosa.Emulator(dis)
                if rc4_info := self.get_rc4(dis, emu):
                    rc4, rc4_func = rc4_info
                    for xref in self.iter_xrefs(rc4_func, dis):
                        ctx, args = emu.get_function_args(xref)
                        src, *_ = args
                        if encrypted := ctx.memory.read_data(src.value):
                            try:
                                decrypted = rc4.decrypt(base64.b64decode(encrypted))
                                encoding = rugosa.detect_encoding(decrypted)
                                value = decrypted.decode(encoding)
                                self.report.add(metadata.DecodedString(value))
                                if self.URL_PTN.fullmatch(value):
                                    self.report.add(metadata.URL(value))
                                elif self.URLPATH_PTN.fullmatch(value):
                                    self.report.add(metadata.URL(path=value))
                            except (binascii.Error, UnicodeDecodeError):
                                self.logger.warning(f"Failed to decrypt {encrypted} at 0x{xref:08x}.")
                        else:
                            self.logger.warning(f"Failed to get encrypted string at 0x{xref:08x}")


