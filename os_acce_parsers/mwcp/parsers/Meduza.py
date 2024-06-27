"""
Description: Parser for Meduza Stealer

"""

from collections import defaultdict
import re
from typing import List, Callable, Tuple

import pefile
import regex

from mwcp import Parser, FileObject, metadata
import dragodis
from dragodis import Disassembler
from dragodis.interface.types import OperandType
import rugosa
from rugosa import Emulator
from rugosa.emulation.cpu_context import ProcessorContext
from rugosa.emulation.operands import Operand

from os_acce_parsers.utils import log_bookends


class Base(Parser):
    EXPECTED = "decrypted strings, a c2 socket address, and possibly a missionid"

    MIN_MATCHES = 350
    MISSIONID = re.compile(b"timezone\x00+(?P<mid>[\w\d]+)\x00+ip\x00")
    # language=PythonVerboseRegExp
    IPv4 = regex.compile(
        r"""
            (?(DEFINE)
                (?P<octet>25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)    # number from 0 - 255
            )
            (?&octet)(?:\.(?&octet)){3}                         # 4 octets separated by .
        """,
        re.DOTALL | re.VERBOSE
    )

    # MUST be implemented by child class
    XOR_CALC_SIZE = None
    PE_TYPE = None

    @classmethod
    def identify(cls, file_object: FileObject) -> bool:
        """
        Validate
        :param file_object:
        :return:
        """
        return bool(
            file_object.pe
            and file_object.pe.PE_TYPE == cls.PE_TYPE
            and len(cls.XOR_CALC_SIZE.findall(file_object.data)) > cls.MIN_MATCHES
        )

    def get_port(self, ea: int, dis: Disassembler, emu: Emulator):
        """
        Acquire the port, which is added to a global address from the 'ax' register after the c2 address is decrypted

        :param int ea: Reference ea for c2 address decryption
        :param Disassembler dis: Dragodis disassembler
        :param Emulator emu: Rugosa emulator

        :return:
        """
        func = dis.get_function(ea)
        for inst in func.instructions(ea):
            if (
                    inst.mnemonic == 'mov'
                    and inst.operands[0].type == OperandType.memory
                    and inst.operands[1].type == OperandType.register
                    and inst.operands[1].value.name == 'ax'
            ):
                ctx = emu.context_at(inst.address)
                return ctx.operands[1].value

    def get_hook_func(self, decrypted: List[Tuple[int, str]]) -> Callable:
        raise NotImplementedError('Get hook function was not implemented.')

    def run(self, *args):
        """
        Decrypt strings for reporting and evaluation for c2 socket address reporting

        :return:
        """
        with log_bookends(self):
            if match := self.MISSIONID.search(self.file_object.data):
                self.report.add(metadata.MissionID(match.group("mid").decode("utf-8")))
            decrypted = []
            hook_func = self.get_hook_func(decrypted)
            # Use IDA due to excessive runtime using Ghidra
            with self.file_object.disassembly('ida') as dis:
                emu = rugosa.Emulator(dis)
                funcs = defaultdict(list)
                for match in rugosa.re.finditer(self.XOR_CALC_SIZE, dis):
                    offset = match.start("s")
                    try:
                        func = dis.get_function(offset)
                        funcs[func.start].append(offset)
                        emu.hook_instruction(offset, hook_func)
                    except dragodis.NotExistError:
                        pass

                # Acquire the context at the last offset in each function where string decryption occurs, capturing the
                # decrypted strings in the global list due to the hook
                for offsets in funcs.values():
                    addr = dis.next_line_address(max(offsets))
                    _ = emu.context_at(addr)

                # We've already acquired decrypted strings, avoid triggering the hook when later finding the port which
                # can create an infinite loop
                emu.clear_hooks()

                for offset, value in decrypted:
                    self.report.add(metadata.DecodedString(value).add_tag(f"{offset:08x}"))
                    if self.IPv4.fullmatch(value):
                        port = self.get_port(offset, dis, emu)
                        self.report.add(metadata.Socket2(value, port, 'tcp').add_tag('c2'))


class Stealerx86(Base):
    DESCRIPTION = "Meduza Stealer (x86)"

    XOR_CALC_SIZE = re.compile(
        # 9022192413dda223b6e8afd73a22cfaa @ 0x00435290
        # 9022192413dda223b6e8afd73a22cfaa @ 0x0042db87
        br"""
            (
                (\x66\x0f\xef)|         # pxor    xmm1, xmmword ptr [ebp-140h]
                (\xc5[\xf1-\xfd]\xef)   # vpxor   xmm1, xmm1, xmmword ptr [ebp-16A0h]
            )
            .{5,60} 
            (\x8a\x01                   # mov     al, [ecx]
            \x41                        # inc     ecx
            \x84\xc0                    # test    al, al
            \x75\xf9                    # jnz     short loc_434DB4
            (?P<s>\x2b\xca))            # sub     ecx, edx
        """,
        re.DOTALL | re.VERBOSE
    )
    PE_TYPE = pefile.OPTIONAL_HEADER_MAGIC_PE

    def get_hook_func(self, decrypted: List[Tuple[int, str]]) -> Callable:
        def _hook_func(ctx: ProcessorContext, ip: int, mnem: str, operands: List[Operand]):
            """
            Add the decrypted string to the list and set the size in the target register

            :return:
            """
            src = ctx.registers['ecx'] - 1
            if value := ctx.memory.read_string(src):
                decrypted.append((ip, value))
                size = len(value)
                ctx.registers['ecx'] = size
        return _hook_func


class Stealerx64(Base):
    DESCRIPTION = "Meduza Stealer (x64)"

    XOR_CALC_SIZE = re.compile(
        # 4c213248be08249f75b68d85dcdf3365 @ 0x14001cf2e
        br"""
            (
                (\x66\x0f\xef)|         # pxor    xmm0, xmmword ptr [rsp+48h+var_18]
                (\xc5[\xf1-\xfd]\xef)
            )
            .{5,60}
            \x49\xff\xc0                # inc     r8
            \x42\x80\x3c\x00{2}         # cmp     byte ptr [rax+r8], 0
            (?P<s>\x75\xf6)             # jnz     short loc_14001CF60
        """,
        re.DOTALL | re.VERBOSE
    )
    PE_TYPE = pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS

    def get_hook_func(self, decrypted: List[Tuple[int, str]]) -> Callable:
        def _hook_func(ctx: ProcessorContext, ip: int, mnem: str, operands: List[Operand]):
            """
            Add the decrypted string to the list and set the size in the target register

            :return:
            """
            src = ctx.registers['rax']
            if value := ctx.memory.read_string(src):
                decrypted.append((ip, value))
                size = len(value)
                ctx.registers['r8'] = size
        return _hook_func
