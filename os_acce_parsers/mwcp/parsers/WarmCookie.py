"""
Description: WarmCookie MWCP parser
"""

import logging
import functools
from Crypto.Cipher import ARC4
import re
from typing import Iterable, List

from mwcp import Parser, FileObject, metadata
from mwcp.utils import construct
from mwcp.utils.construct import this
import dragodis
from dragodis import Disassembler
from dragodis.interface.types import ReferenceType
import rugosa
from rugosa import Emulator
from rugosa.emulation.cpu_context import ProcessorContext
from rugosa.emulation.instruction import Instruction

from os_acce_parsers.utils import log_bookends, rugutils


logger = logging.getLogger(__name__)


def decrypt_string_hook(data: bytes, ctx: ProcessorContext, insn: Instruction):
    """
    Write the decrypted data to the destination address

    :param bytes data: Decrypted data
    :param ProcessorContext ctx: Context
    :param Instruction insn: Current instruction

    :return:
    """
    dst = ctx.memory.alloc(len(data))
    logger.debug(f'Writing 0x{data.hex()} to {dst:08x}')
    ctx.memory.write(dst, data)
    ctx.registers['rax'] = dst


class Backdoor(Parser):
    DESCRIPTION = "WarmCookie Backdoor"

    EXPECTED = "RC4 decrypted strings, a c2 socket address, a user-agent, and a named mutex"

    STRING = construct.Struct(
        'size' / construct.Int32ul,
        'key' / construct.Bytes(4),
        'encrypted' / construct.Bytes(this.size)
    )
    DECRYPT_STRING = re.compile(
        # 1b7b6fb1a99996587a3c20ee9c390a9c @ 0x1800063e9
        # 1b7b6fb1a99996587a3c20ee9c390a9c @ 0x180006559
        # 3f22ddf4ebe3658be71a7a9fc93febae @ 0x180005eb7
        br"""
            (
                (
                    (.?\x8b.\x04)|                  # mov     ebp, [rcx+4]
                    (\x48\x8d.\x08)|                # lea     rdi, [rcx+8]
                    (\x8b.)                         # mov     esi, [rcx]
                ){3}
                .{,6}?
                \x89.\x24.                          # mov     [rsp+158h+var_138], ebp
                .{,6}?
                .\x8d.[\x09\x0a]                    # lea     rcx, [rsi+9]
                .{5,16}?
                [\x48-\x4c][\x89\x8b][\xc1-\xc8]    # mov     r9, rax
                \x48\x85\xc0                        # test    rax, rax
            )|
            (
                # 12aa84e2e56ae684d211679072695906 @ 0x180007087
                # 0d7f58cb43f59d78fdb10627835e5977 @ 0x2eda37d92
                \x48\x8b(?P<a0>.{5,6})                  # mov     rax, [rsp+168h+arg_0]
                \x8b\x00                                # mov     eax, [rax]
                \x89(?P<sv>((\x44\x24.)|(\x85.{4})))    # mov     [rsp+168h+var_148], eax
                \x48\x8b(?P=a0)                         # mov     rax, [rsp+168h+arg_0]
                \x8b\x40\x04                            # mov     eax, [rax+4]
                \x89((\x44\x24.)|(\x85.{4}))            # mov     [rsp+168h+var_138], eax
                \x48\x8b(?P=a0)                         # mov     rax, [rsp+168h+arg_0]
                \x48\x83\xc0\x08                        # add     rax, 8
                \x48\x89((\x44\x24.)|(\x85.{4}))        # mov     [rsp+168h+var_130], rax
                \x8b(?P=sv)                             # mov     eax, [rsp+168h+var_148]
                \x48\x83\xc0[\x09\x0a]                  # add     rax, 9
                \x48.{2}                                # mov     rcx, rax
                \xe8.{4}                                # call    sub_180005D60
                \x48\x89((\x44\x24.)|(\x85.{4}))        # mov     [rsp+168h+var_140], rax
                \x48\x83.{3,5}\x00                      # cmp     [rsp+168h+var_140], 0
            )|
            (
                # 1b7f494c383385d9f76d17e5a9d757d3 @ 0x2eda35e4e
                (
                    (\x8b.)|                        # mov     esi, [rcx]
                    (.?\x8b.\x04)                   # mov     eax, [rcx+4]
                ){2}
                .{,6}?
                .\x8d.[\x09\x0a]                    # lea     rcx, [rsi+0Ah]
                \x89.\x24.                          # mov     [rsp+168h+var_13C], eax
                .{5,16}?
                 [\x48-\x4c][\x89\x8b][\xc1-\xc8]   # mov     r12, rax
                \x48\x85\xc0                        # test    rax, rax
            )
        """,
        re.DOTALL | re.VERBOSE
    )

    @classmethod
    def identify(cls, file_object: FileObject) -> bool:
        """
        Validate string decryption is detected

        :param FileObject file_object: Input file

        :return: String decryption is detected
        :rtype: bool
        """
        return bool(file_object.pe and cls.DECRYPT_STRING.search(file_object.data))

    def report_c2(self, iconnw: rugutils.ResolvedAPI, dis: Disassembler, emu: Emulator):
        """
        Report a c2 socket address and useragent from a call to the function which calls InternetConnectW

        :param rugutils.ResolvedAPI iconnw: Resolved InternetConnectW API
        :param Disassembler dis: Dragodis disassembler
        :param Emulator emu: Rugosa emulator

        :return:
        """
        for ref in iconnw.line.references_to:
            # A data read can indicate a direct call or passing to a register for a call
            if ref.type != ReferenceType.data_read:
                continue
            try:
                func = dis.get_function(ref.from_address)
            except dragodis.NotExistError:
                self.logger.warning(f'Failed to acquire c2 comms function at 0x{ref:08x}')
                continue
            func.name = 'C2Comms'
            for xref in func.calls_to:
                try:
                    ctx, args = emu.get_function_args(xref)
                except dragodis.NotExistError:
                    self.logger.warning(f'Failed to acquire arguments for xref to c2 comms function at 0x{xref:08x}')
                    continue
                ua_src, addr_src, port, *_ = args
                useragent = ctx.memory.read_string(ua_src.value, wide=True)
                self.report.add(metadata.UserAgent(useragent))
                addr = ctx.memory.read_string(addr_src.value, wide=True)
                self.report.add(metadata.Socket2(addr, port.value, 'tcp').add_tag('c2'))
                return
        self.logger.warning(
            f'Failed to report a c2 socket address from resolved InternetConnectW at 0x{iconnw.line.address:08x}'
        )

    def iter_mutexes(self, dis: Disassembler, emu: Emulator) -> Iterable[str]:
        """
        Iterate mutexes from calls to CreateMutexW

        :param Disassembler dis: Dragodis disassembler
        :param Emulator emu: Rugosa emulator

        :yield: Named mutexes
        """
        for ctx, args in rugutils.iter_imp_args('CreateMutexW', dis, emu):
            try:
                src = args[2].value
                # Avoid processing data at an unmapped offset
                if src == 0:
                    continue
                if value := ctx.memory.read_string(src, wide=True):
                    yield value
            except IndexError:
                logger.warning(f"Not enough arguments for call to CreateMutexW at 0x{ctx.ip:08x}")

    def iter_xrefs(self, dis: Disassembler) -> Iterable[int]:
        """
        Iterate xrefs to decrypt string functions

        :param Disassembler dis: Dragodis disassmebler

        :yield: Xrefs to decrypt string functions
        """
        for func in rugosa.re.find_functions(self.DECRYPT_STRING, dis):
            self.logger.debug(f'Identified string decryption function at 0x{func.start:08x}')
            func.name = 'DecryptString'
            yield from func.calls_to

    def iter_strings(self, dis: Disassembler, emu: Emulator) -> Iterable[str]:
        """
        Decrypt and iterate strings

        :param Disassembler dis: Dragodis disassembler
        :param Emulator emu: Rugosa emulator

        :yield: Decrypted strings
        """
        for xref in self.iter_xrefs(dis):
            try:
                ctx, args = emu.get_function_args(xref)
            except dragodis.NotExistError:
                self.logger.warning(f'Failed to obtain arguments for call to string decryption at 0x{xref:08x}')
                continue
            src, *_ = args
            with ctx.memory.open(src.value) as stream:
                try:
                    info = self.STRING.parse_stream(stream)
                except construct.ConstructError:
                    self.logger.warning(
                        f'Failed to parse encrypted string information from 0x{src.value:08x} at xref 0x{xref:08x}'
                    )
                    continue
            rc4 = ARC4.new(info.key)
            decrypted = rc4.decrypt(info.encrypted)
            # Hook for mutex reporting, api resolution and c2 config reporting
            emu.hook_instruction(xref, functools.partial(decrypt_string_hook, decrypted), pre=False)
            encoding = rugosa.detect_encoding(decrypted)
            try:
                string = decrypted.decode(encoding)
                line = dis.get_line(xref)
                line.set_comment(string)
                yield string
            except UnicodeDecodeError:
                self.logger.warning(f'Failed to {encoding} decode string from xref 0x{xref:08x}')

    def run(self, *args):
        """
        Decrypt strings, report mutexes, and resolve APIs to report c2 configuration

        :return:
        """
        with log_bookends(self):
            # Parser is supported by both IDA and Ghidra
            with self.file_object.disassembly(report=self.report) as dis:
                emu = Emulator(dis)
                for string in self.iter_strings(dis, emu):
                    self.report.add(metadata.DecodedString(string))
                for mutex in self.iter_mutexes(dis, emu):
                    self.report.add(metadata.Mutex(mutex))
                for api in rugutils.iter_proc_address_resolution(dis, emu):
                    if api.name == 'InternetConnectW':
                        self.report_c2(api, dis, emu)
