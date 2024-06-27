"""
Helpers for API resolution in Rugosa
"""
from dataclasses import dataclass
import logging
from typing import Iterable

import regex

import dragodis
from dragodis import Disassembler
from dragodis.interface.types import ReferenceType
from dragodis.interface import Line
import rugosa
from rugosa import Emulator

from .helpers import iter_imp_args


logger = logging.getLogger(__name__)


VALID_API = regex.compile("[\w\d]+")


@dataclass
class ResolvedAPI:
    name: str
    line: Line


def iter_resolved_xrefs(api: ResolvedAPI, dis: Disassembler) -> Iterable[int]:
    """
    Iterate calls to a resolved API

    :param ResolvedAPI api: Resolved API
    :param Disassembler dis: Dragodis disassembler

    :yield: Xrefs to resolved API
    """
    for ref in api.line.references_to:
        if ref.type == ReferenceType.data_read and dis.get_mnemonic(ref.from_address) == 'call':
            yield ref.from_address


def iter_proc_address_line_resolution(gpa: ResolvedAPI, dis: Disassembler, emu: Emulator) -> Iterable[ResolvedAPI]:
    """
    From dynamically resolved GetProcAddress calls, iterate resolved APIs

    :param ResolveAPI gpa: Resolved GetProcAddress API
    :param Disassembler dis: Dragodis disassembler
    :param Emulator emu: Rugosa emulator

    :yield: Resolved APIs
    """
    for xref in iter_resolved_xrefs(gpa, dis):
        try:
            ctx, args = emu.get_function_args(xref)
        except dragodis.NotExistError:
            logger.debug(f'Failed to acquire API name for call to GetProcAddress at 0x{xref:08x}')
            continue
        _, src = args
        try:
            name = ctx.memory.read_string(src.value)
        except UnicodeDecodeError:
            logger.debug(f'Failed to acquire API name for call to GetProcAddress at 0x{xref:08x}')
            continue
        if not VALID_API.fullmatch(name):
            continue
        if dest := rugosa.find_destination(dis, xref):
            if resolved := dis.get_line(int(dest)):
                resolved.name = name
                api = ResolvedAPI(name, resolved)
                yield api
                if name == 'GetProcAddress':
                    yield from iter_proc_address_line_resolution(api, dis, emu)


def iter_proc_address_resolution(dis: Disassembler, emu: Emulator) -> Iterable[ResolvedAPI]:
    """
    Dynamically resolve APIs from calls to GetProcAddress

    :param Disassembler dis: Dragodis disassembler
    :param Emulator emu: Rugosa emulator

    :yield: Resolved APIs
    """
    for ctx, args in iter_imp_args('GetProcAddress', dis, emu):
        _, src = args
        try:
            name = ctx.memory.read_string(src.value)
        except UnicodeDecodeError:
            logger.debug(f'Failed to acquire API name for call to GetProcAddress at 0x{ctx.ip:08x}')
            continue
        if not VALID_API.fullmatch(name):
            continue
        if dest := rugosa.find_destination(dis, ctx.ip):
            if resolved := dis.get_line(int(dest)):
                resolved.name = name
                api = ResolvedAPI(name, resolved)
                yield api
                if name == 'GetProcAddress':
                    yield from iter_proc_address_line_resolution(api, dis, emu)