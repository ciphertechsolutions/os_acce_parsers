"""
General helpers for Rugosa
"""
import logging
from typing import List, Iterable, Tuple

import dragodis
from dragodis import Disassembler
from rugosa import Emulator
from rugosa.emulation.cpu_context import ProcessorContext
from rugosa.emulation.functions import FunctionArgument


logger = logging.getLogger(__name__)


def iter_imp_args(
        func_name: str, dis: Disassembler, emu: Emulator, loop: bool = False, iter_args: bool = False
) -> Iterable[Tuple[ProcessorContext, List[FunctionArgument]]]:
    """
    Iterate context and arguments for a call to an import

    :param str func_name: Import function name
    :param Disassembler dis: Disassembler object
    :param Emulator emu: Emulator object
    :param bool loop: Enable follow_loops during emulation
    :param bool iter_args: Enable following different paths for call to function

    :yield: Context and function arguments
    """
    try:
        imp = dis.get_import(func_name)
        for xref in imp.calls_to:
            try:
                for ctx, args in emu.iter_function_args(xref, follow_loops=loop):
                    yield ctx, args
                    if not iter_args:
                        break
            except dragodis.NotExistError:
                logging.warning(f"Failed to acquire arguments from call to {func_name} at 0x{xref:08x}")
    except dragodis.NotExistError:
        pass
