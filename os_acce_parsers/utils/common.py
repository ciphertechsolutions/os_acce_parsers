import contextlib

from mwcp import Parser


@contextlib.contextmanager
def log_bookends(parser: Parser):
    """
    Bookend the run function for the MWCP parser to identify parser running on current file, the expected results, and
    when the parser completes operation

    :param Parser parser: Parser object

    :return:
    """
    if not parser.EXPECTED:
        raise NotImplementedError(f"Expected parameters for parser {parser.DESCRIPTION} were not set.")
    parser.logger.info(
        f"Starting parser {parser.DESCRIPTION} on sample {parser.file_object.name}. Expected results include "
        f"{parser.EXPECTED}."
    )
    try:
        yield
    finally:
        parser.logger.info(f"Completed parsing using {parser.DESCRIPTION} for sample {parser.file_object.name}.")
