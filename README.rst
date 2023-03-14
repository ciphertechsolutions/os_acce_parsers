Open-Source ACCE Parsers
============

This is a collection of the parsers and signatures developed by Cipher Tech Solutions for the frameworks
`DC3-MWCP`_ , `Dragodis`_,  `Rugosa`_, and `YARA`_.

.. _DC3-MWCP: https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP
.. _Dragodis: https://github.com/dod-cyber-crime-center/Dragodis
.. _Rugosa: https://github.com/dod-cyber-crime-center/rugosa
.. _YARA: https://virustotal.github.io/yara/


Install
-------
You can clone this repo and install locally

.. code-block:: rst

    > git clone https://github.com/ciphertechsolutions/os_acce_parsers.git
    > pip install ./os_acce_parsers


Usage
-----

This package extends the existing DC3-MWCP framework with extra parsers.

You can confirm the parsers are installed by using the ``list`` command for MWCP::

    mwcp list
