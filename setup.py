import os
from setuptools import setup, find_packages

def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname), 'r') as fo:
        return fo.read()


# Dependencies in 3 or more modules
common = [
    'construct>=2.9.45',
    'pyparsing==2.3.0',
    'regex>=2020.2.20',
    'yara-python==4.3.1'
]

core_dependencies = [
    'mwcp==3.14.0',
    'dragodis==1.0.0',
    'rugosa==1.0.0',
    'pyhidra==1.2.0'
]

dependencies = core_dependencies
dependencies.extend(common)

setup(
    name='os-acce-parsers',
    version=read('VERSION'),
    author="Cipher Tech Solutions",
    author_email="acce.support@ciphertechsolutions.com",
    description='Open-Source ACCE parsers developed by Cipher Tech.',
    long_description=read('README.rst'),
    packages=find_packages(),
    include_package_data=True,
    url="https://www.ciphertechsolutions.com/products/acce/",
    license="BSD-3",
    python_requires='>=3.9',
    entry_points={
        'mwcp.parsers': [
            'osacce = os_acce_parsers.mwcp.parsers',
        ]
    },
    install_requires=dependencies,
    package_data={
        'os_acce_parsers': ['resources/*', 'resources/rules/*'],
    }
)
