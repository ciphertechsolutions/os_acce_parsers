import os
from setuptools import setup, find_packages
from setuptools.command.develop import develop
from setuptools.command.install import install


class AcceDevelop(develop):
    """Post-installation for development mode."""
    def run(self):
        develop.run(self)
        setup_mwcp_config()


class AcceInstall(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        setup_mwcp_config()


def setup_mwcp_config():
    import appdirs
    import pathlib
    cfg_dir = pathlib.Path(appdirs.user_config_dir("mwcp"))
    cfg_dir.mkdir(parents=True, exist_ok=True)

    config_path = cfg_dir / "config.yml"
    if not config_path:
        # Will only be printed if there is an install error or verbose flag
        print("MWCP config path could not be detected, \
            you will need to manually put the ACCE config at the correct location or set the MWCP_CONFIG environment variable")
        return
    from importlib import resources
    import pathlib
    if config_path.exists():
        # Will only be printed if there is an install error or verbose flag
        print("MWCP config already exists, ACCE config will be placed alongside it, but not used")
        acce_config_path = config_path.parent / "os_acce_config.yml"
    else:
        acce_config_path = config_path
    if not acce_config_path.exists():
        with open(acce_config_path, "w") as file:
            file.write(
                f'LOG_CONFIG_PATH: "{pathlib.PurePosixPath(resources.files("acce_parsers.services.parsers").joinpath("mwcp_log_config.yml").absolute())}"\n')
            file.write(f'YARA_REPO: "{pathlib.PurePosixPath(resources.files("acce_parsers.resources").joinpath("rules").absolute())}"\n')


def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname), 'r') as fo:
        return fo.read()


# Dependencies in 3 or more modules
common = [
    'construct==2.9.45',  # pin because of DC3-MWCP pinning
    'pyparsing==2.3.0',
    'regex>=2020.2.20',
    'yara-python==4.2.3'
]

core_dependencies = [
    'mwcp==3.13.0',
    'dragodis==0.7.1',
    'rugosa==0.8.0'
]


setup(
    name='os-acce-parsers',
    version=read('VERSION'),
    author="Cipher Tech Solutions",
    author_email="acce.support@ciphertechsolutions.com",
    description='Open-Source ACCE parsers developed by Cipher Tech.',
    long_description=read('README.rst'),
    cmdclass={
        "install": AcceInstall,
        "develop": AcceDevelop,
    },
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
    install_requires=core_dependencies,
    package_data={
        'os_acce_parsers': ['resources/*', 'resources/rules/*'],
    }
)
