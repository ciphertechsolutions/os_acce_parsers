"""
Build script for acce_parsers Docker image
"""
import argparse
import atexit
import os
import re
import shlex
import shutil
import string
import subprocess as sp
import sys
import tempfile
from pathlib import Path


def _load_toml():
    """Load the third party TOML package from included ZIP"""
    try:
        import toml
    except ImportError:
        sys.path.insert(0, str(Path(__file__).parent.joinpath("tomlz.zip")))
        import toml

    return toml


class OptionManager:
    def __init__(self, base_path=Path.cwd()):
        self.tempdir = tempfile.mkdtemp(prefix=".build", dir=str(base_path))
        atexit.register(self._cleanup)

        self.options = {}

    def read_options_files(self, *option_paths):
        toml = _load_toml()

        option_paths = option_paths or []
        for path in option_paths:
            options = toml.loads(path.read_text())
            self._merge_options(options)

    def add_options_dict(self, new_options):
        self._merge_options(new_options)

    def add_external_path(self, src):
        if not isinstance(src, Path):
            src = Path(src)
        if src.is_file():
            new_path = Path(shutil.copy(str(src), self.tempdir))
        elif src.is_dir():
            shutil.copytree(str(src), self.tempdir)
            new_path = Path(self.tempdir, src.name)
        else:
            raise RuntimeError(f"Unable to find path {src}")
        return new_path

    def _handle_path(self, orig_path):
        try:
            path = Path(orig_path)
        except OSError:
            return orig_path

        cwd = Path.cwd()

        if cwd in path.absolute().parents:
            return path.absolute().relative_to(cwd).as_posix()
        else:
            new_path = self.add_external_path(path.absolute())
            return Path(new_path).absolute().relative_to(cwd).as_posix()

    def _merge_options(self, new_options):
        for key, value in new_options.items():
            if not isinstance(value, list):
                value = [value]

            for option in value:
                for opt_key, opt_value in option.items():
                    if "path" in opt_key:
                        opt_value = self._handle_path(opt_value)
                        option[opt_key] = opt_value

            self.options.setdefault(key, []).extend(value)

    def _cleanup(self):
        shutil.rmtree(self.tempdir, ignore_errors=True)


def read_build_conf(service):
    toml = _load_toml()
    conf = toml.loads(Path(__file__).parent.joinpath(service, "build.toml").read_text())
    return conf


def read_options(option_paths, config):
    options_manager = OptionManager()
    if option_paths:
        options_manager.read_options_files(*option_paths)
    options_manager.add_options_dict(config.get("options", {}))

    return options_manager.options


def download_dep(dep):
    python_exe = sys.executable
    pip_command = '-m pip download --exists-action i --no-deps -d {} "{}"'.format(
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "wheels")), dep
    )

    pip_command = " ".join((python_exe, pip_command))

    print(f"Calling {pip_command}")

    sp.run(pip_command, env=os.environ, shell=True)


def _patch_line(line, name, options):
    """
    Patch an individual line.

    :param str line: Unprocessed text of the template line
    :param str name: Name extracted from template line
    :param dict options: Build configuration dict
    :return: Patched line
    """
    options = options or {}
    line_options = options.get(name, [])

    if not line_options:
        return []

    if not isinstance(line_options, list):
        line_options = [line_options]

    if not all(isinstance(ex, dict) for ex in line_options):
        return []

    template = string.Template(line)
    new_lines = []

    for extra_vars in line_options:
        new_line = template.safe_substitute(**extra_vars)
        new_lines.append(new_line.lstrip())

    return new_lines


def patch_dockerfile(path, config):
    """
    Patch a Dockerfile using the options in config

    Lines marked with the special template pattern of
    "# %%<name>%% <dockerfile command>" are filled in
    with any options in the build.toml or extra options
    files.

    These lines may have multiple options, and multiple instances
    of these options. If a line name appears more than once or
    contains a list of line options, then that line will
    be repeated.

    :param Path path: Path to the original Dockerfile
    :param dict config: Parsed configuration dict
    """
    if not isinstance(path, Path):
        path = Path(path)

    patches = {}
    docker_lines = path.read_text().splitlines()
    line_re = re.compile(r"^# %%(\w+)%%")

    for index, line in enumerate(docker_lines):
        match = line_re.match(line)
        if match:
            new_lines = _patch_line(line[match.end():], match.group(1), config)
            patches[index] = new_lines

    for index in reversed(sorted(patches)):
        new_lines = patches[index]

        docker_lines[index : index + 1] = new_lines

    return "\n".join(docker_lines)


def list_services():
    base_path = Path(__file__).parent
    return [
        path.name
        for path in base_path.iterdir()
        if path.is_dir() and not path.name.startswith(("_", "."))
    ]


def parse_build_arg(build_arg):
    parsed_args = build_arg.split("=", 1)
    if len(parsed_args) != 2:
        raise argparse.ArgumentTypeError(
            "Additional --build-arg arguments must be in the form of 'key=value'"
        )
    return parsed_args


def main():
    parser = argparse.ArgumentParser(
        description="Build script for ct_parsers Docker image"
    )
    parser.add_argument(
        "service", type=str, help="Name of the service to build", nargs="?"
    )
    parser.add_argument(
        "--download-deps",
        "-d",
        action="store_true",
        help="Download external dependencies",
    )
    parser.add_argument(
        "--registry", "-r", type=str, help="Registry URL to add to image name"
    )
    parser.add_argument("--registry-host", type=str, help="Registry server to push to")
    parser.add_argument("--registry-user", type=str, help="Username for registry")
    parser.add_argument(
        "--registry-password", type=str, help="Password for given user and registry"
    )
    parser.add_argument("--tag", "-t", type=str, help="Tag to add to image name")
    parser.add_argument(
        "--commit-tag", type=str, help="version tag for production image"
    )
    # noinspection PyTypeChecker
    parser.add_argument(
        "--options", "-o", action="append", type=Path, help="Path to options file"
    )
    parser.add_argument(
        "--list", "-l", action="store_true", help="List available services"
    )
    parser.add_argument(
        "--build-arg",
        action="append",
        type=parse_build_arg,
        help="Additional build arguments to pass to Docker",
    )
    parser.add_argument(
        "--load", action="store_true", help="Load image into docker instead of just into the build context (on certain docker configurations).  Adds --load to the docker build command."
    )
    parser.add_argument(
        "--push", "-p", action="store_true", help="Push image during build stage.  Adds --push to the docker build command."
    )

    args = parser.parse_args()

    if args.list:
        print("Available Services:")
        print("\n".join(list_services()))
        return

    if not args.service:
        raise parser.error("A service must be specified")

    conf = read_build_conf(args.service)

    options = read_options(args.options, conf)

    # Download dependencies
    if args.download_deps:
        for dep in conf.get("deps", []):
            download_dep(dep)

    root_path = Path(__file__).parent.parent.parent
    os.chdir(root_path)

    build_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), args.service))

    new_dockerfile = patch_dockerfile(Path(build_dir, "Dockerfile"), options)

    container_name = conf["container_name"]
    if args.registry:
        container_name = args.registry + "/" + container_name
        containername_notag = container_name

    if args.tag:
        container_name = container_name + ":" + args.tag

    # Log into the registry, if one is specified
    login_successful = False
    if args.registry_host:
        if args.registry_user and args.registry_password:
            docker_cmd_login = (
                "docker login --username {user} --password {passwrd} {host}".format(
                    user=args.registry_user,
                    passwrd=args.registry_password,
                    host=args.registry_host,
                )
            )
            print(f"Running: docker login registry-host={args.registry_host}")
            if sys.platform != "win32":
                docker_cmd_login = shlex.split(docker_cmd_login)
            sp.Popen(docker_cmd_login, stdin=sp.PIPE, cwd=str(Path.cwd()))
            login_successful = True
        else:
            raise parser.error("Invalid registry username or password!")

    # Build the images
    build_args = []
    for arg, value in conf.get("build_args", {}).items():
        if isinstance(value, list):
            value = " ".join(["{}".format(elem) for elem in value])
        build_args.append('--build-arg {}="{}"'.format(arg, value))
    for arg, value in args.build_arg or []:
        build_args.append('--build-arg {}="{}"'.format(arg, value))
    if args.push:
        build_args.append("--push")
    if args.load:
        build_args.append("--load")

    docker_cmd = "docker build {build_args} -t {tag} -f- .".format(
        tag=container_name, build_args=" ".join(build_args)
    )
    print(f"Running: {docker_cmd}")
    if sys.platform != "win32":
        docker_cmd = shlex.split(docker_cmd)
    with sp.Popen(docker_cmd, stdin=sp.PIPE, cwd=str(Path.cwd())) as proc:
        proc.stdin.write(new_dockerfile.encode("latin1"))

    # Push images to registry where applicable
    if login_successful:
        docker_cmd_push = "docker push {image_name}".format(image_name=container_name)
        print(f"Running: {docker_cmd}")
        if sys.platform != "win32":
            docker_cmd_push = shlex.split(docker_cmd_push)
        sp.Popen(docker_cmd_push, stdin=sp.PIPE, cwd=str(Path.cwd()))

    # If a CI commit for production, also tag the image as the actual version and build and push that too
    if args.commit_tag:
        docker_cmd_tag = "docker tag {image_name} {image_name_notag}:{ci_tag}".format(
            image_name=container_name,
            image_name_notag=containername_notag,
            ci_tag=args.commit_tag,
        )
        docker_cmd_push = "docker push {image_name_notag}:{ci_tag}".format(
            image_name_notag=containername_notag, ci_tag=args.commit_tag
        )

        # Tag image
        print(f"Tagging image as version {args.commit_tag}")
        if sys.platform != "win32":
            docker_cmd_tag = shlex.split(docker_cmd_tag)
        sp.Popen(docker_cmd_tag, stdin=sp.PIPE, cwd=str(Path.cwd()))

        # Push image
        print(f"Running: {args.commit_tag}")
        if sys.platform != "win32":
            docker_cmd_push = shlex.split(docker_cmd_push)
        sp.Popen(docker_cmd_push, stdin=sp.PIPE, cwd=str(Path.cwd()))


if __name__ == "__main__":
    main()
