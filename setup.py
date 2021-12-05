import subprocess as sp
from setuptools import setup
from os.path import join, dirname

requirements = open(join(dirname(__file__), "requirements.txt")).read().split("\n")
version = sp.check_output("git describe --tags --abbrev=0".split()).decode().rsplit(".", 1)
version[-1] = str(int(version[-1]) + 1) + "-dev"
version = ".".join(version)
setup(
    version=version,
    name="pyrrr",
    description="""pyrrr contains some miscelaneous support utilities for
    working on and operating with rrr consensus""",
    author="Robin Bryce",
    author_email="robinbryce@gmail.com",
    entry_points={
        "console_scripts": [
            "checkstate = pyrrr.checkstate:main",
        ]
    },
    url="https://github.com/RobustRoundRobin/go-rrr/pyrrr",
    packages=["pyrrr"],
    install_requires=requirements
)
print(version)
