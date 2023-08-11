from setuptools import setup, find_packages
from os import path

setup(
    name="ntlmrecon",
    version="0.4b0",
    description="A tool to enumerate information from NTLM authentication enabled web endpoints",
    license="MIT",
    long_description=open(path.join(path.abspath(path.dirname(__file__)), "README.md"), encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/sachinkamath/ntlmrecon",
    author="Sachin S Kamath (@sachinkamath)",
    author_email="mail@skamath.me",
    keywords="security recon redteam cybersecurity ntlm ntlmrecon",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, <4",
    install_requires=[
        "click",
        "colorama",
        "iptools",
        "requests",
        "setuptools",
        "termcolor",
        "urllib3"
    ],
    entry_points={
        "console_scripts": [
            "ntlmrecon=ntlmrecon:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/sachinkamath/ntlmrecon/issues",
        "Source": "https://github.com/sachinkamath/ntlmrecon/",
    },
)
