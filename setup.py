from setuptools import setup, find_packages

setup(
    name="cipher-security",
    version="0.1.0",
    packages=find_packages(),
    py_modules=["cipher_cli"],
    install_requires=[
        "cryptography",
        "PyJWT",
    ],
    entry_points={
        "console_scripts": [
            "cipher-cli=cipher_cli:main",
        ],
    },
)
