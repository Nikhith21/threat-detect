from setuptools import setup

setup(
    name="threat-detect",
    version="1.0",
    py_modules=["threat_detect"],
    install_requires=["colorama"],
    entry_points={
        "console_scripts": [
            "threat-detect=threat_detect:main"
        ]
    },
)