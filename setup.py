from setuptools import setup

setup(
    name='ctape',
    version='1.0',
    scripts=['tape.py'],
    entry_points={
        'console_scripts': ['ctape=tape:main']
    }
)
