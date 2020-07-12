from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='Playbot',
    version='3.2.1',
    packages=[''],
    package_dir={'': 'threat_playbook'},
    url='https://we45.github.io/threatplaybook/',
    license='MIT License',
    author='we45',
    author_email='info@we45.com',
    install_requires=[
        'robotframework==3.1.1',
        'requests==2.21.0'
    ],
    description='ThreatPlaybook Robot Framework Library',
    long_description = long_description,
    long_description_content_type='text/markdown',
    include_package_data=True
)