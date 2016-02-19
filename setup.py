from setuptools import setup
import os
import sys

long_description = ''
long_description_fname = 'README.rst'

if os.path.exists(long_description_fname):
    with open(long_description_fname, 'r') as infile:
        long_description = infile.read()


install_requires = []
install_requires_fname = 'requirements.txt'

if os.path.exists(install_requires_fname):
    with open(install_requires_fname, 'r') as infile:
        install_requires = infile.read().split()


version = '0.0.1'

setup(
    name='i2p.socket',
    description='I2P socket module',
    long_description=long_description,
    author='Jeff',
    author_email='ampernand@gmail.com',
    url='https://github.com/majestrate/i2p.socket',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: Public Domain',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet',
    ],
    license='Public Domain',
    version=version,
    install_requires=install_requires,
    package_dir={'': 'src'},
    packages=['i2p', 'i2p.socket', 'i2p.socket.sam'],
)
