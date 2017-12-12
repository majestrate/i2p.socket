from setuptools import setup
import os
import sys

long_description = ''
long_description_fname = 'README.rst'

if os.path.exists(long_description_fname):
    with open(long_description_fname, 'r') as infile:
        long_description = infile.read()


crypto_requires = []
crypto_requires_fname = 'crypto_requirements.txt'
install_requires = []

if os.path.exists(crypto_requires_fname):
    with open(crypto_requires_fname, 'r') as infile:
        crypto_requires = infile.read().split()

if sys.version_info[0] < 3:
    install_requires.append("future>=0.14.0")
    install_requires.append("enum34>=1.0")
version = '0.4.0'

setup(
    name='i2p.socket',
    description='I2P socket module',
    long_description=long_description,
    author='Jeff',
    author_email='ampernand@gmail.com',
    url='https://github.com/majestrate/i2p.socket',
    download_url='https://github.com/majestrate/i2p.socket/tarball/{}'.format(version),
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
    license='MIT',
    version=version,
    install_requires=install_requires,
    extra_require={'crypto': crypto_requires},
    packages=['i2p', 'i2p.crypto', 'i2p.socket', 'i2p.socket.sam'],
    keywords=['i2p', 'socket'],
)
