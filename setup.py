"""
 setup.py
 
 SAFE 
"""

from setuptools import setup, find_packages
setup(
    name = "safe",
    version = "0.2",
    packages = ['safe'],
    package_dir={'safe': 'src/safe'},

    # Project uses reStructuredText, so ensure that the docutils get
    # installed or upgraded on the target machine
    install_requires = ['argparse>=1.2.1', 
                        'boto>=2.19.0', 
                        'pyOpenSSL>=0.13.1', 
                        'pycrypto>=2.6.1',
                        'wsgiref>=0.1.2',
                        'xmpppy>=0.5.0rc1'],

    # metadata for upload to PyPI
    author = "Andrew Werner, Wathsala Vithanage, and Stephen Lin",
    author_email = "ajwerner@princeton.edu",
    description = "Secure Authentication For Everyone! - a simple, convenient key management solution",
    keywords = "keys encrypt simple easy",
    url = "http://github.com/ajwerner/safe",   # project home page, if any
)