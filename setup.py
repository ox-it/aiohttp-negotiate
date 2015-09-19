from setuptools import setup

setup(
    name='aiohttp-negotiate',
    version='0.9.2',
    description='Mixin for Negotiate authentication for aiohttp',
    long_description=open('README.rst').read(),
    author='IT Services, University of Oxford',
    author_email='github@it.ox.ac.uk',
    url='https://github.com/ox-it/aiohttp-negotiate',
    license='BSD',
    py_modules=['aiohttp_negotiate'],
    tests_require=['nose'],
    test_suite='nose.collector',
    install_requires=['aiohttp', 'gssapi', 'www-authenticate'],
)
