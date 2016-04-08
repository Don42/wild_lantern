from distutils.core import setup

setup(
    name='wild_lantern',
    version='0.1.0',
    description='Module to provide dhcp features',
    long_description=open('README.rst').read(),
    author='Marco \'don\' Kaulea',
    author_email='donmarco42@gmail.com',
    url='https://github.com/Don42/wild_lantern',
    packages=['dhcp', 'dhcp.client', 'dhcp.server'],
    classifiers=[
        'Development Status :: 1 - Pre-Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
)
