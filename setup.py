# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

name = 'more.content_security'
description = (
    'Content Security Policy for Morepath'
)
version = '0.1.0'


def get_long_description():
    readme = open('README.rst').read()
    history = open('HISTORY.rst').read()

    # cut the part before the description to avoid repetition on pypi
    readme = readme[readme.index(description) + len(description):]

    return '\n'.join((readme, history))


setup(
    name=name,
    version=version,
    description=description,
    long_description=get_long_description(),
    url='http://github.com/seantis/more.content_security',
    author='Denis Krienbühl',
    author_email='denis@href.ch',
    license='BSD',
    packages=find_packages(exclude=['ez_setup']),
    namespace_packages=name.split('.')[:-1],
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    install_requires=[
        'morepath'
    ],
    extras_require=dict(
        test=[
            'coverage',
            'pytest',
            'webtest',
        ],
    ),
    classifiers=[
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'License :: OSI Approved :: BSD License',
    ]
)
