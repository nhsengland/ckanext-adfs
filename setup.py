from setuptools import setup, find_packages
import sys, os

version = '0.1'

setup(
    name='ckanext-adfs',
    version=version,
    description="AFDS Authentications",
    long_description='''
    ''',
    classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
    keywords='',
    author='NHS England UK',
    author_email='hello@data.england.nhs.uk',
    url='data.england.nhs.uk',
    license='GPL3',
    packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
    namespace_packages=['ckanext', 'ckanext.adfs'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        # -*- Extra requirements: -*-
        'lxml',
        'm2crypto'
    ],
    entry_points='''
        [ckan.plugins]
        # Add plugins here, e.g.
        adfs=ckanext.adfs.plugin:ADFSPlugin
    ''',
)
