from setuptools import setup, find_packages
setup(
    name='wls-demo',
    version='0.0.1',
    author="Edwin Bahrami Balani",
    author_email="eb677@srcf.net",
    license="MIT",
    description="Web login service demo using the ucam-wls library",
    url="https://github.com/edwinbalani/wls-demo",
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        'ucam-wls',
        'Flask',
    ],
    python_requires='>=3',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Development Status :: 2 - Pre-Alpha',
        'License :: OSI Approved :: MIT License',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ],
    keywords="cambridge university raven login authentication waa2wls demo ucam webauth ucam-webauth wls",
)
