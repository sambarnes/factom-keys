from setuptools import (
    setup,
    find_packages,
)


deps = {
    'factom-keys': [
        'ed25519',
        'python-bitcoinlib',
    ]
}

setup(
    name='factom-keys',
    version='0.0.2',
    description='A small library for using Factom\'s factoid and entry-credit keys',
    author="Sam Barnes",
    author_email="mistersamuelbarnes@gmail.com",
    url='https://github.com/sambarnes/factom-keys',
    keywords=['factom', 'keys'],
    license='MIT',
    py_modules=['factom_keys'],
    install_requires=deps['factom-keys'],
    zip_safe=False,
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "Topic :: Utilities",
    ],
)
