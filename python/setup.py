from setuptools import setup, find_packages

setup(
    name='variamos_security', 
    version='0.0.2',
    packages=find_packages(include=["variamos_security", "variamos_security.*"]),
    install_requires=[
        'python-jose'
    ],
    extras_require={
        "fastapi": ["fastapi>=0.115.0"], 
    },
    author='VariaMos',  
    author_email='variamosple@gmail.com',
    description='VariaMos security commons for Python',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.9',
)