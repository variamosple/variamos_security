from pathlib import Path

from setuptools import setup, find_packages

setup(
    name='variamos_security', 
    version='0.0.3',
    packages=find_packages(include=["variamos_security", "variamos_security.*"]),
    install_requires=[
        'python-jose',
        # The models use the Pydantic 2 API (model_dump)
        'pydantic>=2',
    ],
    extras_require={
        "fastapi": ["fastapi>=0.115.0"], 
    },
    author='VariaMos',  
    author_email='variamosple@gmail.com',
    description='VariaMos security commons for Python',
    long_description=Path(__file__).with_name('README.md').read_text(encoding='utf-8'),
    long_description_content_type='text/markdown',
    url='https://github.com/variamosple/variamos_security',
    project_urls={
        'Source': 'https://github.com/variamosple/variamos_security/tree/main/python',
    },
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.9',
)