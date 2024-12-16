from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vulnscan",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="An asynchronous web application security scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/vulnscan",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "aiohttp>=3.8.0",
        "beautifulsoup4>=4.9.3",
        "colorama>=0.4.4",
        "psutil>=5.8.0",
        "python-dotenv>=0.19.0",
        "pydantic>=1.9.0",
    ],
) 