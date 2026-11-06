from setuptools import setup, find_packages

setup(
    name="h4ck-modern",
    version="0.1.0",
    description="Modern async network & web reconnaissance tool for authorized targets only",
    python_requires=">=3.10",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={"h4ck": ["data/brute/*.txt"]},
    install_requires=[
        "httpx>=0.26.0",
        "typer[all]>=0.12.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "h4ck=h4ck.cli:app",
        ],
    },
)
