from setuptools import setup, find_packages

# Function to read the requirements.txt file


def parse_requirements(filename):
    with open(filename, 'r') as file:
        lines = file.read().splitlines()
        # Filter out comments and empty lines
        requirements = [
            line for line in lines if line and not line.startswith('#')]
    return requirements


# Parse requirements.txt
requirements = parse_requirements('requirements.txt')

setup(
    name="meshtastic_visualizer",
    version="1.7.1",
    packages=find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    author="antlas0",
)
