## Data Types
#### String
In Python, **string data** is data consisting of an ordered sequence of characters. Characters in a string may include letters, numbers, symbols, and spaces. These characters must be placed within quotation marks. Strings are immutable.
Common functions: str() and len() and methods: .upper(), .lower(), .index(), .split()
#### Integer
In Python, integer data is data consisting of a number that does not include a decimal point
#### Float
Float data is data consisting of a number with a decimal point. 
#### Boolean 
Boolean data is data that can only be one of two values: either True or False.
#### List
List data is a data structure that consists of a collection of data in sequential form. Lists elements can be of any data type, such as strings, integers, Booleans, or even other lists. The elements of a list are placed within square brackets, and each element is separated by a comma. List is mutable.
List methods include .insert(pos, element) , .remove(element), .append(element) and .index(element).
#### Tuple
Tuple data is a data structure that consists of a collection of data that cannot be changed. Like lists, tuples can contain elements of varying data types. 
A tuple is placed in parentheses rather than brackets.
#### Dictionary
Dictionary data is data that consists of one or more key-value pairs. Each key is mapped to a value. A colon (:) is placed between the key and value. Commas separate key-value pairs from other key-value pairs, and the dictionary is placed within curly brackets ({}). 
#### Set
Set data is data that consists of an unordered collection of unique values. This means no two values in a set can be the same. 
Elements in a set are always placed within curly brackets and are separated by a comma. These elements can be of any data type.

## Functions
A **function** is a section of code that can be reused in a program.
- A **parameter** is an object that is included in a function definition for use in that function.
- An **argument** is the data brought into a function when it is called.
- When defining functions in Python, you use return statements if you want the function to return output. The return keyword is used to return information from a function.
- A **global variable** is a variable that is available through the entire program. Global variables are assigned outside of a function definition.
- A **local variable** is a variable assigned within a function. These variables cannot be called or accessed outside of the body of a function.
## Working with files
- The keyword `with` handles errors and manages external resources when used with other functions. 
- We can use it with the open() function in order to open a file. It will then manage the resources by closing the file after exiting the with statement.
- The first parameter of the open() function is the absolute file path and the second parameter indicates what you want to do with the file.
- "r" indicates that you want to read the file, "w" if you want to write to a file or "a" if you want to append to a file.
- When you open a file using with open(), you must provide a variable that can store the file while you are within the with statement. You can do this through the keyword as followed by this variable name. The keyword as assigns a variable that references another object.
- We can use the .read() method to read the contents of the file. 
- The .write() method writes string data to a specified file. you can use the .write() method with both "w" and "a".
## Modules and libraries
A module is a Python file that contains additional functions, variables, and other kinds of runnable code. 
A Python library is a collection of modules.
- The **Python Standard Library** is an extensive collection of Python code that often comes packaged with Python. It includes a variety of modules, each with pre-built code centered around a particular type of task.
Modules in the Python Standard Library:
- The re module, which provides functions used for searching for patterns in log files
- The csv module, which provides functions used when working with .csv files
- The glob and os modules, which provide functions used when interacting with the command line
- The time and datetime modules, which provide functions used when working with timestamps

To import an entire Python Standard Library module, you use the import keyword. The import keyword searches for a module or library in a system and adds it to the local Python environment. To import a specific function from the Python Standard Library, you can use the from keyword.

In addition to the Python Standard Library, you can also download external libraries and incorporate them into your Python code.
eg: Beautiful Soup (bs4) for parsing HTML files and NumPy (numpy) for arrays and mathematical computations.
## Package management
Python package management involves installing, managing, and updating external libraries and modules required for Python projects.
**pip:** is The standard package installer for Python, included by default with Python 3.4 and later. It is primarily used to install packages from the Python Package Index (PyPI).
```shell
pip install [package] 
pip install -r requirements.txt
pip uninstall [package]
```

To prevent compatibility issues with varying dependency versions we can include package versions in the requirement file too.

But if the dependencies of these dependencies have any breaking changes that will affect our project.
So we can do Dependency pinning 
`pip freeze > requirements.lock`
This  is used in Python development to capture the exact versions of all installed packages in the current environment and save them to a file named `requirements.lock`.

## Virtual environments
A Python virtual environment is an isolated Python installation with its own Python interpreter and packages, preventing conflicts between projects. 
Virtual environments are essential for reproducible, portable, and secure development, allowing different projects to use different package versions without affecting each other or the system's main Python installation.  

The built-in venv module creates lightweight environments, while the standalone virtualenv tool offers similar functionality. 
```bash
python -m venv venv
source venv/bin/activate  # On linux
venv\Scripts\activate   # On windows
```

## pyenv
Sometimes a package may not work with the python version installed on our machine and may require a certain version of python to work. 
The pyenv command-line tool allows you to install and switch between multiple Python versions without interfering with your operating system's Python installation.
We can pin the version of python by using a `.python-version` file in our project dir with python version we need. 
Then we can install the version required using `pyenv install -s`. 
pyenv will automatically change your path and use the correct python. Or we can manually run by using `pyenv exec python` 

## uv
UV (written in Rust) is an ultra-fast, all-in-one Python package and project manager designed to replace and unify tools like `pip`, `venv`, `poetry`, and `pyenv`.

```bash
uv init             # Create a new project
uv add [package]    # Install a package / add dependeny
uv remove [package] # Remove a package
uv sync             # Update the venv 
uv lock             # Update the lock file
uv publish          # Send package to PyPI
uv tree             # Show dependency tree
```
To run a python file:
```
uv run script.py
```
This will install the correct python version, create virtual environment and install the required packages for the project

Note: uv will store the dependencies in the `pyproject.toml` file instead of `requirements.txt` file.
