@echo off

python3 -m virtualenv --copies .env

echo Enter cmd to install dependencies: "pip install -r .\requirements.txt"
start .\.env\Scripts\activate.bat
