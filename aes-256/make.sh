#!/bin/bash

# You must have the following installed:
# apt install openssl libssl-dev

g++ -Wall -Werror -std=c++11 *.cc -o cipher -lcrypto
