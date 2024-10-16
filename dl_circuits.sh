#!/bin/bash

# Download the latest.zip file
curl -LO https://opid-circuits.s3.amazonaws.com/latest.zip

# Unzip the file into ./circuits
unzip -d ./circuits latest.zip

# remove the zip file
rm latest.zip
