#!/bin/bash

string="azure.com"
#name=${string%%.*}
name=${string##*azure}

echo [$name]