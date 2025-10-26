#!/bin/bash

# Get commit message
read  -p "Enter commit message: " message

# Add changes to commit
git add -A

# Test is user entered anything
if [ -z "$message" ]
then
	# Create automated commit
	git commit -m "Automated Commit"
else
	# Create commit with user message
	git commit -m "$message"
fi

# Make sure you are up to date
git pull

# Push commit to remote
git push