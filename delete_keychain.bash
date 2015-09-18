#!/bin/bash

    # If this environment variable is missing, we must not be running on Travis.
    if [ -z "$KEY_PASSWORD" ]
    then
        return 0
    fi

    security delete-keychain "$KEYCHAIN"
