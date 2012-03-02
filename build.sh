#!/bin/sh

node-waf configure build && cp build/Release/ldapauth.node ./
