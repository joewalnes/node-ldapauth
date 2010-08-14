#!/bin/sh

node-waf configure build && cp build/default/ldapauth.node ./
