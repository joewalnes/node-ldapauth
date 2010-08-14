LDAP Authentication for Node.JS
===============================

Provides a simple function for validating username/password credentials
on an LDAP server.

This can be used in web-applications that authenticate users from a central directory.

It binds to the native OpenLDAP library (libldap) and calls ldap_simple_bind().

For more info, see:

    man 3 ldap_bind

Building
--------

    node-waf configure build

Usage
-----

Ensure ldapauth.node is in your node path.

    var ldapauth = require('ldapauth');
    ldapauth.authenticate('some.host', 389 /*port*/, 'someuser', 'somepassword', 
      function(err, result) {
        if (err) {
          print('Error');
        } else {
          print('Credentials valid = ' + result); // true or false
        }
      });

Resources
---------

http://nodejs.org/
http://www.openldap.org/

*2010, Joe Walnes, joe@walnes.com, http://joewalnes.com/*
