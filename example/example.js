#!/usr/bin/env node

var sys       = require('sys'),
    ldapauth  = require('../ldapauth'); // Path to ldapauth.node

var scheme    = 'ldap',
    ldap_host = 'some.ldap.server',
    ldap_port = 389,
    username  = 'SOMEDOMAIN\\SOMEUSER',
    password  = 'SOMEPASS'
    base      = "OU=FOO,DC=US,DC=BAR,DC=com",
    filter    = "(&(objectclass=user)(sAMAccountName=someone))";

ldapauth.search(ldap_host, ldap_port, username, password, base, filter,
  function(err, result) {
    if (err) {
      sys.puts(err);
    } else {
      sys.puts('Search: ' + JSON.stringify(result));
    }
  });

ldapauth.authenticate(scheme, ldap_host, ldap_port, username, password,
  function(err, result) {
    if (err) {
      sys.puts(err);
    } else {
      sys.puts('Auth: ' + result);
    }
  });
