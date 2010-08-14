#!/usr/bin/env node

var sys       = require('sys'),
    ldapauth  = require('../ldapauth'); // Path to ldapauth.node

var ldap_host = 'ldap.mycompany.com',
    ldap_port = 389,
    username  = 'someuser',
    password  = 'somepass';

ldapauth.authenticate(ldap_host, ldap_port, username, password,
  function(err, result) {
    if (err) {
      sys.puts(err);
    } else {
      sys.puts('Result: ' + result);
    }
  });
