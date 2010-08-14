#!/usr/bin/env node

// Include build path
require.paths.unshift('build/default');

var sys       = require('sys'),
    ldapauth  = require('ldapauth');

var ldap_host = 'ldap.mycompany.com',
    ldap_port = 389,
    username  = 'someuser',
    password  = 'somepass';

sys.puts('Before authenticate()');

ldapauth.authenticate(ldap_host, ldap_port, username, password, 
  function(err, result) {
    sys.puts('Callback from authenticate(): ' + err + ',' + result);
  });

sys.puts('After authenticate()');

