#!/usr/bin/env node

var sys       = require('sys'),
    ldapauth  = require('../ldapauth'); // Path to ldapauth.node

var ldap_host = 'chidc.us.drwholdings.com',
    ldap_port = 389,
    username  = 'US\\jfriedman',
    password  = 'dumb9croc'
    base      = "OU=Accounts,DC=US,DC=DRWHoldings,DC=com",
    filter    = "(&(objectclass=user)(sAMAccountName=greeves))";

ldapauth.search(ldap_host, ldap_port, username, password, base, filter,
  function(err, result) {
    if (err) {
      sys.puts(err);
    } else {
      sys.puts('Search: ' + JSON.stringify(result));
    }
  });

ldapauth.authenticate(ldap_host, ldap_port, username, password,
  function(err, result) {
    if (err) {
      sys.puts(err);
    } else {
      sys.puts('Auth: ' + result);
    }
  });
