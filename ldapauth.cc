// Provides Node.JS binding for ldap_simple_bind().
// See README
// 2010, Joe Walnes, joe@walnes.com, http://joewalnes.com/


/*
Here's the basic flow of events. LibEIO is used to ensure that
the LDAP calls occur on a background thread and do not block
the main Node event loop.

 +----------------------+                +------------------------+
 | Main Node Event Loop |                | Background Thread Pool |
 +----------------------+                +------------------------+

      User application
             |
             V
    JavaScript: authenticate()
             |
             V
    ldapauth.cc: Authenticate()
             |
             +-------------------------> libauth.cc: EIO_Authenticate()
             |                                      |
             V                                      V
      (user application carries               ldap_simple_bind()
       on doing its stuff)                          |
             |                              (wait for response
       (no blocking)                           from server)
             |                                      |
     (sometime later)                         (got response)
             |                                      |
    ldapauth.cc: EIO_AfterAuthenticate() <----------+
             |
             V
Invoke user supplied JS callback

*/

#include <v8.h>
#include <node.h>
#include <node_events.h>
#include <ldap.h>
#include <unistd.h>
#include <stdlib.h>

#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <iostream>

using namespace v8;

#define THROW(message) ThrowException(Exception::TypeError(String::New(message)))

// Data passed between threads
struct auth_request 
{
  // Input params
  char *host;
  int port;
  char *username;
  char *password;
  // Callback function
  Persistent<Function> callback;
  // Result
  bool connected;
  bool authenticated;

  ~auth_request()
  {
    free(host);
    free(username);
    free(password);
    callback.Dispose();
  }
};

struct search_request : auth_request
{
  // Search Input params
  char *base;
  char *filter;

  // Results
  std::map<char*, std::vector<char*> > result;

  ~search_request()
  {
    free(base);
    free(filter);
  }
};

// Runs on background thread, performing the actual LDAP request.
static int EIO_Authenticate(eio_req *req) 
{
  struct auth_request *auth_req = (struct auth_request*)(req->data);

  // Node: OpenLDAP does actually provide _some_ async API calls,
  // But ldap_open does NOT have an async equivalent, so we have to
  // do this in a background thread. Seeing as we're in a background
  // thread anyway, it's just simpler to call the rest of the calls
  // synchronously.
  
  // Connect to LDAP server
  LDAP *ldap = ldap_open(auth_req->host, auth_req->port);
  if (ldap == NULL) {
    auth_req->connected = false;
    auth_req->authenticated = false;
  } else {
    // Bind with credentials, passing result into auth_request struct
    int ldap_result = ldap_simple_bind_s(ldap, auth_req->username, auth_req->password);
    // Disconnect
    ldap_unbind_s(ldap);

    auth_req->connected = true;
    auth_req->authenticated = (ldap_result == LDAP_SUCCESS);
  }
  
  return 0;
}

// Called on main event loop when background thread has completed
static int EIO_AfterAuthenticate(eio_req *req) 
{
  ev_unref(EV_DEFAULT_UC);
  HandleScope scope;
  struct auth_request *auth_req = (struct auth_request *)(req->data);
  
  // Invoke callback JS function
  Handle<Value> callback_args[2];
  callback_args[0] = auth_req->connected ? (Handle<Value>)Undefined() : Exception::Error(String::New("LDAP connection failed"));
  callback_args[1] = Boolean::New(auth_req->authenticated);
  auth_req->callback->Call(Context::GetCurrent()->Global(), 2, callback_args);

  // Cleanup auth_request struct
  delete auth_req;

  return 0;
}

static std::map<char*, std::vector<char*> > ResultObject(LDAP* ldap, LDAPMessage *resultMessage)
{
  std::map<char*, std::vector<char*> > results;

  BerElement *berptr;
  char *attr;

  for (attr = ldap_first_attribute(ldap, resultMessage, &berptr); attr; attr = ldap_next_attribute(ldap, resultMessage, berptr))
  {
    char **vals = ldap_get_values(ldap, resultMessage, attr);
    int numVals = ldap_count_values(vals);

    std::vector<char*> values;
    for (int idx = 0; idx < numVals; idx++)
    {
      values.push_back(strdup(vals[idx]));
    }

    results.insert(std::pair<char*, std::vector<char*> >(strdup(attr), values));
    ldap_value_free(vals);
    ldap_memfree(attr);
  }

  ber_free(berptr, 0);

  return results;
}

static Handle<Value> JsResultObject(std::map<char*, std::vector<char*> > c_results)
{
  HandleScope scope;

  Local<Object> results = Object::New();

  BerElement *berptr;

  for (std::map<char*, std::vector<char*> >::const_iterator iter = c_results.begin(); iter != c_results.end(); ++iter )
  {
    char* attr = iter->first;
    std::vector<char*> values = iter->second;

    int numVals = values.size();

    if (numVals == 1) {
      results->Set(String::New(attr), String::New(values[0]));
    } else {
      Local<Array> jsValues = Array::New(numVals);
      for (int idx = 0; idx < numVals; idx++)
      {
        jsValues->Set(Integer::New(idx), String::New(values.at(idx)));
      }
      results->Set(String::New(attr), jsValues);
    }

    while(!values.empty()) {
      free(values.back());
      values.pop_back();
    }
    free(attr);
  }

  ber_free(berptr, 0);

  return scope.Close(results);
}

// Exposed authenticate() JavaScript function
static Handle<Value> Authenticate(const Arguments& args)
{
  HandleScope scope;
  
  // Validate args.
  if (args.Length() < 5)      return THROW("Required arguments: ldap_host, ldap_port, username, password, callback");
  if (!args[0]->IsString())   return THROW("ldap_host should be a string");
  if (!args[1]->IsInt32())    return THROW("ldap_port should be a string");
  if (!args[2]->IsString())   return THROW("username should be a string");
  if (!args[3]->IsString())   return THROW("password should be a string");
  if (!args[4]->IsFunction()) return THROW("callback should be a function");

  // Input params.
  String::Utf8Value host(args[0]);
  int port = args[1]->Int32Value();
  String::Utf8Value username(args[2]);
  String::Utf8Value password(args[3]);
  Local<Function> callback = Local<Function>::Cast(args[4]);
  
  // Store all parameters in auth_request struct, which shall be passed across threads.
  //struct auth_request *auth_req = (struct auth_request*) calloc(1, sizeof(struct auth_request));
  struct auth_request *auth_req = new auth_request;
  auth_req->host = strdup(*host);
  auth_req->port = port;
  auth_req->username = strdup(*username);
  auth_req->password = strdup(*password);
  auth_req->callback = Persistent<Function>::New(callback);
  
  // Use libeio to invoke EIO_Authenticate() in background thread pool
  // and call EIO_AfterAuthententicate in the foreground when done
  eio_custom(EIO_Authenticate, EIO_PRI_DEFAULT, EIO_AfterAuthenticate, auth_req);
  ev_ref(EV_DEFAULT_UC);

  return Undefined();
}

static search_request* BuildSearchRequest(const Arguments& args) 
{ 
  // Input params.
  String::Utf8Value host(args[0]);
  int port = args[1]->Int32Value();
  String::Utf8Value username(args[2]);
  String::Utf8Value password(args[3]);
  String::Utf8Value base(args[4]);
  String::Utf8Value filter(args[5]);
  Local<Function> callback = Local<Function>::Cast(args[6]);

  // Store all parameters in search_request struct, which shall be passed across threads.
  //struct search_request *search_req = (struct search_request*) calloc(1, sizeof(struct search_request));
  struct search_request *search_req = new search_request;
  search_req->host = strdup(*host);
  search_req->port = port;
  search_req->username = strdup(*username);
  search_req->password = strdup(*password);
  search_req->base = strdup(*base);
  search_req->filter = strdup(*filter);
  search_req->callback = Persistent<Function>::New(callback);

  return search_req;
}

static void SearchAncestors(LDAP *ldap, char* group, char* base, std::vector<char*> *groups)
{
    std::string group_dn (group);
    std::string group_filter ("(distinguishedName=" + group_dn + ")");

    LDAPMessage *groupSearchResultMessage;
    int ldap_result = ldap_search_ext_s(ldap, base, LDAP_SCOPE_SUB, group_filter.c_str(), NULL, 0, NULL, NULL, NULL, 0, &groupSearchResultMessage);
    if(ldap_result == LDAP_SUCCESS)
    {
      char **names = ldap_get_values(ldap, groupSearchResultMessage, "name");
      char* group_short_name;
      if (ldap_count_values(names)) {
        group_short_name = names[0];
      } else {
        group_short_name = group;
      }

      groups->push_back(strdup(group_short_name));

      char** ancestors = ldap_get_values(ldap, groupSearchResultMessage, "memberOf");
      int numAncestors = ldap_count_values(ancestors);
      if (numAncestors == 0) {
      }
      for( int j = 0; j < numAncestors; j++) 
      {
        SearchAncestors(ldap, ancestors[j], base, groups);
      }
      ldap_value_free(ancestors);
      ldap_value_free(names);
    }
    else 
    {
      groups->push_back(strdup(group));
    }
    ldap_msgfree(groupSearchResultMessage);
}

static int EIO_Search(eio_req *req)
{
  struct search_request *search_req = (struct search_request*)(req->data);
  LDAP *ldap = ldap_open(search_req->host, search_req->port);

  if (ldap == NULL) {
    search_req->connected = false;
  } else {
    ldap_simple_bind_s(ldap, search_req->username, search_req->password);

    LDAPMessage *resultMessage;
    char **attrs = NULL;
    ldap_search_ext_s(ldap, search_req->base, LDAP_SCOPE_SUB, search_req->filter, attrs, 0, NULL, NULL, NULL, 0, &resultMessage);

    std::vector<char*> groups;

    char** members = ldap_get_values(ldap, resultMessage, "memberOf");
    int numMembers = ldap_count_values(members);

    for (int i = 0; i < numMembers; i++)
    {
      SearchAncestors(ldap, members[i], search_req->base, &groups);
    }

    ldap_value_free(members);

    std::map<char*, std::vector<char*> > results = ResultObject(ldap, resultMessage);
    results.insert(std::pair<char*, std::vector<char*> >(strdup("allGroups"), groups));
    search_req->result = results;
    search_req->connected = true;

    ldap_msgfree(resultMessage);
    ldap_unbind_s(ldap);
  }

  return 0;
}

static int EIO_AfterSearch(eio_req *req) 
{

  ev_unref(EV_DEFAULT_UC);
  HandleScope scope;
  struct search_request *search_req = (struct search_request *)(req->data);

  Handle<Value> jsResults = search_req->connected ? JsResultObject(search_req->result) : (Handle<Value>)Undefined();

  Handle<Value> callback_args[2];
  callback_args[0] = search_req->connected ? (Handle<Value>)Undefined() : Exception::Error(String::New("LDAP connection failed"));
  callback_args[1] = jsResults;
  search_req->callback->Call(Context::GetCurrent()->Global(), 2, callback_args);

  //cleanup search_request struct
  delete search_req;
  return 0;
}

static Handle<Value> Search(const Arguments &args)
{
  HandleScope scope;
  search_request *search_req = BuildSearchRequest(args);

  eio_custom(EIO_Search, EIO_PRI_DEFAULT, EIO_AfterSearch, search_req);
  ev_ref(EV_DEFAULT_UC);

  return Undefined();
}

// Entry point for native Node module
extern "C" void
init (Handle<Object> target) 
{
  HandleScope scope;
  target->Set(String::New("authenticate"), FunctionTemplate::New(Authenticate)->GetFunction());
  target->Set(String::New("search"), FunctionTemplate::New(Search)->GetFunction());
}
