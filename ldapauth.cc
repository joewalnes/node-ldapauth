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
};

struct search_request : auth_request
{
  // Search Input params
  char *base;
  char *filter;

  // Results
  Handle<Object> results;
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
    ldap_unbind(ldap);

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
  auth_req->callback.Dispose();
  free(auth_req);

  return 0;
}

static int EIO_Search(eio_req *req)
{
  struct search_request *search_req = (struct search_request*)(req->data);

  // Connect to LDAP server
  //printf("Trying to open connection");
  LDAP *ldap = ldap_open(search_req->host, search_req->port);

  if (ldap == NULL) {
    search_req->connected = false;
    search_req->authenticated = false;
  } else {
    // Bind to server to authenticate
    int ldap_result = ldap_simple_bind_s(ldap, search_req->username, search_req->password);
    if (ldap_result == LDAP_SUCCESS)
    {
      char **attrs = NULL;

      LDAPMessage *resultMessage;
      struct timeval *timeout = (struct timeval*) calloc(1, sizeof(struct timeval));
      timeout->tv_sec = 10;
      int ldap_result = ldap_search_ext_s(ldap, search_req->base, LDAP_SCOPE_SUB, search_req->filter, attrs, 0, NULL, NULL, timeout, 0, &resultMessage);

      search_req->results = Object::New();

      if (ldap_result == LDAP_SUCCESS) {
        BerElement *berptr;
        char **vals;
        char *attr;

        for (attr = ldap_first_attribute(ldap, resultMessage, &berptr); attr; attr = ldap_next_attribute(ldap, resultMessage, berptr))
        {
          vals = ldap_get_values(ldap, resultMessage, attr);
          int numVals = ldap_count_values(vals);

          if (numVals == 1) {
            search_req->results->Set(String::New(attr), String::New(vals[0]));
          } else {
            Local<Array> jsValues = Array::New(numVals);
            for (int idx = 0; idx < numVals; ++idx)
            {
              jsValues->Set(Integer::New(idx), String::New(vals[idx]));
            }
            search_req->results->Set(String::New(attr), jsValues);
          }
          ldap_value_free(vals);
          ldap_memfree(attr);
        }
        ber_free(berptr, 0);
      }

      free(timeout);

      search_req->connected = true;
    } else {
      search_req->connected = false;
    }
    ldap_unbind(ldap);
  }

  return 0;
}

static int EIO_AfterSearch(eio_req *req)
{
  ev_unref(EV_DEFAULT_UC);
  HandleScope scope;

  struct search_request *search_req = (struct search_request *)(req->data);

  // Invoke JS callback function
  Handle<Value> callback_args[2];
  callback_args[0] = search_req->connected ? (Handle<Value>)Undefined() : Exception::Error(String::New("LDAP connection failed"));
  callback_args[1] = search_req->results;
  search_req->callback->Call(Context::GetCurrent()->Global(), 2, callback_args);

  // Cleanup search_request struct
  search_req->callback.Dispose();
  free(search_req);

  return 0;
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
  struct auth_request *auth_req = (struct auth_request*) calloc(1, sizeof(struct auth_request));
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

// Exposed user by login JavaScript function
static Handle<Value> Search(const Arguments& args)
{
  HandleScope scope;

  // Validate args.
  // TODO

  // Input params.
  String::Utf8Value host(args[0]);
  int port = args[1]->Int32Value();
  String::Utf8Value username(args[2]);
  String::Utf8Value password(args[3]);
  String::Utf8Value base(args[4]);
  String::Utf8Value filter(args[5]);
  Local<Function> callback = Local<Function>::Cast(args[6]);

  // Store all parameters in search_request struct, which shall be passed across threads.
  struct search_request *search_req = (struct search_request*) calloc(1, sizeof(struct search_request));
  search_req->host = strdup(*host);
  search_req->port = port;
  search_req->username = strdup(*username);
  search_req->password = strdup(*password);
  search_req->base = strdup(*base);
  search_req->filter = strdup(*filter);
  search_req->callback = Persistent<Function>::New(callback);

  // Use libeio to invoke EIO_Search in the background thread pool
  // and call EIO_AfterSearch in the foreground when done
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
