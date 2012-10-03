#include <node.h>
#include <node_buffer.h>
#include <node_version.h>
#include <assert.h>
#include <pcap/pcap.h>
#include <v8.h>
#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <locale.h>
#include <gpgme.h>

#define BAIL(x,y) if(err = x){                                                 \
    return Exception::Error(String::Concat(String::New(y),                     \
                                           String::New(gpgme_strerror(err)))); \
  }

using namespace v8;
using namespace node;

// This needs to be moved into a class.
// So more than one operation can run at a time.
gpgme_ctx_t ctx;

void str_to_data(gpgme_data_t *data, const char* string){
  gpgme_data_new_from_mem(data, string, strlen(string), 1); }

Handle<Value>Verify(const Arguments& args) {
  HandleScope scope;

  gpgme_error_t err;
  gpgme_ctx_t ctx;
  gpgme_data_t SIG, DATA;
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  /* setup */
  setlocale (LC_ALL, "");
  gpgme_check_version (NULL);
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  #ifdef LC_MESSAGES
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
  #endif

  BAIL(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP),
       "engine initialization error:");

  /* create context */
  BAIL(gpgme_new(&ctx), "context creation error:")

  /* parse arguments */
  if (args.Length() != 2)
    return ThrowException(Exception::TypeError(
      String::New("verify takes two arguments")));

  if (!args[0]->IsString())
    return ThrowException(Exception::TypeError(
      String::New("First argument is a string (signature)")));
  String::Utf8Value signature(args[0]->ToString());
  str_to_data(&SIG, *signature);

  if (!args[1]->IsString())
    return ThrowException(Exception::TypeError(
      String::New("Second argument is a string (data)")));
  String::Utf8Value data(args[1]->ToString());
  str_to_data(&DATA, *data);

  BAIL(gpgme_op_verify(ctx, SIG, DATA, NULL), "verification error:");

  result = gpgme_op_verify_result(ctx);
  sig = result->signatures;

  if(sig->status == GPG_ERR_NO_ERROR) return True();
  else                                return False();
}

extern "C" void init (Handle<Object> target) {
    HandleScope scope;
    target->Set(String::New("verify"),
                FunctionTemplate::New(Verify)->GetFunction()); }
