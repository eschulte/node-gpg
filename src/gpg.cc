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

using namespace v8;
using namespace node;

// This needs to be moved into a class.
// So more than one operation can run at a time.
gpgme_ctx_t ctx;

void bail(gpgme_error_t err, const char * msg){
  char buff[1024];
  if(err){
    sprintf(buff, "GPG %s error: %s", msg, gpgme_strerror(err));
    throw(buff); }}

void init(){
  setlocale (LC_ALL, "");
  gpgme_check_version (NULL);
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  #ifdef LC_MESSAGES
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
  #endif
  bail(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "engine init"); }

void str_to_data(gpgme_data_t *data, const char* string){
  bail(gpgme_data_new_from_mem(data, string, strlen(string), 1),
       "in-memory data buffer creation"); }

Handle<Value>Verify(const Arguments& args) {
  HandleScope scope;

  gpgme_data_t SIG, DATA;
  gpgme_verify_result_t result;
  gpgme_signature_t sig;

  try{
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

    bail(gpgme_op_verify(ctx, SIG, DATA, NULL), "verification");

    result = gpgme_op_verify_result(ctx);
    sig = result->signatures;

    if(sig->status == GPG_ERR_NO_ERROR) return True();
    else                                return False();
  } catch(const char* s) {
    return ThrowException(Exception::Error(String::New(s))); }
}

Handle<Value>Decrypt(const Arguments& args) {
  HandleScope scope;

  gpgme_data_t CIPHER, PLAIN;
  std::string str;
  
  try{
    if (args.Length() != 1)
      return ThrowException(Exception::TypeError(
        String::New("decrypt takes one argument")));

    if (!args[0]->IsString())
      return ThrowException(Exception::TypeError(
        String::New("First argument is a string (cipher data)")));
    String::Utf8Value signature(args[0]->ToString());
    str_to_data(&CIPHER, *signature);

    bail(gpgme_data_new(&PLAIN), "memory to hold decrypted data");
    bail(gpgme_op_decrypt(ctx, CIPHER, PLAIN), "decryption");

    // get the size of the PLAIN data
    off_t length = gpgme_data_seek(PLAIN, SEEK_END, 0);
    // TODO: ensure that this actually works
    return scope.Close(String::New(gpgme_data_release_and_get_mem(PLAIN, (size_t* )length)));

  } catch(const char* s) {
    return ThrowException(Exception::Error(String::New(s))); }
}

extern "C" void init (Handle<Object> target) {
  HandleScope scope;
  init();
  bail(gpgme_new(&ctx), "context creation");
  target->Set(String::New("verify"),
              FunctionTemplate::New(Verify)->GetFunction());
  target->Set(String::New("decrypt"),
              FunctionTemplate::New(Decrypt)->GetFunction());
}
