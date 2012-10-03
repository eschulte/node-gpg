#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdlib.h>
#include <locale.h>
#include <gpgme.h>

using namespace v8;
using namespace node;

// TODO: move this into a class
gpgme_ctx_t ctx;

void bail(gpgme_error_t err, const char * msg){
  // run a GPG operation and throw informative errors on GPG errors
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
  // TODO: allow other versions to be specified
  bail(gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP), "engine init"); }

void str_to_data(gpgme_data_t *data, const char* string){
  bail(gpgme_data_new_from_mem(data, string, strlen(string), 1),
       "in-memory data buffer creation"); }

// TODO: implement async version, rename this VerifySync
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
        String::New("First argument must be a string (signature)")));
    String::Utf8Value signature(args[0]->ToString());
    str_to_data(&SIG, *signature);

    if (!args[1]->IsString())
      return ThrowException(Exception::TypeError(
        String::New("Second argument must be a string (data)")));
    String::Utf8Value data(args[1]->ToString());
    str_to_data(&DATA, *data);

    bail(gpgme_op_verify(ctx, SIG, DATA, NULL), "verification");

    result = gpgme_op_verify_result(ctx);
    sig = result->signatures;

    if(sig->status == GPG_ERR_NO_ERROR) return True();
    else                                return False();
  } catch(const char* s) {
    return ThrowException(Exception::Error(String::New(s))); } }

// TODO: implement async version, rename this DecryptSync
Handle<Value>Decrypt(const Arguments& args) {
  HandleScope scope;

  gpgme_data_t CIPHER, PLAIN;
  char * plain;
  size_t amt;

  try{
    if (args.Length() != 1)
      return ThrowException(Exception::TypeError(
        String::New("decrypt takes one argument")));

    if (!args[0]->IsString())
      return ThrowException(Exception::TypeError(
        String::New("First argument must be a string (cipher data)")));
    String::Utf8Value signature(args[0]->ToString());
    str_to_data(&CIPHER, *signature);

    bail(gpgme_data_new(&PLAIN), "memory to hold decrypted data");
    bail(gpgme_op_decrypt(ctx, CIPHER, PLAIN), "decryption");

    // decrypt
    plain = gpgme_data_release_and_get_mem(PLAIN, &amt);
    plain[amt] = 0;

    return scope.Close(String::New(plain));
  } catch(const char* s) {
    return ThrowException(Exception::Error(String::New(s))); } }

Handle<Value>DecryptAndVerify(const Arguments& args) {
  HandleScope scope;

  gpgme_data_t CIPHER, PLAIN;
  char * plain;
  size_t amt;

  try{
    if (args.Length() != 1)
      return ThrowException(Exception::TypeError(
        String::New("decrypt takes one argument")));

    if (!args[0]->IsString())
      return ThrowException(Exception::TypeError(
        String::New("First argument must be a string (cipher data)")));
    String::Utf8Value signature(args[0]->ToString());
    str_to_data(&CIPHER, *signature);

    bail(gpgme_data_new(&PLAIN), "memory to hold decrypted data");
    bail(gpgme_op_decrypt_verify(ctx, CIPHER, PLAIN), "decryption");

    // decrypt
    plain = gpgme_data_release_and_get_mem(PLAIN, &amt);
    plain[amt] = 0;

    return scope.Close(String::New(plain));
  } catch(const char* s) {
    return ThrowException(Exception::Error(String::New(s))); } }

// TODO: add key objects, then have this take the key of the signer
Handle<Value>Sign(const Arguments& args) {
  HandleScope scope;

  gpgme_key_t key;
  gpgme_data_t PLAIN, SIG;
  char * sig;
  size_t amt;

  try{
    if (args.Length() != 2)
      return ThrowException(Exception::TypeError(
        String::New("sign takes two arguments")));

    if (!args[0]->IsString())
      return ThrowException(Exception::TypeError(
        String::New("First argument must be a string indicating the signer")));
    String::Utf8Value pattern(args[0]->ToString());

    if (!args[1]->IsString())
      return ThrowException(Exception::TypeError(
        String::New("Second argument must be a string of the data to sign")));
    String::Utf8Value plain(args[1]->ToString());
    str_to_data(&PLAIN, *plain);

    // get the key of the signer
    gpgme_signers_clear(ctx);
    bail(gpgme_op_keylist_start(ctx, *pattern, 1), "searching keys");
    bail(gpgme_op_keylist_next(ctx, &key), "selecting first matched key");
    bail(gpgme_op_keylist_end(ctx), "done listing keys");
    // print key identification
    // printf("key owned by '%s'\n",
    //        gpgme_key_get_string_attr(key, GPGME_ATTR_USERID, NULL, 0));
    gpgme_signers_add(ctx, key);
    bail(gpgme_data_new(&SIG), "memory to hold signature");
    bail(gpgme_op_sign(ctx, PLAIN, SIG, GPGME_SIG_MODE_DETACH), "signing");

    sig = gpgme_data_release_and_get_mem(SIG, &amt);
    sig[amt] = 0;

    // sign the message
    return scope.Close(String::New(sig));
  } catch(const char* s) {
    return ThrowException(Exception::Error(String::New(s))); } }

Handle<Value>Encrypt(const Arguments& args) {
  HandleScope scope;

  gpgme_key_t *rec;
  gpgme_data_t PLAIN, CIPHER;
  char * cipher;
  size_t amt;
  int i;

  try{
    if (args.Length() != 2)
      return ThrowException(Exception::TypeError(
        String::New("sign takes two arguments")));

    // TODO: should take a list of keys
    if (!args[0]->IsArray())
      return ThrowException(Exception::TypeError(
        String::New("First argument must be a list of recipient strings")));

    if (!args[1]->IsString())
      return ThrowException(Exception::TypeError(
       String::New("Second argument must be a string of the data to encrypt")));
    String::Utf8Value plain(args[1]->ToString());
    str_to_data(&PLAIN, *plain);

    // build the list of recipients
    Local<Array> array = Local<Array>::Cast(args[0]);

    // need to initialize rec to hold keys + NULL
    rec = (gpgme_key_t*)malloc(sizeof(gpgme_key_t)*(array->Length() + 1));

    for(i=0;i<array->Length();i++){
      String::Utf8Value str(array->Get(i)->ToString());
      bail(gpgme_op_keylist_start(ctx, *str, 1), "searching keys");
      bail(gpgme_op_keylist_next(ctx, &rec[i]),
           "selecting first matched key");
      bail(gpgme_op_keylist_end(ctx), "done listing keys");
    }
    rec[i] = NULL;

    // encrypt the message
    bail(gpgme_data_new(&CIPHER), "memory to hold cipher text");
    bail(gpgme_op_encrypt(ctx, rec, GPGME_ENCRYPT_NO_ENCRYPT_TO, PLAIN, CIPHER),
         "encrypting");

    cipher = gpgme_data_release_and_get_mem(CIPHER, &amt);
    cipher[amt] = 0;

    return scope.Close(String::New(cipher));
  } catch(const char* s) {
    return ThrowException(Exception::Error(String::New(s))); } }

extern "C" void init (Handle<Object> target) {
  HandleScope scope;
  init();
  bail(gpgme_new(&ctx), "context creation");
  gpgme_set_armor(ctx, 1);
  target->Set(String::New("verify"),
              FunctionTemplate::New(Verify)->GetFunction());
  target->Set(String::New("decrypt"),
              FunctionTemplate::New(Decrypt)->GetFunction());
  target->Set(String::New("decryptAndVerify"),
              FunctionTemplate::New(DecryptAndVerify)->GetFunction());
  target->Set(String::New("sign"),
              FunctionTemplate::New(Sign)->GetFunction());
  target->Set(String::New("encrypt"),
              FunctionTemplate::New(Encrypt)->GetFunction());
}
