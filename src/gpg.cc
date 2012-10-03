/* for node */
#include <v8.h>
#include <node.h>
#include <node_version.h>
#include <node_buffer.h>
/* for GPG */
#include <string.h>
#include <locale.h>
#include <gpgme.h>

using namespace v8;
using namespace node;

class Gpg : ObjectWrap {
public:
  static void Initialize(Handle<Object> target);
  Handle<Value> setContext(const Arguments &args);
  Handle<Value> Verify(const Arguments* args);
};

void Gpg::Initialize(Handle<Object> target){
  HandleScope scope;

  Local<FunctionTemplate> t = FunctionTemplate::New(New);
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("Gpg"));

  NODE_SET_PROTOTYPE_METHOD(t, "setContext", setContext);
  NODE_SET_PROTOTYPE_METHOD(t, "verify", Verify);
  
  target->Set(String::NewSymbol("Gpg"), t->GetFunction());
}

Handle<Value> Gpg::New(const Arguments* args) {
  HandleScope scope;
  Gpg *gpg = new Gpg();
  gpg->Wrap(args.Holder());
  gpg->ctx = NULL;
  return args.This();
}

Handle<Value> Gpg::setContext(const Arguments &args) {
  Gpg *gpg = ObjectWrap::Unwrap<Gpg>(args.Holder());

  // GPG initialization (maybe should be in init)
  setlocale (LC_ALL, "");
  gpgme_check_version (NULL);
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  #ifdef LC_MESSAGES
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
  #endif
  gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

  // setup a context (could take arguments later)
  gpgme_ctx_t ctx;
  gpgme_new(&ctx);
  gpg->ctx = ctx;

  return True();
}

Handle<Value> Gpg::Verify(const Arguments &args) {
  HandleScope scope;
  
  Gpg *gpg = ObjectWrap::Unwrap<Gpg>(args.Holder());

  if(args.length() != 2)
    return ThrowException(Exception::TypeError(
     String::New("requires 2 arguments")));

  if(!args[0]->IsString())
    return ThrowException(Exception::TypeError(
      String::New("first argument must be a string (signature)")));
  String::Utf8Value sig_str(args[0]->ToString());
  gpgme_data_t sig_data;
  gpgme_data_new_from_mem(&sig_data, sig_str, strlen(sig_str), 1);

  if(!args[1]->IsString())
    return ThrowException(Exception::TypeError(
      String::New("second argument must be a string (content)")));
  String::Utf8Value content_str(args[1]->ToString());
  gpgme_data_t content_data;
  gpgme_data_new_from_mem(&content_data, content_str, strlen(content_str), 1);
  
  gpgme_op_verify(gpg->ctx, sig_data, content_data, NULL);

  gpgme_signature_t sig = gpgme_op_verify_result(gpg->ctx)->signatures;

  if (sig->status == GPG_ERR_NO_ERROR)
    return True();
  else
    return False();
}

}

extern "C"
void init(Handle<Object> target){ return Gpg::Initialize(target); };
