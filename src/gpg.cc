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

namespace gpg {
  class Context : ObjectWrap {
  public:
    static void Initialize(Handle<Object> target);
    Handle<Value> setContext(const Arguments &args);
    Handle<Value> Verify(const Arguments* args);
  };

  static void Initialize(Handle<Object> target);

  /*
   * Context methods
   */

  void Context::Initialize(v8::Handle<v8::Object> target){
    HandleScope scope;
    Local<FunctionTemplate> t = FunctionTemplate::New(New);
    t->InstanceTemplate()->SetInternalFieldCount(1);
    
    NODE_SET_PROTOTYPE_METHOD(t, "setContext", setContext);
    NODE_SET_PROTOTYPE_METHOD(t, "verify", Verify);
    
    target->Set(String::NewSymbol("Context"), t->GetFunction());
  }

  Handle<Value> Context::New(const Arguments& args) {
    HandleScope scope;
    Context *ctx = new Context();
    ctx->Wrap(args.This());
    return args.This();
  }
  
  Handle<Value> Context::Context() : ObjectWrap() {
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
  }

  Handle<Value> Context::Verify(const Arguments &args) {
    HandleScope scope;
    
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
