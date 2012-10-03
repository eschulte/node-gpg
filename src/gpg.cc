/* basics */
#include <cstring>

/* for node */
#include <v8.h>
#include <node.h>

/* for GPG */
#include <locale.h>
#include <gpgme.h>

using namespace v8;
using namespace node;

namespace gpg_v8 {
  
Handle<Value> verify( const Arguments &args ) {
  HandleScope scope;

  char* str = "schulte";

  return String::New( str, strlen(str));
}
  
}

extern "C"
void init(Handle<Object> target){
  HandleScope scope;
  Local<FunctionTemplate> t = FunctionTemplate::New(gpg_v8::verify);
  target->Set( String::NewSymbol( "verify" ), t->GetFunction() );
};
