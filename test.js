var gpg = require('./build/Release/gpg');

var msg = {
  "signature":"-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v2.0.19 (GNU/Linux)\n\niQEcBAABAgAGBQJQa3thAAoJEDwbhYFhTKBdrwsH/jK7rDbodKgZ1CNdKOjOmsWD\ntUC+brptZ+y78AwUPKusIv2t3HBcsecxmn8+dGXiXPLZQJ7cIDtAf8gf78/zHzHh\nnshii5qTYEeMGADTWlMbK9Kdi19t6N3GD6VHm1h2GLuOUi+vRx6WyZ8rPjkcoeR1\n6MGUHBuxPxMct0N+wKmzM+H+uabL3ysiYAyNpO1Q8m//aw/bqtvsydVsfjFAuzBW\nnOswdATDkDkQIl+maVsbrW0jJO6Dqp9RxjdKygObeIY7r8xWiqGdto2oV+4FFDQO\nOyU4jzhtDpGa+jeU8BGRnveiWQgn3Q0NBQnQmrt4rrbKcZAWbsEsfgkCFZhzqYI=\n=FGNI\n-----END PGP SIGNATURE-----",
  "data":"patton\n"}

var verify = function(msg){
  if(gpg.verify(msg.signature, msg.data)) console.log("verified: success");
  else                                    console.log("verified: failed");
};

verify(msg);
msg.data = "foo";
verify(msg);
