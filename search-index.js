var searchIndex = {};
searchIndex["matrix_federation"] = {"doc":"","items":[[5,"sign_request","matrix_federation","Compute the signature for an outgoing federation request",null,{"inputs":[{"name":"signingkeypair"},{"name":"str"},{"name":"str"},{"name":"str"},{"name":"str"}],"output":{"name":"signature"}}],[5,"sign_request_with_content","","Compute the signature for an outgoing federation request",null,{"inputs":[{"name":"signingkeypair"},{"name":"str"},{"name":"str"},{"name":"str"},{"name":"str"},{"name":"option"}],"output":{"name":"signature"}}],[5,"verify_request_with_content","","",null,{"inputs":[{"name":"signature"},{"name":"verifykey"},{"name":"str"},{"name":"str"},{"name":"str"},{"name":"str"},{"name":"option"}],"output":{"name":"verifyresultdetached"}}],[5,"generate_auth_header","","Generate a Matrix Authorization header.",null,{"inputs":[{"name":"signingkeypair"},{"name":"str"},{"name":"str"},{"name":"str"},{"name":"str"},{"name":"option"}],"output":{"name":"string"}}],[0,"key","","Helper functions for the key API",null,null],[3,"TlsFingerprint","matrix_federation::key","",null,null],[12,"sha256","","",0,null],[3,"KeyApiResponse","","",null,null],[4,"ValidationError","","",null,null],[13,"Serialization","","",1,null],[5,"validate_key_server_v2_response","","Verifies the a response from a key server.",null,null],[11,"fmt","","",1,null],[11,"fmt","","",1,null],[11,"description","","",1,null],[11,"cause","","",1,null],[11,"from","","",1,{"inputs":[{"name":"serdejsonerror"}],"output":{"name":"validationerror"}}],[11,"fmt","","",0,null],[11,"clone","","",0,null],[11,"hash","","",0,null],[11,"eq","","",0,null],[11,"ne","","",0,null],[11,"partial_cmp","","",0,null],[11,"lt","","",0,null],[11,"le","","",0,null],[11,"gt","","",0,null],[11,"ge","","",0,null],[11,"cmp","","",0,null],[11,"fmt","","",2,null],[11,"clone","","",2,null],[11,"hash","","",2,null],[11,"eq","","",2,null],[11,"ne","","",2,null],[11,"partial_cmp","","",2,null],[11,"lt","","",2,null],[11,"le","","",2,null],[11,"gt","","",2,null],[11,"ge","","",2,null],[11,"cmp","","",2,null],[11,"create","","",2,{"inputs":[{"name":"signingkeypair"},{"name":"str"},{"name":"string"}],"output":{"name":"keyapiresponse"}}],[11,"with_time","","",2,{"inputs":[{"name":"signingkeypair"},{"name":"str"},{"name":"string"},{"name":"datetime"}],"output":{"name":"keyapiresponse"}}],[11,"server_name","","",2,null],[11,"tls_fingerprints","","",2,null],[11,"valid_until_ts","","",2,null],[11,"verify_keys","","",2,null],[11,"old_verify_keys","","",2,null],[11,"signatures","","",2,null],[11,"signatures_mut","","",2,null],[11,"as_canonical","","",2,null],[0,"ser","matrix_federation","",null,null],[0,"hash","matrix_federation::ser","",null,null],[4,"TypedHash","matrix_federation::ser::hash","",null,null],[13,"Sha256","","",3,null],[13,"Sha512","","",3,null],[11,"fmt","","",3,null],[11,"clone","","",3,null],[11,"hash","","",3,null],[11,"eq","","",3,null],[11,"ne","","",3,null],[11,"partial_cmp","","",3,null],[11,"lt","","",3,null],[11,"le","","",3,null],[11,"gt","","",3,null],[11,"ge","","",3,null],[11,"cmp","","",3,null],[11,"serialize","","",3,null],[11,"deserialize","","",3,{"inputs":[{"name":"d"}],"output":{"name":"result"}}],[0,"verify_keys","matrix_federation::ser","",null,null],[3,"VerifyKeys","matrix_federation::ser::verify_keys","",null,null],[12,"map","","",4,null],[11,"fmt","","",4,null],[11,"clone","","",4,null],[11,"hash","","",4,null],[11,"eq","","",4,null],[11,"ne","","",4,null],[11,"partial_cmp","","",4,null],[11,"lt","","",4,null],[11,"le","","",4,null],[11,"gt","","",4,null],[11,"ge","","",4,null],[11,"cmp","","",4,null],[11,"new","","",4,{"inputs":[],"output":{"name":"verifykeys"}}],[11,"from_key","","",4,{"inputs":[{"name":"verifykey"}],"output":{"name":"verifykeys"}}],[11,"deref","","",4,null],[11,"default","","",4,{"inputs":[],"output":{"name":"verifykeys"}}],[11,"serialize","","",4,null],[11,"deserialize","","",4,{"inputs":[{"name":"d"}],"output":{"name":"result"}}],[17,"UNPADDED_BASE64","matrix_federation","",null,null]],"paths":[[3,"TlsFingerprint"],[4,"ValidationError"],[3,"KeyApiResponse"],[4,"TypedHash"],[3,"VerifyKeys"]]};
initSearch(searchIndex);
