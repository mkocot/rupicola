Rupicola
==========

Rust Remote Procedure Caller Application

Rupicola is a program that allows calling procedures on remote machines.
Procedures to be called are part of application configuration.

## How to call anything?
This section briefly describe how to use server from client perspective.

Server support HTTP/1.1 and require valid HTTP POST request. If permission checking is enabled then request **should** contains basic auth with login and password. Only exception from this is made when method and bind point is explicit marked as allowing unchecked requests from loopback.

Body of request contains valid JSON RPC 2.0. For details see [http://www.jsonrpc.org/specification](http://www.jsonrpc.org/specification).

Note that all methods using arguments **require** passing arguments in request by-name, and positional parameters are not supported yet.

### Streaming

Streaming version use HTTP Chunked response, and thus require HTTP/1.1 compatible client.
Current implementation stream stdout from called executable "as is".

## Configuration
This section provides detailed information about configuration files.
Configuration file use YAML format. Below is detailed rundown of all configuration sections.

Configuration contains following sections:

* include
* protocol
* limits
* log
* methods

### include
To include other configuration files use
```yaml
include:
  - file 1
  - file 2
```
First ever appearance of method or any other definition is used and it redefinition is ignored.
Default action for missing included file is warning (non fatal). For now maximum depth is hardcoded to 10.

### protocol
Section used to configure bind points, auth mode and change default path to streaming and RPC subsystems.

#### bind
Define listening bindpoint. This object have following fields:
**type, address, port, allow_private**

*allow_private* is special flag which indicate if request from loopback is handled without checking credentials. This flag can be used on any bind point type. Default value is false.

Note that any field that is not highlighted is ignored during parsing configuration.
For defining http listening endpoint use:
```yaml
type: http
address: any.ipv4.address
port: int
```

To use https:
```yaml
type: https
address: any.ipv4.address
key: path/to/key
cert: path/to/cert
port: int
```
To use unix socket
```yaml
type: unix
address: /path/to/socket
mode: int
gid: int
uid: int
```
Default values for mode is 666, gid - inherited from running process, uid - inherited from running process.

#### auth-basic
To enforce checking auth you can specify login and password. Server use simple http basic auth. Please note that this method is safe when used with https or unix bind point type.
```yaml
login: any-string
```
Password field is string

Hashed version of password use following modes:

- Standard BSD hash
- Enhanced DES-based hash
- MD5 crypt
- HMAC-SHA1 hash
- SHA-256 based
- SHA-512 based
- standard unix crypt

To generate MD5 based hash or standard unix use for example openssl passwd.

```yaml
passowrd: $1$sRN7MKRJ$XfbAXBpoOphTIhBRZuPAl.
password: ktsudxoI79bPk
```

This is recommended method of storing password.

To disable crypt and force plaintext password check set field is_plaintext to true

```yaml
is_plaintext: true
```

#### uri
To change default uri path for streamed and RPC define
```yaml
uri:
    streamed: /path
    rpc: /path
```
Both fields are optional and require string field type. Note that path must be prefixed with trailing '/'.

| Parameter | Default   |
| --------- | --------- |
| streamed  | /streamed |
| rpc       | /jsonrpc  |

### limits
This field allow to set default limits for methods. All fields are optional
Currently supported fields:

| Name         | Default | Unit | Description |
| ------------ | ------- | ---- | ----------- |
| read-timeout | 20000   | ms   | Maximum time spend for next portion of data from external source. Setting it to 0 disables timeout |
| exec-timeout | 0       | ms   | Maximum time spend while processing request. Setting it to 0 disables timeout (which is default). NOTE: Currently this is not working at all |
| payload-size | 5242880 | byte | Maximum size for request (RPC and stream). THIS IS GLOBAL MAXIMUM (methods cannot change it) |
| max-response | 5242880 | byte | Maximum response for RPC. Could be changed on per-method level |
| request-wait | 30000   | ms   | Maximum timeout used when waiting for client request. THIS IS GLOBAL MAXIMUM (methods cannot change it). Setting it to 0 disables timeout |


### log
Configure how handle output from logs. Possible output sink is syslog or stdout.
You can change log level with
level: string-level value.

Possible levels are: off, trace, debug, info, warn, error
If backend is not specified then stdout is used by default.
backend: stdout | syslog
to change path used by syslog use
path: /path/to/socket

### methods
This is place where you specify how handle processing request.
Construction for method definition is as follow:
```yaml
method-name:
    private: boolean (default: false)
    streamed: boolean
    encoding: utf-8 | base64 (default: utf-8)
    params: (default: nil)
        parameter_name:
            type: string | number | bool
            optional: boolean (default: false)
    invoke:
        exec: string
        delay: int (default: 10)
        args: (default: nil)
            - arg0
            - {param: string}
            - [arg1, {param: string}]
            - ["arg 2", {param: string, skip: boolean}]
    	run-as: (default: nil)
        	gid: int
        	uid: int
    output: (default: nil)
        format: json
        response: YAML (optional)
    limits: (default: nil)
        - fields from limits (same as global level, default: from global)
```
All methods are defined as object with keys that reflect names. All names should be string value. All methods by default are public which means they are accessible from loopback and external addresses. To force only local access specify flag 'private' to true. Method can work only as streamed or RPC. This aspect is controlled by settings field 'streamed' to either true or false.

For special function it's also possible to encode raw byte output from invoked application as Base64. This is controlled by field 'encoding'. Default all stdout is converted to UTF-8.

All methods can require parameters. Only supported method of providing them is by-name. All parameters should have valid string name and specified type. If parameter is flagged as optional (optional: true) then all arguments using this parameters are ignored in invocation.

To specify application to run it's required to set exec field to correct path.

RPC methods can be invoked in 'delayed' mode. This is special case for methods which ends in terminal state (for example reboot). If response field is present then value of field 'response' is returned to user and real method execution is delayed by specified amount in delay field (in seconds).

All arguments in args list are passed to executable unless:
*    argument use optional field, and this field is missing in request,
*    argument use optional phantom field, and this field is missing in request.

Phantom field is used to bind presence of given argument to presence of parameter - without using argument value.

Values can be nested using lists, but going too deep is not recommended.
For example this is perfectly valid argument definition ```[[[[[[a],[b]],[[c]]],[" "]], [{param: uri}]], [" cba"]]``` 
and it could be simplified to ```["abc ", {param: uri}, " cba"]```

To use parameter in normal mode use {param: name}. Phantom mode use field skip with value true: ```{param: name, skip:true}```.

Special parameter value is 'self'. This get request in JSON format and pass as single argument to executable.

Default all methods are executed with privilages of user running main process. To change user running procedure define field 'run-as' with 'gid' and 'uid' specified as required. Both fields are required.

As default output from executable is treated as series of bytes, but this can be changed to JSON. In this mode expected output from executable is valid JSON document. To change mode use 
```yaml
output:
    format: json
```
### Example
For example configuration see examples/sample.conf

## Contact and License
Rupicola is written by Marcin Kocot for [Korbank S.A.](http://korbank.com).
The primary distribution point is [https://github.com/korbank/rupicola](https://github.com/korbank/rupicola).

Rupicola is distributed under GNU GPL v3 license. See LICENSE file for details.

GPL terms do not apply to the invoked procedures provided by configuration file.
