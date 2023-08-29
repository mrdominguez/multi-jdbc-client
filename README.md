# multi-jdbc-client

AUTHOR: Mariano Dominguez  
<marianodominguez@hotmail.com>  
https://www.linkedin.com/in/marianodominguez

FEEDBACK/BUGS: Please contact me by email.

## Description
All-purpose JDBC client with native support for:
- Trino | `io.trino.jdbc.TrinoDriver`
- HiveServer2 (Hive) | `org.apache.hive.jdbc.HiveDriver`
- Phoenix (HBase) | `org.apache.phoenix.jdbc.PhoenixDriver`
- Phoenix Query Server (PQS) | `org.apache.phoenix.queryserver.client.Driver`

## Release Notes 
**Version 4.2**

New SSL options:
- `--https`, which translates to `SSL=true` for `trino` and `ssl=true` for `hive` (parameters are case-sensitive)
- `--sslTrustStorePath`, which translates to `SSLTrustStorePath=<>` for `trino` and `sslTrustStore=<>` for `hive`
- `--sslTrustStorePw`, which translates to `SSLTrustStorePassword=<>` for `trino` and `trustStorePassword=<>` for `hive` (it can be set as `-D` system property)
- `--b64sslTrustStore`, base64 encoded TrustStore (also, system property)

The password for the TrustStore must be Base64-encoded. Additional SSL related parameters can be set using `--jdbcPars`.

In the case of `trino`, using TLS (and a configured shared secret) is required for Kerberos authentication. Thus, for the sake of simplicity, `--kerberos` is equivalent to `--kerberos --https --jdbcPars '&SSLVerification=NONE'`

**Version 4.0**
- If Kerberos authentication (`-k`) is enabled, `--krbPrincipal` and `--keytab` are now required (no default values assumed)
- New `hive` and `trino` options:
  - Kerberos service name: `--krbServiceName`
  - Kerberos service instance: `--krbServiceInstance`
  - Kerberos realm (`hive` only): `--krbServiceRealm`

`--krbServiceName ${USER} --krbServiceInstance ${HOST} --krbServiceRealm ${REALM}` is equivalent to the following JDBC parameters:
- (`trino`) `KerberosServicePrincipalPattern=${USER}@${HOST}`
- (`hive`) `principal=${USER}/${HOST}@${REALM}`

If `krbServiceInstance` is not set, `${HOST}` gets replaced with...
- (`trino`) the hostname of the Trino coordinator (after canonicalization if enabled)
- (`hive`) a wildcard placeholder (`_HOST`) containing the fully qualified domain name (FQDN) of the server running the HiveServer daemon process

**Version 3.2**
- Temporary files downloaded from S3 or created as decoded data use `java.io.tmpdir` (`/tmp` by default)
- Full exception stack trace included in email body
- Minor code improvements

**Version 3.0**
- Added support for:
  - Phoenix/HBase: `-s phoenix|hbase`
    - HBase znode: `-z,--znode`
    - Consider adding `hbase-site.xml` to Java's CLASSPATH
  - Phoenix Query Server: `-s pqs`
    - Serialization format: `--pqsSerde`
    - Authentication mechanism: `--pqsAuth`

**Version 2.1**
- Enhanced generic connection handling: URL parsing
- Unless manually entered upon prompt, password must be Base64-encoded:
  - System property
  - Command-line argument
  - Properties file

How to use `base64` to encode data:

*String*
```
$ echo -n 'password' | base64
cGFzc3dvcmQ=
```
*File*
```
$ base64 -w0 /path/to/file
IyBMaWNlbnNlZCB0byB0aGUgQXBhY2hlIFN ...
```

**Version 2.0**
- Support for generic JDBC connectivity: `-s generic`
  - Connection URL: `--jdbcUrl`
  - Driver class: `--jdbcDriver`
- Prompt for password if not provided in command argument: `-w,--password`
- Get all options (except `--service`) from properties file: `-f,--propFile`
  - The properties file has precedence over command-line options

**Version 1.0**
- Initial release with support for:
  - HiveServer2: `-s hive`
  - Trino: `-s trino`
- Built-in Kerberos authentication mode: `-k,--kerberos`
- Both Kerberos keytab (`--keytab`) and configuration (`--krbConf`) files can be:
  - A path to the local file system
  - A path to an S3 bucket (using underlying AWS credentials)
  - Base64 encoded data: `--b64keytab`, `--b64krbConf`
    - Base64 values have precedence over files
- Additional parameters: `-j,--jdbcPars`
- System properties: `-Dpassword`, `-Db64keytab`, `-Db64krbConf`
- In Linux environments, send email notification (via `mail` command) when an error/exception occurs

## Compilation and Usage
This is the list of JAR files I used to compile and test the code:
```
aws-java-sdk-core-1.12.397.jar
aws-java-sdk-s3-1.12.397.jar
commons-cli-1.3.jar
commons-collections-3.2.2.jar
commons-configuration2-2.8.0.jar
commons-io-2.8.0.jar
commons-lang3-3.12.0.jar
commons-logging-1.1.3.jar
commons-text-1.10.0.jar
hadoop-auth-3.3.3-amzn-2.jar
hadoop-common-3.3.3-amzn-2.jar
hive-jdbc-3.1.3-amzn-3-standalone.jar
jackson-annotations-2.12.7.jar
jackson-core-2.12.7.jar
jackson-databind-2.12.7.1.jar
joda-time-2.9.9.jar
mariadb-java-client-2.7.2.jar
phoenix-client-hbase-2.4-5.1.2.jar
phoenix-queryserver-client-6.0.0.jar
trino-jdbc-403-amzn-0.jar
```
Links to [Maven artifacts](https://github.com/mrdominguez/multi-jdbc-client/blob/master/README.md#dependencies) below.
```
$ javac -cp *:. MultiJdbcClient.java && sudo java -cp *:. MultiJdbcClient

Missing required option: s
usage: MultiJdbcClient [--b64keytab <arg>] [--b64krbConf <arg>] [--b64sslTrustStore <arg>] [-c <arg>] [-d <arg>] [-f <arg>] [-h <arg>]
       [--https] [--jdbcDriver <arg>] [--jdbcPars <arg>] [--jdbcUrl <arg>] [-k] [--keytab <arg>] [--krbConf <arg>] [--krbPrincipal
       <arg>] [--krbServiceInstance <arg>] [--krbServiceName <arg>] [--krbServiceRealm <arg>] [-m <arg>] [-p <arg>] [--pqsAuth <arg>]
       [--pqsSerde <arg>] [-q <arg>] -s <arg> [--sslTrustStorePath <arg>] [--sslTrustStorePw <arg>] [-u <arg>] [-w <arg>] [-z <arg>]
    --b64keytab <arg>            Encoded keytab (base64)
    --b64krbConf <arg>           Encoded krb5.conf (base64)
    --b64sslTrustStore <arg>     Encoded TrustStore (base64)
 -c,--catalog <arg>              Trino catalog (default: hive)
 -d,--database <arg>             Database (default: default)
 -f,--propFile <arg>             Properties file
 -h,--host <arg>                 Hostname
    --https                      Use SSL
    --jdbcDriver <arg>           *Driver class
    --jdbcPars <arg>             Additional parameters
    --jdbcUrl <arg>              *Connection URL
 -k,--kerberos                   Enable Kerberos authentication
    --keytab <arg>               Path to keytab file (local or S3)
    --krbConf <arg>              Path to krb5.conf file (local or S3)
    --krbPrincipal <arg>         Keytab principal
    --krbServiceInstance <arg>   Kerberos service instance
    --krbServiceName <arg>       Kerberos service name
    --krbServiceRealm <arg>      Kerberos realm (hive only)
 -m,--email <arg>                Send email
 -p,--port <arg>                 Port
    --pqsAuth <arg>              Authentication mechanism (default: SPENGO)
    --pqsSerde <arg>             Serialization format (default: PROTOBUF)
 -q,--query <arg>                Query
 -s,--service <arg>              *SQL service (trino, hive, phoenix|hbase, pqs, generic)
    --sslTrustStorePath <arg>    Path to TrustStore file
    --sslTrustStorePw <arg>      TrustStore password (base64)
 -u,--user <arg>                 Username
 -w,--password <arg>             Password
 -z,--znode <arg>                HBase znode (default: /hbase)
```

## Default Values

| Option | Value |
| :---: | :---: |
| `catalog` | hive |
| `database` | default |
| `host` | localhost |
| `port` | `trino` 8889, 7778 (kerberos), `hive` 10000, `hbase` 2181, `pqs` 8765 |
| `user` | `trino` trino, `hive` hive, `hbase` phoenix, `pqs` phoenix |
| `krbConf` | /etc/krb5.conf |
| `krbServiceName` | `trino` trino, `hive` hive |
| `krbServiceInstance` | `trino` _null_, `hive` _HOST |
| `krbRealm` | EC2.INTERNAL |
| `query` | show schemas |
| `znode` | /hbase |
| `pqsSerde` | PROTOBUF |
| `pqsAuth` | SPENGO |

## Sample Output
### Trino (Hive catalog)
```
$ java -cp MultiJdbcClient.jar MultiJdbcClient -s trino -h $(hostname -f) -k \
--keytab /etc/trino/trino.keytab --krbPrincipal trino \
-q 'select current_user, version(), current_catalog, current_schema'

service: trino
user: trino
host: *****
port: 7778
kerberos is enabled
krbConf: /etc/krb5.conf
keytab: /etc/trino/trino.keytab
krbPrincipal: trino
krbServiceName: trino
krbServiceInstance is not set
query: select current_user, version(), current_catalog, current_schema
jdbcUrl: jdbc:trino://*****:7778/hive/default?KerberosKeytabPath=/etc/trino/trino.keytab&KerberosPrincipal=trino&KerberosRemoteServiceName=trino&KerberosConfigPath=/etc/krb5.conf&SSL=true&SSLVerification=NONE
Connection established
\__ Executing query...
trino _col0,  403.amzn.0 _col1,  hive _col2,  default _col3
---
```

Using properties file:
```
$ cat trino.properties
host=*****
kerberos=true
keytab=/etc/trino/qa.keytab
krbPrincipal=qa
query=select current_user

$ java -cp MultiJdbcClient.jar MultiJdbcClient -s trino -propFile trino.properties

service: trino
propFile: trino.properties
user: qa
host: *****
port: 7778
kerberos is enabled
krbConf: /etc/krb5.conf
keytab: /etc/trino/qa.keytab
krbPrincipal: qa
krbServiceName: trino
krbServiceInstance is not set
query: select current_user
jdbcUrl: jdbc:trino://*****:7778/hive/default?KerberosKeytabPath=/etc/trino/qa.keytab&KerberosPrincipal=qa&KerberosRemoteServiceName=trino&KerberosConfigPath=/etc/krb5.conf&SSL=true&SSLVerification=NONE
Connection established
\__ Executing query...
qa _col0
---
```
### HiveServer2
```
$ java -cp MultiJdbcClient.jar MultiJdbcClient -s hive -h $(hostname -f) -k \
--keytab /etc/hadoop/hadoop.keytab --krbPrincipal hadoop/***** \
-q 'select current_user(), version(), current_database()'

service: hive
user: hadoop
host: *****
port: 10000
kerberos is enabled
krbConf: /etc/krb5.conf
keytab: /etc/hadoop/hadoop.keytab
krbPrincipal: hadoop/*****
krbServiceName: hive
krbServiceInstance : _HOST
krbServiceRealm: EC2.INTERNAL
query: select current_user(), version(), current_database()
jdbcUrl: jdbc:hive2://*****:10000/default;principal=hive/_HOST@EC2.INTERNAL
Connection established
\__ Executing query...
hadoop _c0,  3.1.3-amzn-3 rUnknown _c1,  default _c2
---
```
### Generic: MariaDB
Password input from console:
```
$ java -cp MultiJdbcClient.jar MultiJdbcClient -s generic --jdbcUrl jdbc:mariadb://$(hostname -f):3306 \
--jdbcDriver org.mariadb.jdbc.Driver -u admin -w -q 'select current_user, version()'
Enter password:

service: mariadb
user: admin
password is set
host: *****
port: 3306
query: select current_user, version()
Connected to jdbc:mariadb://*****:3306
\__ Executing query...
admin@% current_user,  8.0.23 version()
---
```

## Dependencies
- https://mvnrepository.com/artifact/com.amazonaws/aws-java-sdk-core
- https://mvnrepository.com/artifact/com.amazonaws/aws-java-sdk-s3
- https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-annotations
- https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-core
- https://mvnrepository.com/artifact/com.fasterxml.jackson.core/jackson-databind
- https://mvnrepository.com/artifact/commons-cli/commons-cli
- https://mvnrepository.com/artifact/commons-collections/commons-collections
- https://mvnrepository.com/artifact/commons-io/commons-io
- https://mvnrepository.com/artifact/commons-logging/commons-logging
- https://mvnrepository.com/artifact/io.trino/trino-jdbc
- https://mvnrepository.com/artifact/joda-time/joda-time
- https://mvnrepository.com/artifact/org.apache.commons/commons-configuration2
- https://mvnrepository.com/artifact/org.apache.commons/commons-lang3
- https://mvnrepository.com/artifact/org.apache.commons/commons-text
- https://mvnrepository.com/artifact/org.apache.hadoop/hadoop-auth
- https://mvnrepository.com/artifact/org.apache.hadoop/hadoop-common
- https://mvnrepository.com/artifact/org.apache.hive/hive-jdbc
- https://mvnrepository.com/artifact/org.apache.phoenix/phoenix-client-hbase-2.4
- https://mvnrepository.com/artifact/org.apache.phoenix/phoenix-queryserver-client
- https://mvnrepository.com/artifact/org.mariadb.jdbc/mariadb-java-client
