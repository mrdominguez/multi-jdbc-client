# multi-jdbc-client

AUTHOR: Mariano Dominguez  
<marianodominguez@hotmail.com>  
https://www.linkedin.com/in/marianodominguez

VERSION: 3.0

FEEDBACK/BUGS: Please contact me by email.

## Description
All-purpose JDBC client with native support for:
- HiveServer2 | `org.apache.hive.jdbc.HiveDriver`
- Trino | `io.trino.jdbc.TrinoDriver`
- Phoenix (HBase) | `org.apache.phoenix.jdbc.PhoenixDriver`
- Phoenix Query Server (PQS) | `org.apache.phoenix.queryserver.client.Driver`

## Release Notes 
**Version 3.0**
- Added support for:
  - Phoenix/HBase: `-s phoenix|hbase`
    - HBase znode: `-z,--znode`
    - Consider adding `hbase-site.xml` to Java's CLASSPATH
  - Phoenix Query Server: `-s pqs`
    - Serialization format: `--pqsSerde`
    - Authentication mechanism: `--pqsAuth`
- Minor code improvements

**Version 2.1**
- Improved generic connection handling: URL parsing
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
- Multiple options for Kerberos keytab (`--keytab`) and configuration (`--krbConf`) files:
  - Path to local file system
  - Path to S3 bucket (using underlying AWS credentials)
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
usage: MultiJdbcClient [--b64keytab <arg>] [--b64krbConf <arg>] [-c <arg>] [-d <arg>]
       [-f <arg>] [-h <arg>] [--jdbcDriver <arg>] [--jdbcPars <arg>] [--jdbcUrl <arg>]
       [-k] [--keytab <arg>] [--krbConf <arg>] [--krbPrincipal <arg>] [--krbRealm <arg>]
       [-m <arg>] [-p <arg>] [--pqsAuth <arg>] [--pqsSerde <arg>] [-q <arg>] -s <arg>
       [-u <arg>] [-w <arg>] [-z <arg>]
    --b64keytab <arg>      Encoded keytab (base64)
    --b64krbConf <arg>     Encoded krb5.conf (base64)
 -c,--catalog <arg>        Trino catalog (default: hive)
 -d,--database <arg>       Database (default: default)
 -f,--propFile <arg>       Properties file
 -h,--host <arg>           Hostname
    --jdbcDriver <arg>     *Driver class (generic data source)
    --jdbcPars <arg>       Additional parameters
    --jdbcUrl <arg>        *Connection URL (generic data source)
 -k,--kerberos             Enable Kerberos authentication
    --keytab <arg>         Path to keytab file (local or S3)
    --krbConf <arg>        Path to krb5.conf (local or S3)
    --krbPrincipal <arg>   Keytab principal
    --krbRealm <arg>       Kerberos realm
 -m,--email <arg>          Send email alerts
 -p,--port <arg>           Port
    --pqsAuth <arg>        Authentication mechanism (default: SPENGO)
    --pqsSerde <arg>       Serialization format (default: PROTOBUF)
 -q,--query <arg>          Query
 -s,--service <arg>        *SQL service (trino, hive, phoenix|hbase, pqs, generic)
 -u,--user <arg>           Username
 -w,--password <arg>       Password
 -z,--znode <arg>          HBase znode (default: /hbase)
```

## Sample Output
### Trino
```
$ java -cp MultiJdbcClient.jar MultiJdbcClient -s trino -h $(hostname -f) \
-k -q 'select current_user, version(), current_catalog, current_schema'

service: trino
user: trino
host: *****
port: 7778
kerberos is enabled
krbConf: /etc/krb5.conf
keytab: /etc/trino/trino.keytab
krbPrincipal: trino
krbRealm: EC2.INTERNAL
query: select current_user, version(), current_catalog, current_schema
Connected to jdbc:trino://*****:7778/hive/default?KerberosKeytabPath=/etc/trino/trino.keytab&KerberosPrincipal=trino@EC2.INTERNAL&KerberosRemoteServiceName=trino&KerberosConfigPath=/etc/krb5.conf&SSL=true&SSLVerification=NONE
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
krbRealm: EC2.INTERNAL
query: select current_user
Connected to jdbc:trino://*****:7778/hive/default?KerberosKeytabPath=/etc/trino/qa.keytab&KerberosPrincipal=qa@EC2.INTERNAL&KerberosRemoteServiceName=trino&KerberosConfigPath=/etc/krb5.conf&SSL=true&SSLVerification=NONE
\__ Executing query...
qa _col0
---
```

### HiveServer2
```
$ java -cp MultiJdbcClient.jar MultiJdbcClient -s hive -h $(hostname -f) \
-k -q 'select current_user(), version(), current_database()'

service: hive
user: hadoop
host: *****
port: 10000
kerberos is enabled
krbConf: /etc/krb5.conf
keytab: /etc/hadoop.keytab
krbPrincipal: hadoop
krbRealm: EC2.INTERNAL
query: select current_user(), version(), current_database()
Connected to jdbc:hive2://*****:10000/default;principal=hive/_HOST@EC2.INTERNAL
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
