# multi-jdbc-client

AUTHOR: Mariano Dominguez  
<marianodominguez@hotmail.com>  
https://www.linkedin.com/in/marianodominguez

VERSION: 2.0

FEEDBACK/BUGS: Please contact me by email.

## Description
All-purpose JDBC client with an emphasis on HiveServer2 and Trino.

**Version 2.0**
- Support for generic JDBC connectivity: `-s generic --url <jdbc_connection_string> --driverClass <jdbc_class_name>`
- Prompt for password if not provided in command argument `-w,--password`
- Get all options (except `--service`) from properties file: `-f,--propFile`
  - The properties file has precedence over command-line options

**Version 1.0**
- Initial release for HiveServer2 and Trino: `-s hive|trino`
- Built-in Kerberos authentication mode: `-k,--kerberos`
- Multiple options for Kerberos keytab (`--keytab`) and configuration (`--krbConf`) files:
  - Path to local file system
  - Path to S3 bucket (using underlying AWS credentials)
  - Base64 encoded data: `--b64keytab`, `--b64krbConf`
    - Base64 values have precedence over files
- Support for additional JDBC parameters: `-j,--jdbcPars`
- In Linux environments, send email notification (via `mail` command) when an error/exception occurs

## Compilation and Usage
See [dependencies](https://github.com/mrdominguez/multi-jdbc-client/blob/master/README.md#dependencies) below.
```
$ javac -cp *:. MultiJdbcClient.java && sudo java -cp *:. MultiJdbcClient

Missing required option: s
usage: MultiJdbcClient [--b64keytab <arg>] [--b64krbConf <arg>] [-c <arg>] [-d <arg>]
       [--driverClass <arg>] [-f <arg>] [-h <arg>] [-j <arg>] [-k] [--keytab <arg>]
       [--krbConf <arg>] [--krbPrincipal <arg>] [--krbRealm <arg>] [-m <arg>] [-p <arg>]
       [-q <arg>] -s <arg> [-u <arg>] [--url <arg>] [-w <arg>]
    --b64keytab <arg>      Encoded keytab (base64)
    --b64krbConf <arg>     Encoded krb5.conf (base64)
 -c,--catalog <arg>        Trino catalog (default: hive)
 -d,--database <arg>       Database (default: default)
    --driverClass <arg>    JDBC driver class (generic data source)
 -f,--propFile <arg>       Properties file
 -h,--host <arg>           Hostname
 -j,--jdbcPars <arg>       Additional JDBC parameters
 -k,--kerberos             Enable Kerberos authentication
    --keytab <arg>         Path to keytab file (local or S3)
    --krbConf <arg>        Path to krb5.conf (local or S3)
    --krbPrincipal <arg>   Keytab principal
    --krbRealm <arg>       Kerberos realm
 -m,--email <arg>          Send email alerts
 -p,--port <arg>           Port
 -q,--query <arg>          Query
 -s,--service <arg>        SQL service (trino, hive, phoenix, generic)
 -u,--user <arg>           Username
    --url <arg>            JDBC connection URL (generic data source)
 -w,--password <arg>       Password
```
Note: `--service phoenix` is equivalent to `--service trino --catalog phoenix`.

## Sample Output
***Trino***
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

***Trino*** (using properties file)
```
$ cat trino.properties
host=*****
kerberos=true
keytab=/etc/trino/admin.keytab
krbPrincipal=admin
query=select current_user

$ java -cp MultiJdbcClient.jar MultiJdbcClient -s trino -propFile trino.properties
properties file: trino.properties
service: trino
user: admin
host: *****
port: 7778
kerberos is enabled
krbConf: /etc/krb5.conf
keytab: /etc/trino/admin.keytab
krbPrincipal: admin
krbRealm: EC2.INTERNAL
query: select current_user
Connected to jdbc:trino://*****:7778/hive/default?KerberosKeytabPath=/etc/trino/admin.keytab&KerberosPrincipal=admin@EC2.INTERNAL&KerberosRemoteServiceName=trino&KerberosConfigPath=/etc/krb5.conf&SSL=true&SSLVerification=NONE
\__ Executing query...
admin _col0
---
```

***Hive***
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
***Generic: MariaDB*** (password input from console)
```
$ java -cp MultiJdbcClient.jar MultiJdbcClient -s generic --url jdbc:mariadb://$(hostname -f):3306 \
--driverClass org.mariadb.jdbc.Driver -u admin -w -q 'select current_user, version()'
Enter password:

service: generic
user: admin
password is set
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
- https://mvnrepository.com/artifact/org.apache.hadoop/hadoop-auth
- https://mvnrepository.com/artifact/org.apache.hadoop/hadoop-common
- https://mvnrepository.com/artifact/org.apache.hive/hive-jdbc
