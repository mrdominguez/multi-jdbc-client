/*
 * Copyright 2023 Mariano Dominguez
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * All-purpose JDBC client with native support for:
 * - Trino
 * - HiveServer2 (Hive)
 * - Phoenix (HBase)
 * - Phoenix Query Server (PQS)
 *
 * Author: Mariano Dominguez
 * Version: 4.2
 * Release date: 2023-08-29
 */

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.UserGroupInformation;

import com.amazonaws.AmazonWebServiceRequest;
import com.amazonaws.services.s3.AmazonS3URI;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.s3.model.GetObjectRequest;
import java.io.File;

import com.amazonaws.util.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.lang3.RandomStringUtils;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.Console;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;

public class MultiJdbcClient {

  private static MultiJdbcClient jdbcClient = new MultiJdbcClient();
  private static String service;
  private static String host;
  private static String port;
  private static String email;
  private static Boolean b64Password = true;

  private static String getPassword() {
	Console console = System.console();
	if (console == null) {
		System.out.println("No console available");
		System.exit(1);
	}

	char[] password = console.readPassword("Enter password: ");
	jdbcClient.b64Password = false;
	return new String(password);
  }

  private static void sendEmail(String email, Exception ex) {
	String s;
	Process p;
	String body = "host: " + jdbcClient.host;
	if ( jdbcClient.port != null ) body += "\nport: " + jdbcClient.port;
	body += "\nservice: " + jdbcClient.service;
	if ( ex != null ) body += "\n\n" + ExceptionUtils.getStackTrace(ex);
	System.out.println("Sending email...");
	try {
		String mailCmd = "echo -e \'" + body + "\' | mail -s " + jdbcClient.getClass().getSimpleName() + " " + email;
		String[] command = {
			"/bin/sh",
			"-c",
			mailCmd
		};
		p = Runtime.getRuntime().exec(command);
		BufferedReader br = new BufferedReader(
			new InputStreamReader(p.getInputStream()));
		while ((s = br.readLine()) != null)
			System.out.println(s);
		p.waitFor();
		System.out.println("\\__ exit: " + p.exitValue());
		p.destroy();
	} catch (Exception e) {
		e.printStackTrace();
  	}
  }

  private static void writeBase64ToFile(String content, String fileName) {
	try { 
		byte[] bytes = Base64.decode(content);
		FileUtils.writeByteArrayToFile(new File(fileName), bytes);
	} catch (Exception e) {
		e.printStackTrace();
		if ( jdbcClient.email != null ) sendEmail(jdbcClient.email, e);
		System.exit(1);
	}
  }

  private static String downloadS3File(String S3Path) {
	String localPath = null;
	try {
		AmazonS3URI S3URI = new AmazonS3URI(S3Path);
		String bucket = S3URI.getBucket();
		String key = S3URI.getKey();
		if ( key == null ) {
			System.out.println("Missing key from S3 path");
			System.exit(1);
		}
		localPath = System.getProperty("java.io.tmpdir") + "/" + key.substring(key.lastIndexOf("/") + 1);
		AmazonS3Client S3Client = new AmazonS3Client();
		S3Client.getObject(new GetObjectRequest(bucket,key), new File(localPath));
	} catch (Exception e) {
		e.printStackTrace();
		if ( jdbcClient.email != null ) sendEmail(jdbcClient.email, e);
		System.exit(1);
	}
	return localPath;
  }

  public static void main(String args[]) throws SQLException, ClassNotFoundException {
	Options options = new Options();

	Option serviceOpt = new Option("s", "service", true, "*SQL service (trino, hive, phoenix|hbase, pqs, generic)");
	serviceOpt.setRequired(true);
	options.addOption(serviceOpt);

	Option catalogOpt = new Option("c", "catalog", true, "Trino catalog (default: hive)");
	catalogOpt.setRequired(false);
	options.addOption(catalogOpt);

	Option databaseOpt = new Option("d", "database", true, "Database (default: default)");
	databaseOpt.setRequired(false);
	options.addOption(databaseOpt);

	Option hostOpt = new Option("h", "host", true, "Hostname");
	hostOpt.setRequired(false);
	options.addOption(hostOpt);

	Option portOpt = new Option("p", "port", true, "Port");
	portOpt.setRequired(false);
	options.addOption(portOpt);

	Option userOpt = new Option("u", "user", true, "Username");
	userOpt.setRequired(false);
	options.addOption(userOpt);

	Option passwordOpt = new Option("w", "password", true, "Password");
	passwordOpt.setRequired(false);
	passwordOpt.setOptionalArg(true);
	options.addOption(passwordOpt);

	Option sslOpt = new Option(null, "https", false, "Use SSL");
	sslOpt.setRequired(false);
	options.addOption(sslOpt);

	Option sslTrustStoreOpt = new Option(null, "sslTrustStorePath", true, "Path to TrustStore file");
	sslTrustStoreOpt.setRequired(false);
	options.addOption(sslTrustStoreOpt);

	Option b64sslTrustStoreOpt = new Option(null, "b64sslTrustStore", true, "Encoded TrustStore (base64)");
	b64sslTrustStoreOpt.setRequired(false);
	options.addOption(b64sslTrustStoreOpt);

	Option sslTrustStorePwOpt = new Option(null, "sslTrustStorePw", true, "TrustStore password (base64)");
	sslTrustStorePwOpt.setRequired(false);
	options.addOption(sslTrustStorePwOpt);

	Option kerberosOpt = new Option("k", "kerberos", false, "Enable Kerberos authentication");
	kerberosOpt.setRequired(false);
	options.addOption(kerberosOpt);

	Option krbConfOpt = new Option(null, "krbConf", true, "Path to krb5.conf file (local or S3)");
	krbConfOpt.setRequired(false);
	options.addOption(krbConfOpt);

	Option b64krbConfOpt = new Option(null, "b64krbConf", true, "Encoded krb5.conf (base64)");
	b64krbConfOpt.setRequired(false);
	options.addOption(b64krbConfOpt);

	Option keytabOpt = new Option(null, "keytab", true, "Path to keytab file (local or S3)");
	keytabOpt.setRequired(false);
	options.addOption(keytabOpt);

	Option b64keytabOpt = new Option(null, "b64keytab", true, "Encoded keytab (base64)");
	b64keytabOpt.setRequired(false);
	options.addOption(b64keytabOpt);

	Option krbPrincipalOpt = new Option(null, "krbPrincipal", true, "Keytab principal");
	krbPrincipalOpt.setRequired(false);
	options.addOption(krbPrincipalOpt);

	Option krbServiceNameOpt = new Option(null, "krbServiceName", true, "Kerberos service name");
	krbServiceNameOpt.setRequired(false);
	options.addOption(krbServiceNameOpt);

	Option krbServiceInstanceOpt = new Option(null, "krbServiceInstance", true, "Kerberos service instance");
	krbServiceInstanceOpt.setRequired(false);
	options.addOption(krbServiceInstanceOpt);

	Option krbServiceRealmOpt = new Option(null, "krbServiceRealm", true, "Kerberos realm (hive only)");
	krbServiceRealmOpt.setRequired(false);
	options.addOption(krbServiceRealmOpt);

	Option queryOpt = new Option("q", "query", true, "Query");
	queryOpt.setRequired(false);
	options.addOption(queryOpt);

	Option emailOpt = new Option("m", "email", true, "Send email");
	emailOpt.setRequired(false);
	options.addOption(emailOpt);

	Option jdbcParsOpt = new Option(null, "jdbcPars", true, "Additional parameters");
	jdbcParsOpt.setRequired(false);
	options.addOption(jdbcParsOpt);

	Option jdbcUrlOpt = new Option(null, "jdbcUrl", true, "*Connection URL");
	jdbcUrlOpt.setRequired(false);
	options.addOption(jdbcUrlOpt);

	Option jdbcDriverOpt = new Option(null, "jdbcDriver", true, "*Driver class");
	jdbcDriverOpt.setRequired(false);
	options.addOption(jdbcDriverOpt);

	Option propFileOpt = new Option("f", "propFile", true, "Properties file");
	propFileOpt.setRequired(false);
	options.addOption(propFileOpt);

	Option znodeOpt = new Option("z", "znode", true, "HBase znode (default: /hbase)");
	znodeOpt.setRequired(false);
	options.addOption(znodeOpt);

	Option pqsSerdeOpt = new Option(null, "pqsSerde", true, "Serialization format (default: PROTOBUF)");
	pqsSerdeOpt.setRequired(false);
	options.addOption(pqsSerdeOpt);

	Option pqsAuthOpt = new Option(null, "pqsAuth", true, "Authentication mechanism (default: SPENGO)");
	pqsAuthOpt.setRequired(false);
	options.addOption(pqsAuthOpt);

	CommandLineParser parser = new DefaultParser();
	HelpFormatter formatter = new HelpFormatter();
	CommandLine cmd = null;

	try {
		cmd = parser.parse(options, args);
	} catch (ParseException e) {
		System.out.println(e.getMessage());
		formatter.printHelp(136, jdbcClient.getClass().getSimpleName(), null, options, null, true);
		System.exit(1);
	}

	service = cmd.getOptionValue("service");
	String catalog = cmd.hasOption("catalog") ? cmd.getOptionValue("catalog") : "hive";
	String database = cmd.hasOption("database") ? cmd.getOptionValue("database") : "default";
	host = cmd.hasOption("host") ? cmd.getOptionValue("host") : "localhost";
	port = cmd.hasOption("port") ? cmd.getOptionValue("port") : null;
	String user = cmd.hasOption("user") ? cmd.getOptionValue("user") : null;
	String password = cmd.hasOption("password") ? cmd.getOptionValue("password") == null ? getPassword() : cmd.getOptionValue("password") : System.getProperty("password");
	Boolean ssl = cmd.hasOption("https") ? true : false;
	String sslTrustStore = cmd.hasOption("sslTrustStorePath") ? cmd.getOptionValue("sslTrustStorePath") : null;
	String b64sslTrustStore = cmd.hasOption("b64sslTrustStore") ? cmd.getOptionValue("b64sslTrustStore") : System.getProperty("b64sslTrustStore");
	String sslTrustStorePw = cmd.hasOption("sslTrustStorePw") ? cmd.getOptionValue("sslTrustStorePw") : System.getProperty("sslTrustStorePw");
	Boolean kerberos = cmd.hasOption("kerberos") ? true : false;
	String krbConf = cmd.hasOption("krbConf") ? cmd.getOptionValue("krbConf") : "/etc/krb5.conf";
	String b64krbConf = cmd.hasOption("b64krbConf") ? cmd.getOptionValue("b64krbConf") : System.getProperty("b64krbConf");
	String keytab = cmd.hasOption("keytab") ? cmd.getOptionValue("keytab") : null;
	String b64keytab = cmd.hasOption("b64keytab") ? cmd.getOptionValue("b64keytab") : System.getProperty("b64keytab");
	String krbPrincipal = cmd.hasOption("krbPrincipal") ? cmd.getOptionValue("krbPrincipal") : null;
	String krbServiceName = cmd.hasOption("krbServiceName") ? cmd.getOptionValue("krbServiceName") : null;
	String krbServiceInstance = cmd.hasOption("krbServiceInstance") ? cmd.getOptionValue("krbServiceInstance") : null;
	String krbServiceRealm = cmd.hasOption("krbServiceRealm") ? cmd.getOptionValue("krbServiceRealm") : "EC2.INTERNAL";
	String query = cmd.hasOption("query") ? cmd.getOptionValue("query") : "show schemas";
	email = cmd.hasOption("email") ? cmd.getOptionValue("email") : null;
	String jdbcPars = cmd.hasOption("jdbcPars") ? cmd.getOptionValue("jdbcPars") : null;
	String jdbcUrl = cmd.hasOption("jdbcUrl") ? cmd.getOptionValue("jdbcUrl") : null;
	String jdbcDriver = cmd.hasOption("jdbcDriver") ? cmd.getOptionValue("jdbcDriver") : null;
	String propFile = cmd.hasOption("propFile") ? cmd.getOptionValue("propFile") : null;
	String znode = cmd.hasOption("znode") ? cmd.getOptionValue("znode") : "/hbase";
	String pqsSerde = cmd.hasOption("pqsSerde") ? cmd.getOptionValue("pqsSerde") : "PROTOBUF";
	String pqsAuth = cmd.hasOption("pqsAuth") ? cmd.getOptionValue("pqsAuth") : "SPENGO";
	Boolean sslTrustStoreS3 = false;
	Boolean krbConfS3 = false;
	Boolean keytabS3 = false;

	if ( propFile != null ) {
		try (InputStream input = new FileInputStream(propFile)) {
			Properties prop = new Properties();
			prop.load(input);
			if ( prop.getProperty("catalog") != null ) catalog = prop.getProperty("catalog");
			if ( prop.getProperty("database") != null ) database = prop.getProperty("database");
			if ( prop.getProperty("host") != null ) host = prop.getProperty("host");
			if ( prop.getProperty("port") != null ) port = prop.getProperty("port");
			if ( prop.getProperty("user") != null ) user = prop.getProperty("user");
			if ( prop.getProperty("password") != null ) password = prop.getProperty("password");
			if ( prop.getProperty("ssl") != null ) ssl = Boolean.parseBoolean(prop.getProperty("ssl"));
			if ( prop.getProperty("sslTrustStorePath") != null ) sslTrustStore = prop.getProperty("sslTrustStorePath");
			if ( prop.getProperty("b64sslTrustStore") != null ) b64sslTrustStore = prop.getProperty("b64sslTrustStore");
			if ( prop.getProperty("sslTrustStorePw") != null ) sslTrustStorePw = prop.getProperty("sslTrustStorePw");
			if ( prop.getProperty("kerberos") != null ) kerberos = Boolean.parseBoolean(prop.getProperty("kerberos"));
			if ( prop.getProperty("krbConf") != null ) krbConf = prop.getProperty("krbConf");
			if ( prop.getProperty("b64krbConf") != null ) b64krbConf = prop.getProperty("b64krbConf");
			if ( prop.getProperty("keytab") != null ) keytab = prop.getProperty("keytab");
			if ( prop.getProperty("b64keytab") != null ) b64keytab = prop.getProperty("b64keytab");
			if ( prop.getProperty("krbPrincipal") != null ) krbPrincipal = prop.getProperty("krbPrincipal");
			if ( prop.getProperty("krbServiceName") != null ) krbServiceName = prop.getProperty("krbServiceName");
			if ( prop.getProperty("krbServiceInstance") != null ) krbServiceInstance = prop.getProperty("krbServiceInstance");
			if ( prop.getProperty("krbServiceRealm") != null ) krbServiceRealm = prop.getProperty("krbServiceRealm");
			if ( prop.getProperty("query") != null ) query = prop.getProperty("query");
			if ( prop.getProperty("email") != null ) email = prop.getProperty("email");
			if ( prop.getProperty("jdbcPars") != null ) jdbcPars = prop.getProperty("jdbcPars");
			if ( prop.getProperty("jdbcUrl") != null ) jdbcUrl = prop.getProperty("jdbcUrl");
			if ( prop.getProperty("jdbcDriver") != null ) jdbcDriver = prop.getProperty("jdbcDriver");
			if ( prop.getProperty("znode") != null ) znode = prop.getProperty("znode");
			if ( prop.getProperty("pqsSerde") != null ) pqsSerde = prop.getProperty("pqsSerde");
			if ( prop.getProperty("pqsAuth") != null ) pqsAuth = prop.getProperty("pqsAuth");
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
	}

	if ( password != null && jdbcClient.b64Password ) {
		byte[] decodedPassword = Base64.decode(password);
		password = new String(decodedPassword);
	}

	if ( b64sslTrustStore != null ) { 
		sslTrustStore = System.getProperty("java.io.tmpdir") + "/" + RandomStringUtils.randomAlphanumeric(10).toUpperCase() + ".truststore";
		writeBase64ToFile(b64sslTrustStore, sslTrustStore);
	}

	if ( sslTrustStorePw != null ) {
		byte[] decodedPassword = Base64.decode(sslTrustStorePw);
		sslTrustStorePw = new String(decodedPassword);
	}

	if ( b64krbConf != null ) { 
		krbConf = System.getProperty("java.io.tmpdir") + "/" + RandomStringUtils.randomAlphanumeric(10).toUpperCase() + ".conf";
		writeBase64ToFile(b64krbConf, krbConf);
	}

	if ( b64keytab != null ) { 
		keytab = System.getProperty("java.io.tmpdir") + "/" + RandomStringUtils.randomAlphanumeric(10).toUpperCase() + ".keytab";
		writeBase64ToFile(b64keytab, keytab);
	}

	if ( sslTrustStore != null && sslTrustStore.contains("s3://") ) {
		sslTrustStore = downloadS3File(sslTrustStore);
		sslTrustStoreS3 = true;
	}

	if ( krbConf.contains("s3://") ) {
		krbConf = downloadS3File(krbConf);
		krbConfS3 = true;
	}

	if ( keytab != null && keytab.contains("s3://") ) {
		keytab = downloadS3File(keytab);
		keytabS3 = true;
	}

	if ( kerberos && ( krbPrincipal == null || keytab == null ) ) {
		System.out.println("Kerberos authentication requires 'krbPrincipal' and 'keytab'");
		System.exit(1);
	}

	if ( ! ssl && ( sslTrustStore != null || sslTrustStorePw != null ) ) ssl = true;

	switch (service) {
		case "hbase":
		case "phoenix":
			Class.forName("org.apache.phoenix.jdbc.PhoenixDriver");
			if ( ! kerberos && user == null ) user = "phoenix";
			if ( port == null ) port = "2181";
			jdbcUrl = "jdbc:phoenix:" + host + ":" + port + ":" + znode;
			if ( kerberos ) jdbcUrl += ":" + krbPrincipal + ":" + keytab;
			break;

		case "pqs":
			Class.forName("org.apache.phoenix.queryserver.client.Driver");
			if ( ! kerberos && user == null ) user = "phoenix";
			if ( port == null ) port = "8765";
			jdbcUrl = "jdbc:phoenix:thin:url=http://" + host + ":" + port + ";serialization=" + pqsSerde;
			if ( kerberos ) jdbcUrl += ";authentication=" + pqsAuth
				+ ";principal=" + krbPrincipal
				+ ";keytab=" + keytab;
			break;

		case "trino":
			Class.forName("io.trino.jdbc.TrinoDriver");
			if ( ! kerberos && user == null ) user = "trino";
			if ( port == null ) port = ( kerberos ) ? "7778" : "8889";
			if ( krbServiceName == null ) krbServiceName = "trino";
			jdbcUrl = "jdbc:trino://" + host + ":" + port + "/" + catalog + "/" + database;
			if ( kerberos ) {
				jdbcUrl += "?KerberosKeytabPath=" + keytab
					+ "&KerberosPrincipal=" + krbPrincipal
					+ "&KerberosRemoteServiceName=" + krbServiceName
					+ "&KerberosConfigPath=" + krbConf;
				if ( krbServiceInstance != null ) jdbcUrl += "&KerberosServicePrincipalPattern=" + krbServiceName + "@" + krbServiceInstance;
				if ( ! ssl ) jdbcUrl += "&SSL=true&SSLVerification=NONE";
			}
			if ( ssl ) {
			       	if ( kerberos ) {
					jdbcUrl += "&";
				} else {
					jdbcUrl += "?";
				}
				jdbcUrl += "SSL=true";
				if ( sslTrustStore != null ) jdbcUrl += "&SSLTrustStorePath=" + sslTrustStore;
				if ( sslTrustStorePw != null ) jdbcUrl += "&SSLTrustStorePassword=" + sslTrustStorePw;
			}
			break;

		case "hive":
			Class.forName("org.apache.hive.jdbc.HiveDriver");
			if ( ! kerberos && user == null ) user = "hive";
			if ( port == null ) port = "10000";
			if ( krbServiceName == null ) krbServiceName = "hive";
			if ( krbServiceInstance == null ) krbServiceInstance = "_HOST";
			jdbcUrl = "jdbc:hive2://" + host + ":" + port + "/" + database;
			if ( kerberos ) {
				jdbcUrl += ";principal=" + krbServiceName + "/" + krbServiceInstance + "@" + krbServiceRealm;
				try {
					Configuration conf = new org.apache.hadoop.conf.Configuration();
					conf.set("hadoop.security.authentication", "Kerberos");
					conf.set("java.security.krb5.conf", krbConf);
					UserGroupInformation.setConfiguration(conf);
					UserGroupInformation.loginUserFromKeytab(krbPrincipal, keytab);
				} catch (Exception e) {
					e.printStackTrace();
					if ( email != null ) sendEmail(email, e);
					System.exit(1);
				}
			}
			if ( ssl ) jdbcUrl += ";ssl=true";
			if ( sslTrustStore != null ) jdbcUrl += ";sslTrustStore=" + sslTrustStore;
			if ( sslTrustStorePw != null ) jdbcUrl += ";trustStorePassword=" + sslTrustStorePw;
			break;

		case "generic":
			if ( jdbcUrl == null || jdbcDriver == null || user == null ) {
				System.out.println("Generic data source requires 'jdbcDriver', 'jdbcUrl' and 'user'");
	                        System.exit(1);
			}
			Class.forName(jdbcDriver);
			if ( ! jdbcUrl.startsWith("jdbc:") ) {
				System.out.println("Invalid URL: " + jdbcUrl + "\nConnection string must begin with 'jdbc:'");
				System.exit(1);
			}
			try {
				host = new URI(jdbcUrl.substring(5)).getHost();
				port = Integer.toString(new URI(jdbcUrl.substring(5)).getPort());
				service = new URI(jdbcUrl.substring(5)).getScheme();
			} catch (URISyntaxException e) {
				e.printStackTrace();
			}
			break;

		default:
			System.out.println("Invalid service: " + service);
			System.exit(1);
	}
	if ( kerberos && user == null ) user = krbPrincipal.split("@")[0].split("/")[0];
	if ( jdbcPars != null ) jdbcUrl += jdbcPars;

	System.out.println("\nservice: " + service);
	if ( propFile != null ) System.out.println("propFile: " + propFile);
	System.out.println("user: " + user);
	if ( password != null ) System.out.println("password is set");
	System.out.println("host: " + host);
	System.out.println("port: " + port);
	if ( ! cmd.getOptionValue("service").equals("generic") ) {
		if ( kerberos ) {
			System.out.println("kerberos is enabled");
			System.out.println("krbConf: " + krbConf);
			System.out.println("keytab: " + keytab);
			System.out.println("krbPrincipal: " + krbPrincipal);
			System.out.println("krbServiceName: " + krbServiceName);
			System.out.print("krbServiceInstance ");
			if ( krbServiceInstance == null ) {
				System.out.println("is not set");
			} else {
				System.out.println(": " + krbServiceInstance);
			}
			if ( service.equals("hive") ) System.out.println("krbServiceRealm: " + krbServiceRealm);
		} else {
			System.out.println("kerberos is disabled");
		}

		if ( ssl ) System.out.println("SSL is enabled");
		if ( sslTrustStore != null ) System.out.println("sslTrustStore: " + sslTrustStore);
		if ( sslTrustStorePw != null ) System.out.println("sslTrustStorePw is set");
	}
	System.out.println("query: " + query);
	System.out.println("jdbcUrl: " + jdbcUrl);

	Properties properties = new Properties();
	properties.setProperty("user", user); 
	if ( password != null ) properties.setProperty("password", password);

	try {
		Connection sqlConnection = DriverManager.getConnection(jdbcUrl, properties);
		System.out.println("Connection established");

		Statement stmt = sqlConnection.createStatement();
//		stmt.setMaxRows(10);

		System.out.println("\\__ Executing query...");
		ResultSet rs = stmt.executeQuery(query);
		ResultSetMetaData rsmd = rs.getMetaData();
		int columnsNumber = rsmd.getColumnCount();

		while(rs.next()) {
			for (int i = 1; i <= columnsNumber; i++) {
				if (i > 1) System.out.print(",  ");
				String columnValue = rs.getString(i);
				System.out.print(columnValue + " " + rsmd.getColumnName(i));
			}
			System.out.println();
		}
		System.out.println("---");

		rs.close();
		stmt.close();
		sqlConnection.close();
	} catch (Exception e) {
		e.printStackTrace();
		System.out.println("Exception caught!");
		if ( email != null ) sendEmail(email, e);
	} finally {
		if ( b64sslTrustStore != null || sslTrustStoreS3 ) new File(sslTrustStore).delete();
		if ( b64krbConf != null || krbConfS3 ) new File(krbConf).delete();
		if ( b64keytab != null || keytabS3 ) new File(keytab).delete();
	}
  }
}
