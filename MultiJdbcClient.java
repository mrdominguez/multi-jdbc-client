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
 * - HiveServer2
 * - Trino
 * - Phoenix (HBase)
 * - Phoenix Query Server (PQS)
 *
 * Author: Mariano Dominguez
 * Version: 3.2
 * Release date: 2023-06-17
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

	Option kerberosOpt = new Option("k", "kerberos", false, "Enable Kerberos authentication");
	kerberosOpt.setRequired(false);
	options.addOption(kerberosOpt);

	Option krbConfOpt = new Option(null, "krbConf", true, "Path to krb5.conf (local or S3)");
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

	Option krbRealmOpt = new Option(null, "krbRealm", true, "Kerberos realm");
	krbRealmOpt.setRequired(false);
	options.addOption(krbRealmOpt);

	Option queryOpt = new Option("q", "query", true, "Query");
	queryOpt.setRequired(false);
	options.addOption(queryOpt);

	Option emailOpt = new Option("m", "email", true, "Send email");
	emailOpt.setRequired(false);
	options.addOption(emailOpt);

	Option jdbcParsOpt = new Option(null, "jdbcPars", true, "Additional parameters");
	jdbcParsOpt.setRequired(false);
	options.addOption(jdbcParsOpt);

	Option jdbcUrlOpt = new Option(null, "jdbcUrl", true, "*Connection URL (generic data source)");
	jdbcUrlOpt.setRequired(false);
	options.addOption(jdbcUrlOpt);

	Option jdbcDriverOpt = new Option(null, "jdbcDriver", true, "*Driver class (generic data source)");
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
		formatter.printHelp(88, jdbcClient.getClass().getSimpleName(), null, options, null, true);
		System.exit(1);
	}

	service = cmd.getOptionValue("service");
	String catalog = cmd.hasOption("catalog") ? cmd.getOptionValue("catalog") : "hive";
	String database = cmd.hasOption("database") ? cmd.getOptionValue("database") : "default";
	host = cmd.hasOption("host") ? cmd.getOptionValue("host") : "localhost";
	port = cmd.hasOption("port") ? cmd.getOptionValue("port") : null;
	String user = cmd.hasOption("user") ? cmd.getOptionValue("user") : null;
	String password = cmd.hasOption("password") ? cmd.getOptionValue("password") == null ? getPassword() : cmd.getOptionValue("password") : System.getProperty("password");
	Boolean kerberos = cmd.hasOption("kerberos") ? true : false;
	String krbConf = cmd.hasOption("krbConf") ? cmd.getOptionValue("krbConf") : "/etc/krb5.conf";
	String b64krbConf = cmd.hasOption("b64krbConf") ? cmd.getOptionValue("b64krbConf") : System.getProperty("b64krbConf");
	String keytab = cmd.hasOption("keytab") ? cmd.getOptionValue("keytab") : null;
	String b64keytab = cmd.hasOption("b64keytab") ? cmd.getOptionValue("b64keytab") : System.getProperty("b64keytab");
	String krbPrincipal = cmd.hasOption("krbPrincipal") ? cmd.getOptionValue("krbPrincipal") : null;
	String krbRealm = cmd.hasOption("krbRealm") ? cmd.getOptionValue("krbRealm") : "EC2.INTERNAL";
	String query = cmd.hasOption("query") ? cmd.getOptionValue("query") : "show schemas";
	email = cmd.hasOption("email") ? cmd.getOptionValue("email") : null;
	String jdbcPars = cmd.hasOption("jdbcPars") ? cmd.getOptionValue("jdbcPars") : null;
	String jdbcUrl = cmd.hasOption("jdbcUrl") ? cmd.getOptionValue("jdbcUrl") : null;
	String jdbcDriver = cmd.hasOption("jdbcDriver") ? cmd.getOptionValue("jdbcDriver") : null;
	String propFile = cmd.hasOption("propFile") ? cmd.getOptionValue("propFile") : null;
	String znode = cmd.hasOption("znode") ? cmd.getOptionValue("znode") : "/hbase";
	String pqsSerde = cmd.hasOption("pqsSerde") ? cmd.getOptionValue("pqsSerde") : "PROTOBUF";
	String pqsAuth = cmd.hasOption("pqsAuth") ? cmd.getOptionValue("pqsAuth") : "SPENGO";
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
			if ( prop.getProperty("kerberos") != null ) kerberos = Boolean.parseBoolean(prop.getProperty("kerberos"));
			if ( prop.getProperty("krbConf") != null ) krbConf = prop.getProperty("krbConf");
			if ( prop.getProperty("b64krbConf") != null ) b64krbConf = prop.getProperty("b64krbConf");
			if ( prop.getProperty("keytab") != null ) keytab = prop.getProperty("keytab");
			if ( prop.getProperty("b64keytab") != null ) b64keytab = prop.getProperty("b64keytab");
			if ( prop.getProperty("krbPrincipal") != null ) krbPrincipal = prop.getProperty("krbPrincipal");
			if ( prop.getProperty("krbRealm") != null ) krbRealm = prop.getProperty("krbRealm");
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

	if ( b64krbConf != null ) { 
		krbConf = System.getProperty("java.io.tmpdir") + "/" + RandomStringUtils.randomAlphanumeric(10).toUpperCase() + ".conf";
		writeBase64ToFile(b64krbConf, krbConf);
	}
	if ( b64keytab != null ) { 
		keytab = System.getProperty("java.io.tmpdir") + "/" + RandomStringUtils.randomAlphanumeric(10).toUpperCase() + ".keytab";
		writeBase64ToFile(b64keytab, keytab);
	}

	if ( krbConf.contains("s3://") ) {
		krbConf = downloadS3File(krbConf);
		krbConfS3 = true;
	}
	if ( keytab != null && keytab.contains("s3://") ) {
		keytab = downloadS3File(keytab);
		keytabS3 = true;
	}
	
	String keytabFolder = "/etc/security/keytabs/";
	switch (service) {
		case "hbase":
		case "phoenix":
			Class.forName("org.apache.phoenix.jdbc.PhoenixDriver");
			if ( port == null ) port = "2181";
			if ( krbPrincipal == null ) krbPrincipal = "phoenix";
			if ( keytab == null ) keytab = keytabFolder + krbPrincipal + ".keytab";
			jdbcUrl = "jdbc:phoenix:" + host + ":" + port + ":" + znode;
			if ( kerberos ) jdbcUrl += ":" + krbPrincipal + "@" + krbRealm + ":" + keytab;
			break;

		case "pqs":
			Class.forName("org.apache.phoenix.queryserver.client.Driver");
			if ( port == null ) port = "8765";
			if ( krbPrincipal == null ) krbPrincipal = "phoenix";
			if ( keytab == null ) keytab = keytabFolder + krbPrincipal + ".keytab";
			jdbcUrl = "jdbc:phoenix:thin:url=http://" + host + ":" + port + ";serialization=" + pqsSerde;
			if ( kerberos ) jdbcUrl += ";authentication=" + pqsAuth
				+ ";principal=" + krbPrincipal + "@" + krbRealm
				+ ";keytab=" + keytab;
			break;

		case "trino":
			Class.forName("io.trino.jdbc.TrinoDriver");
			if ( port == null ) port = ( kerberos ) ? "7778" : "8889";
			if ( krbPrincipal == null ) krbPrincipal = "trino";
			if ( keytab == null ) keytab = keytabFolder + krbPrincipal + ".keytab";
			jdbcUrl = "jdbc:trino://" + host + ":" + port + "/" + catalog + "/" + database;
			if ( kerberos ) jdbcUrl += "?KerberosKeytabPath=" + keytab
				+ "&KerberosPrincipal=" + krbPrincipal + "@" + krbRealm
				+ "&KerberosRemoteServiceName=trino&KerberosConfigPath=" + krbConf
				+ "&SSL=true&SSLVerification=NONE";
			break;

		case "hive":
			Class.forName("org.apache.hive.jdbc.HiveDriver");
			if ( port == null ) port = "10000";
			if ( krbPrincipal == null ) krbPrincipal = "hadoop";
			jdbcUrl = "jdbc:hive2://" + host + ":" + port + "/" + database;
			if ( kerberos ) {
				jdbcUrl += ";principal=hive/_HOST@" + krbRealm;
				if ( keytab == null ) keytab = keytabFolder + krbPrincipal + ".keytab";
				try {
					Configuration conf = new org.apache.hadoop.conf.Configuration();
					conf.set("hadoop.security.authentication", "Kerberos");
					conf.set("java.security.krb5.conf", krbConf);
					String principal = cmd.hasOption("krbPrincipal") ? krbPrincipal + "@" + krbRealm : krbPrincipal + "/" + host + "@" + krbRealm;
					UserGroupInformation.setConfiguration(conf);
					UserGroupInformation.loginUserFromKeytab(principal, keytab);
				} catch (Exception e) {
					e.printStackTrace();
					if ( email != null ) sendEmail(email, e);
					System.exit(1);
				}
			}
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
	if ( user == null ) user = krbPrincipal;
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
			System.out.println("krbRealm: " + krbRealm);
		} else {
			System.out.println("kerberos is disabled");
		}
	}
	System.out.println("query: " + query);

	Properties properties = new Properties();
	properties.setProperty("user", user); 
	if ( password != null ) properties.setProperty("password", password);

	try {
		Connection sqlConnection = DriverManager.getConnection(jdbcUrl, properties);
		System.out.println("Connected to " + jdbcUrl);

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
		if ( b64krbConf != null || krbConfS3 ) new File(krbConf).delete();
		if ( b64keytab != null || keytabS3 ) new File(keytab).delete();
	}
  }
}
