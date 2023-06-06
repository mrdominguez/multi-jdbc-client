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
 * All-purpose JDBC client with an emphasis on HiveServer2 and Trino.
 * Author: Mariano Dominguez
 * Version: 2.1
 * Release date: 2023-05-30
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

  public static Boolean b64Password = true;
  private static String getPassword() {
	Console console = System.console();
	if (console == null) {
		System.out.println("No console available");
		System.exit(1);
	}

	char[] password = console.readPassword("Enter password: ");
	System.out.println();
	E2EJdbcClient.b64Password = false;
	return new String(password);
  }

  private static void emailAlert(String email, String body) {
	String s;
	Process p;
	System.out.println ("Sending email alert...");
	try {
		String mailCmd = "echo -e \"" + body + "\" | mail -s \"Error: SQL Monitor\" " + email;
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
		System.out.println ("\\__ exit: " + p.exitValue());
		p.destroy();
	} catch (Exception e) {
		e.printStackTrace();
  	}
  }

  private static void writeBase64ToFile(String content, String keytab, String email, String host, String service) {
	try { 
		byte[] bytes = Base64.decode(content);
		FileUtils.writeByteArrayToFile(new File(keytab), bytes);
	} catch (Exception e) {
		e.printStackTrace();
		if ( email != null ) emailAlert(email, "host: " + host + "\nservice: " + service + "\n\n" + e);
		System.exit(1);
	}
  }

  private static String downloadS3File(String S3Path, String email, String host, String service) {
	String localPath = null;
	try {
		AmazonS3URI S3URI = new AmazonS3URI(S3Path);
		String bucket = S3URI.getBucket();
		String key = S3URI.getKey();
		localPath = key.substring(key.lastIndexOf("/") + 1);
		AmazonS3Client S3Client = new AmazonS3Client();
		S3Client.getObject(new GetObjectRequest(bucket,key), new File(localPath));
	} catch (Exception e) {
		e.printStackTrace();
		if ( email != null ) emailAlert(email, "host: " + host + "\nservice: " + service + "\n\n" + e);
		System.exit(1);
	}
	return localPath;
  }

  public static void main(String args[]) throws SQLException, ClassNotFoundException {
	MultiJdbcClient m = new MultiJdbcClient();
	Options options = new Options();

	Option serviceOpt = new Option("s", "service", true, "SQL service (trino, hive, phoenix, generic)");
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

	Option emailOpt = new Option("m", "email", true, "Send email alerts");
	emailOpt.setRequired(false);
	options.addOption(emailOpt);

	Option jdbcParsOpt = new Option("j", "jdbcPars", true, "Additional JDBC parameters");
	jdbcParsOpt.setRequired(false);
	options.addOption(jdbcParsOpt);

	Option urlOpt = new Option(null, "url", true, "JDBC connection URL (generic data source)");
	urlOpt.setRequired(false);
	options.addOption(urlOpt);

	Option driverClassOpt = new Option(null, "driverClass", true, "JDBC driver class (generic data source)");
	driverClassOpt.setRequired(false);
	options.addOption(driverClassOpt);

	Option propFileOpt = new Option("f", "propFile", true, "Properties file");
	propFileOpt.setRequired(false);
	options.addOption(propFileOpt);

	CommandLineParser parser = new DefaultParser();
	HelpFormatter formatter = new HelpFormatter();
	CommandLine cmd = null;

	try {
		cmd = parser.parse(options, args);
	} catch (ParseException e) {
		System.out.println(e.getMessage());
		formatter.printHelp(90, m.getClass().getSimpleName(), null, options, null, true);
		System.exit(1);
	}

	String service = cmd.getOptionValue("service");
	String catalog = cmd.hasOption("catalog") ? cmd.getOptionValue("catalog") : "hive";
	String database = cmd.hasOption("database") ? cmd.getOptionValue("database") : "default";
	String host = cmd.hasOption("host") ? cmd.getOptionValue("host") : "localhost";
	String port = cmd.hasOption("port") ? cmd.getOptionValue("port") : null;
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
	String email = cmd.hasOption("email") ? cmd.getOptionValue("email") : null;
	String jdbcPars = cmd.hasOption("jdbcPars") ? cmd.getOptionValue("jdbcPars") : null;
	String url = cmd.hasOption("url") ? cmd.getOptionValue("url") : null;
	String driverClass = cmd.hasOption("driverClass") ? cmd.getOptionValue("driverClass") : null;
	String propFile = cmd.hasOption("propFile") ? cmd.getOptionValue("propFile") : null;
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
			if ( prop.getProperty("url") != null ) url = prop.getProperty("url");
			if ( prop.getProperty("driverClass") != null ) driverClass = prop.getProperty("driverClass");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	if ( password != null && E2EJdbcClient.b64Password ) {
		byte[] decodedPassword = Base64.decode(password);
		password = new String(decodedPassword);
	}

	if ( b64krbConf != null ) { 
		krbConf = "krb5_" + RandomStringUtils.randomAlphanumeric(10).toUpperCase() + ".conf";
		writeBase64ToFile(b64krbConf, krbConf, email, host, service);
	}
	if ( b64keytab != null ) { 
		keytab = RandomStringUtils.randomAlphanumeric(10).toUpperCase() + ".keytab";
		writeBase64ToFile(b64keytab, keytab, email, host, service);
	}

	if ( krbConf.contains("s3://") ) {
		krbConf = downloadS3File(krbConf, email, host, service);
		krbConfS3 = true;
	}
	if ( keytab != null && keytab.contains("s3://") ) {
		keytab = downloadS3File(keytab, email, host, service);
		keytabS3 = true;
	}
	
	switch (service) {
		case "phoenix":
			catalog = "phoenix";
		case "trino":
			Class.forName("io.trino.jdbc.TrinoDriver");
			if ( port == null ) port = ( kerberos ) ? "7778" : "8889";
			if ( keytab == null ) keytab = "/etc/trino/trino.keytab";
			if ( krbPrincipal == null ) krbPrincipal = "trino";
			if ( user == null ) user = krbPrincipal;
			url = "jdbc:trino://" + host + ":" + port + "/" + catalog + "/" + database;
			if ( kerberos ) url += "?KerberosKeytabPath=" + keytab
				+ "&KerberosPrincipal=" + krbPrincipal + "@" + krbRealm
				+ "&KerberosRemoteServiceName=trino&KerberosConfigPath=" + krbConf
				+ "&SSL=true&SSLVerification=NONE";
			if ( jdbcPars != null ) url += jdbcPars;
			break;

		case "hive":
			Class.forName("org.apache.hive.jdbc.HiveDriver");
			if ( port == null ) port = "10000";
			if ( krbPrincipal == null ) krbPrincipal = "hadoop";
			if ( user == null ) user = krbPrincipal;
			url = "jdbc:hive2://" + host + ":" + port + "/" + database;
			if ( kerberos ) {
				url += ";principal=hive/_HOST@" + krbRealm;
				if ( keytab == null ) keytab = "/etc/hadoop.keytab";
				try {
					Configuration conf = new org.apache.hadoop.conf.Configuration();
					conf.set("hadoop.security.authentication", "Kerberos");
					conf.set("java.security.krb5.conf", krbConf);
					String principal = cmd.hasOption("krbPrincipal") ? krbPrincipal + "@" + krbRealm : krbPrincipal + "/" + host + "@" + krbRealm;
					UserGroupInformation.setConfiguration(conf);
					UserGroupInformation.loginUserFromKeytab(principal, keytab);
				} catch (Exception e) {
					e.printStackTrace();
					if ( email != null ) emailAlert(email, "host: " + host + "\nservice: " + service + "\n\n" + e);
					System.exit(1);
				}
			}
			if ( jdbcPars != null ) url += jdbcPars;
			break;

		case "generic":
			if ( url == null || driverClass == null || user == null ) {
				System.out.println("Generic data source requires 'driverClass', 'url' and 'user'");
	                        System.exit(1);
			}
			Class.forName(driverClass);
			if ( ! url.startsWith("jdbc:") ) {
				System.out.println("Invalid URL: " + url + "\nConnection string must begin with 'jdbc:'");
				System.exit(1);
			}
			if ( jdbcPars != null ) url += jdbcPars;
			try {
				host = new URI(url.substring(5)).getHost();
				port = Integer.toString(new URI(url.substring(5)).getPort());
				service = new URI(url.substring(5)).getScheme();
			} catch (URISyntaxException e) {
				e.printStackTrace();
			}
			break;

		default:
			System.out.println("Invalid service: " + service);
			System.exit(1);
	}

	System.out.println("service: " + service);
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
		Connection sqlConnection = DriverManager.getConnection(url, properties);
		System.out.println("Connected to " + url);

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
		if ( email != null ) emailAlert(email, "host: " + host + "\nservice: " + service + "\n\n" + e);
	} finally {
		if ( b64krbConf != null || krbConfS3 ) new File(krbConf).delete();
		if ( b64keytab != null || keytabS3 ) new File(keytab).delete();
	}
  }
}
