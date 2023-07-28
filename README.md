# Totp-Migration

## Steps
1. Add the following configs in the environment variables.
```
public static final String HOSTNAME = "api.asg.io";
public static final String USERNAME = "<client-id>";
public static final String PASSWORD = "<client-secret>";

// DB configs
public static final String MSSQL_DRIVER = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
public static final String DB_URL = "jdbc:sqlserver://localhost:1433;databaseName=demoidentity";
public static final String DB_USERNAME = "";
public static final String DB_PASSWORD = "";

// System property org.wso2.CipherTransformation
public static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
// Server configuration JCEProvider, update this if we change this via toml.
public static final String CIPHER_TRANSFORMATION_PROVIDER = "BC";
public static final String DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM = "AES";
// Add the value of encryption.key in toml.
public static final String SECRET = "<SYMMETRIC-KEY>";
```
2. Run `mvn clean install`
3. Run `java -jar totp-migration-<version>-jar-with-dependencies.jar` from `target/`

