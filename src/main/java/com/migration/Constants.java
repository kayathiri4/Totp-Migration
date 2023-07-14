package com.migration;

public class Constants {

    public static final String HOSTNAME = "api.asg.io";
    public static final String USERNAME = "";
    public static final String PASSWORD = "";


    // DB configs
    public static final String MSSQL_DRIVER = "com.microsoft.sqlserver.jdbc.SQLServerDriver";
    public static final String DB_URL = "jdbc:sqlserver://localhost:1433;databaseName=demoidentity";
    public static final String DB_USERNAME = System.getenv("DB_USERNAME") != null ? System.getenv("DB_USERNAME") : "";
    public static final String DB_PASSWORD = System.getenv("DB_PASSWORD") != null ? System.getenv("DB_PASSWORD") : "";

    // System property org.wso2.CipherTransformation
    public static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    // Server configuration JCEProvider, update this if we change this via toml.
    public static final String CIPHER_TRANSFORMATION_PROVIDER = "BC";
    public static final String DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM = "AES";
    // Add the value of encryption.key in toml.
    public static final String SECRET = "";



}
