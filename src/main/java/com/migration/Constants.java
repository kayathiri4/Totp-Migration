package com.migration;

public class Constants {

    public static final String HOSTNAME = System.getenv("HOSTNAME") != null ? System.getenv("HOSTNAME") : "api.asg.io";
    public static final String USERNAME = System.getenv("USERNAME") != null ? System.getenv("USERNAME") : "h52q3EHetKFIfhdpMPlQqLd_nf0a";
    public static final String PASSWORD = System.getenv("PASSWORD") != null ? System.getenv("PASSWORD") : "eI9yV7M_zCMQ25nchrUH7PGlCfn7KoDb4LrC_XaUUdEa";


    // DB configs
    public static final String MSSQL_DRIVER = System.getenv("MSSQL_DRIVER") != null ? System.getenv("MSSQL_DRIVER") : "com.microsoft.sqlserver.jdbc.SQLServerDriver";
    public static final String DB_URL = System.getenv("DB_URL") != null ? System.getenv("DB_URL") : "jdbc:sqlserver://localhost:1433;databaseName=demoidentity";
    public static final String DB_USERNAME = System.getenv("DB_USERNAME") != null ? System.getenv("DB_USERNAME") : "SA";
    public static final String DB_PASSWORD = System.getenv("DB_PASSWORD") != null ? System.getenv("DB_PASSWORD") : "myStrongPaas42!emc2";

    // System property org.wso2.CipherTransformation
    public static final String CIPHER_TRANSFORMATION = System.getenv("CIPHER_TRANSFORMATION") != null ? System.getenv("CIPHER_TRANSFORMATION") : "AES/GCM/NoPadding";
    // Server configuration JCEProvider, update this if we change this via toml.
    public static final String CIPHER_TRANSFORMATION_PROVIDER = System.getenv("CIPHER_TRANSFORMATION_PROVIDER") != null ? System.getenv("CIPHER_TRANSFORMATION_PROVIDER") : "BC";
    public static final String DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM = System.getenv("DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM") != null ? System.getenv("DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM") : "AES";
    // Add the value of encryption.key in toml.
    public static final String SECRET = System.getenv("SECRET") != null ? System.getenv("SECRET") : "03BAFEB27A8E871CAD83C5CD4E771DAB";

}
