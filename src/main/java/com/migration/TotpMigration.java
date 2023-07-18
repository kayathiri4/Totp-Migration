package com.migration;

import com.google.gson.JsonSyntaxException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.*;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.impl.client.CloseableHttpClient;

import java.net.URLEncoder;
import java.nio.charset.Charset;

import com.google.gson.Gson;

import java.security.Security;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.*;

import org.apache.http.HttpEntity;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class TotpMigration {

    private static final Log log = LogFactory.getLog(TotpMigration.class);

    private static final String PASSWORD = Constants.PASSWORD;
    private static final String MSSQL_DRIVER = Constants.MSSQL_DRIVER;
    private static final String DB_URL = Constants.DB_URL;
    private static final String DB_USERNAME = Constants.DB_USERNAME;
    private static final String DB_PASSWORD = Constants.DB_PASSWORD;
    private static final String CIPHER_TRANSFORMATION = Constants.CIPHER_TRANSFORMATION;
    private static final String CIPHER_TRANSFORMATION_PROVIDER = Constants.CIPHER_TRANSFORMATION_PROVIDER;
    private static final String DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM = Constants.DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM;
    private static final String SECRET = Constants.SECRET;
    public static final int GCM_TAG_LENGTH = 128;
    private static Gson gson = new Gson();

    public static final String HOSTNAME = Constants.HOSTNAME;
    public static final String API_URL = "https://"+ HOSTNAME + "/oauth2/token";
    public static final String API_URL_CLAIM_DIALECT = "https://"+ HOSTNAME + "/api/server/v1/claim-dialects";
    public static final String  API_URL_USER_SEARCH = "https://"+ HOSTNAME + "/scim2/Users";
    public static final String API_URL_PATCH_USER = "https://"+ HOSTNAME + "/scim2/Users/";

    static String accessToken = "";
    static String dialectId = "";

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());
        try {

            log.info("Starting the migration process...");
            // Create a connection to current IDP the database
            Class.forName(MSSQL_DRIVER);
            Connection connection = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);
            // Create a statement
            Statement statement = connection.createStatement();
            // Execute a query to get the required data
            String query = "SELECT USER_NAME AS USERNAME, " +
                    "(SELECT DATA_VALUE FROM IDN_IDENTITY_USER_DATA " +
                    "WHERE USER_NAME = ud.USER_NAME AND DATA_KEY = 'http://wso2.org/claims/identity/secretkey') " +
                    "AS TOTP_SECRET " +
                    "FROM IDN_IDENTITY_USER_DATA ud WHERE DATA_KEY = 'http://wso2.org/claims/identity/totpEnabled' " +
                    "AND DATA_VALUE = 'true' AND USER_NAME LIKE 'ASGARDEO-USER/%';";
            ResultSet resultSet = statement.executeQuery(query);

            //Get access token (This method also use to refresh the access token, hence the method name)
            refreshToken();
            if (accessToken == null || accessToken.isEmpty()) {
                log.error("Error while getting access token");
                return;
            }
            getClaimDialectID();
            if (dialectId == null || dialectId.isEmpty()) {
                log.error("Error while getting claim dialect ID");
                return;
            }
            // Add scim mapping for secretkey.
            if (!addScimMapping("urn:scim:wso2:schema:secretkey",
                    "http://wso2.org/claims/identity/secretkey")) {
                log.error("Error while adding scim mapping for secretkey");
                return;
            }
            log.info("Scim mapping for secretkey added...");
            // Add scim mapping for verifySecretkey.
            if (!addScimMapping("urn:scim:wso2:schema:verifySecretkey",
                    "http://wso2.org/claims/identity/verifySecretkey")) {
                log.error("Error while adding scim mapping for verifySecretkey");
                return;
            }
            log.info("Scim mapping for verifySecretkey added...");

            // iterate over the result set
            while (resultSet.next()) {

                String userName = resultSet.getString("USERNAME");
                String dataValue = resultSet.getString("TOTP_SECRET");

                log.info("--- USER Email: " + userName);

                // decode dataValue from base64
                byte[] decodedBytes = Base64.getDecoder().decode(dataValue);
                // convert decodedBytes to string
                CipherMetaDataHolder
                        cipherMetaDataHolder = cipherTextToCipherMetaDataHolder(decodedBytes);

                byte[] newDecrypted = decryptNewWay(cipherMetaDataHolder.getCipherBase64Decoded());
                String newDecryptedString = new String(newDecrypted);
                log.info("Key decryption was successful for user: " + userName);

                if (newDecryptedString == null || newDecryptedString.isEmpty()) {
                    log.error("Error while decrypting the secret key for user: " + userName);
                    continue;
                }

                // Send the second POST request with the access token
                String id = getUserId(userName);
                log.info("----| User ID: " + id);

                // Send the second PATCH request to update the user key in Asgardeo
                JSONObject patchResponse = patchUser(id, newDecryptedString);
                log.info("----| Final patch Response: " + patchResponse);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            log.info("Migration process completed.");
            // Delete scim mapping
            deleteScimMappings();
        }
    }

    /**
     * @return
     * @throws Exception
     */
    private static void refreshToken() throws Exception {

        try {

            URIBuilder builder = new URIBuilder(API_URL);
            HttpPost httpPost = new HttpPost(builder.build());

            // Set request headers
            httpPost.addHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());
            httpPost.addHeader(HttpHeaders.ACCEPT, "*/*");

            // Set Basic Authentication
            String credentials = Constants.USERNAME + ":" + PASSWORD;
            String authHeaderValue = "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes());
            httpPost.setHeader("Authorization", authHeaderValue);

            // Set request body
            String requestBody = "{\"grant_type\":\"client_credentials\", \"scope\":\"SYSTEM\"}";
            StringEntity requestEntity = new StringEntity(requestBody, ContentType.APPLICATION_JSON);
            httpPost.setEntity(requestEntity);

            try (CloseableHttpClient client = HttpClientBuilder.
                    create()
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build()) {

                CloseableHttpResponse response = client.execute(httpPost);
                // Get response code
                int responseCode = response.getStatusLine().getStatusCode();
                HttpEntity responseEntity = response.getEntity();
                String responseBody = EntityUtils.toString(responseEntity);

                // Create the JSON response object
                JSONObject jsonResponse = new JSONObject(responseBody);

                // Extract the access token
                accessToken = jsonResponse.getString("access_token");

                response.close();

            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Get claim id.
     */
    public static void getClaimDialectID() {

        try {
            URIBuilder builder = new URIBuilder(API_URL_CLAIM_DIALECT);
            HttpGet httpGet = new HttpGet(builder.build());

            // Set request headers
            httpGet.setHeader("Content-Type", "application/json");
            httpGet.setHeader("Authorization", "Bearer " + accessToken);
            httpGet.setHeader("Accept", "application/json");

            try (CloseableHttpClient client = HttpClientBuilder.
                    create()
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build()) {

                CloseableHttpResponse response = client.execute(httpGet);
                // Get response code
                int responseCode = response.getStatusLine().getStatusCode();

                if (responseCode == 401) {
                    log.info("Access token expired. Refreshing access token...");
                    refreshToken();
                    getClaimDialectID();
                    return;
                }

                if (responseCode == 200) {
                    HttpEntity responseEntity = response.getEntity();
                    String responseBody = EntityUtils.toString(responseEntity);

                    // Create the JSON response object
                    JSONArray jsonResponse = new JSONArray(responseBody);
                    for (int i = 0; i < jsonResponse.length(); i++) {
                        JSONObject jsonObject = jsonResponse.getJSONObject(i);

                        // Check if the dialectURI matches the target value
                        if ("urn:scim:wso2:schema".equals(jsonObject.getString("dialectURI"))) {
                            dialectId = jsonObject.getString("id");
                            log.info("Found matching dialectURI. id: " + dialectId);
                            break; // Stop iterating if the desired match is found
                        }
                    }
                } else {
                    log.error("Error in getting claim dialect id");
                }
                response.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean addScimMapping(String claimURI, String mappedLocalClaimURI) {

        try {
            URIBuilder builder = new URIBuilder(API_URL_CLAIM_DIALECT + "/" + dialectId + "/claims");
            HttpPost httpPost = new HttpPost(builder.build());

            // Set request headers
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setHeader("Authorization", "Bearer " + accessToken);
            httpPost.setHeader("Accept", "application/json");

            // Set request body
            String requestBody = "{" +
                    "  \"claimURI\": \"" + claimURI + "\"," +
                    "  \"mappedLocalClaimURI\": \"" + mappedLocalClaimURI + "\"" +
                    "}";
            StringEntity requestEntity = new StringEntity(requestBody, ContentType.APPLICATION_JSON);
            httpPost.setEntity(requestEntity);
            try (CloseableHttpClient client = HttpClientBuilder.
                    create()
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build()) {

                CloseableHttpResponse response = client.execute(httpPost);
                // Get response code
                int responseCode = response.getStatusLine().getStatusCode();

                if (responseCode == 401) {
                    log.info("Access token expired. Refreshing access token...");
                    refreshToken();
                    addScimMapping(claimURI, mappedLocalClaimURI);
                    return true;
                }
                if (responseCode == 201 || responseCode == 409) {
                    response.close();
                    return true;
                }
                response.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Delete the scim mappings.
     */
    public static void deleteScimMappings() {

        List<String> claimURIs =  new ArrayList<>(Arrays.asList(
                "urn:scim:wso2:schema:secretkey",
                "urn:scim:wso2:schema:verifySecretkey"
        ));

        JSONArray scimMappings = getScimMappings();
        for (int i = 0; i < scimMappings.length(); i++) {
            JSONObject jsonObject = scimMappings.getJSONObject(i);
            String claimURI = jsonObject.getString("claimURI");
            if (claimURIs.contains(claimURI)) {
                String id = jsonObject.getString("id");
                deleteScimMapping(id);
            }
        }
    }

    /**
     * Delete the scim mapping.
     * @param id    id of the scim mapping.
     */
    public static void deleteScimMapping(String id) {
        try {
            URIBuilder builder = new URIBuilder(API_URL_CLAIM_DIALECT +
                    "/" + dialectId + "/claims" + "/" + id);
            HttpDelete httpDelete = new HttpDelete(builder.build());

            // Set request headers
            httpDelete.setHeader("Content-Type", "application/json");
            httpDelete.setHeader("Authorization", "Bearer " + accessToken);
            httpDelete.setHeader("Accept", "application/json");
            try (CloseableHttpClient client = HttpClientBuilder.
                    create()
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build()) {

                CloseableHttpResponse response = client.execute(httpDelete);
                // Get response code
                int responseCode = response.getStatusLine().getStatusCode();
                if (responseCode == 401) {
                    log.info("Access token expired. Refreshing access token...");
                    refreshToken();
                    deleteScimMapping(id);
                    return;
                }
                if (responseCode == 204) {
                    log.info("Successfully deleted claim mapping with id: " + id);
                } else {
                    log.error("Error in deleting claim mapping with id: " + id);
                }
                response.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the scim mappings.
     * @return scim mappings.
     */
    public static JSONArray getScimMappings() {

        try {
            URIBuilder builder = new URIBuilder(API_URL_CLAIM_DIALECT + "/" + dialectId + "/claims");
            HttpGet httpGet = new HttpGet(builder.build());

            // Set request headers
            httpGet.setHeader("Content-Type", "application/json");
            httpGet.setHeader("Authorization", "Bearer " + accessToken);
            httpGet.setHeader("Accept", "application/json");

            try (CloseableHttpClient client = HttpClientBuilder.
                    create()
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build()) {

                CloseableHttpResponse response = client.execute(httpGet);
                // Get response code
                int responseCode = response.getStatusLine().getStatusCode();

                if (responseCode == 401) {
                    log.info("Access token expired. Refreshing access token...");
                    refreshToken();
                    return getScimMappings();
                }

                if (responseCode == 200) {
                    HttpEntity responseEntity = response.getEntity();
                    String responseBody = EntityUtils.toString(responseEntity);

                    // Create the JSON response object
                    JSONArray jsonResponse = new JSONArray(responseBody);
                    return jsonResponse;
                } else {
                    log.error("Error in getting claims for dialect id: " + dialectId);
                }
                response.close();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return new JSONArray();
    }

    public static CipherMetaDataHolder cipherTextToCipherMetaDataHolder(byte[] cipherText) {

        String cipherStr = new String(cipherText, Charset.defaultCharset());
        try {
            return gson.fromJson(cipherStr, CipherMetaDataHolder.class);
        } catch (JsonSyntaxException e) {

            return null;
        }
    }

    /**
     * @param userEmail
     * @return UserId
     * @throws Exception
     */
    private static String getUserId(String userEmail) throws Exception {
        String id = null;
        String[] parts = userEmail.split("/");
        String domain = parts[0];
        userEmail = parts[1];

        String count = "11";
        String excludedAttributes = "groups,roles";
        String filter = URLEncoder.encode("emails eq " + userEmail, "UTF-8");
        String startIndex = "0";

        String url = API_URL_USER_SEARCH + "?count=" + count + "&domain=" + domain + "&excludedAttributes=" +
                excludedAttributes + "&filter=" + filter + "&startIndex=" + startIndex;

        try {
            // Create an instance of CloseableHttpClient
            URIBuilder builder = new URIBuilder(url);

            // Create the POST request with the endpoint URL
            HttpGet httpGet = new HttpGet(builder.build());

            // Set request headers
            httpGet.setHeader("Content-Type", "application/scim+json");
            httpGet.setHeader("Authorization", "Bearer " + accessToken);
            httpGet.setHeader("Accept", "application/scim+json");

            try (CloseableHttpClient client = HttpClientBuilder.
                    create()
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build()) {

                CloseableHttpResponse response = client.execute(httpGet);
                // Get response code
                int responseCode = response.getStatusLine().getStatusCode();
                HttpEntity responseEntity = response.getEntity();
                String responseBody = EntityUtils.toString(responseEntity);

                // Check if unauthorized
                if (responseCode == 401) {
                    // Retry the request with refreshed credentials
                    refreshToken();
                    getUserId(userEmail);
                }

                // Create the JSON response object
                JSONObject jsonResponse = new JSONObject(responseBody);

                // Extract the value of the "id" field
                JSONArray resources = jsonResponse.optJSONArray("Resources");
                if (resources != null && resources.length() > 0) {
                    JSONObject resource = resources.getJSONObject(0);
                    id = resource.getString("id");
                }
                response.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return id;
    }

    /**
     * @param userId
     * @param userKey
     * @return Patch user response as JSON
     */
    private static JSONObject patchUser(String userId, String userKey){

        JSONObject jsonResponse = null;
        try {
            // Create an instance of CloseableHttpClient
            URIBuilder builder = new URIBuilder(API_URL_PATCH_USER + userId);

            // Create the PATCH request with the endpoint URL
            HttpPatch httpPatch = new HttpPatch(builder.build());

            // Set request headers
            httpPatch.setHeader("Content-Type", "application/scim+json");
            httpPatch.setHeader("Accept", "application/scim+json");
            httpPatch.setHeader("Authorization", "Bearer " + accessToken);
            // Add any other required headers

            // Set request body (if sending data in the request)
            String requestBody = "{\n" +
                    "    \"Operations\": [\n" +
                    "        {\n" +
                    "            \"op\": \"replace\",\n" +
                    "            \"value\": {\n" +
                    "                \"urn:scim:wso2:schema\": {\n" +
                    "                    \"secretkey\": \"" + userKey + "\",\n" +
                    "                    \"verifySecretkey\": \"" + userKey + "\",\n" +
                    "                    \"enabledAuthenticators\": \"totp\",\n" +
                    "                    \"totpEnabled\": true\n" +
                    "                }\n" +
                    "            }\n" +
                    "        }\n" +
                    "    ],\n" +
                    "    \"schemas\": [\n" +
                    "        \"urn:ietf:params:scim:api:messages:2.0:PatchOp\"\n" +
                    "    ]\n" +
                    "}";
            StringEntity requestEntity = new StringEntity(requestBody, ContentType.APPLICATION_JSON);
            httpPatch.setEntity(requestEntity);

            try (CloseableHttpClient client = HttpClientBuilder.
                    create()
                    .setSSLContext(new SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .build()) {

                CloseableHttpResponse response = client.execute(httpPatch);
                // Get response code
                int responseCode = response.getStatusLine().getStatusCode();

                if (responseCode == 401) {
                    log.info("Unauthorized. Refreshing access token.");
                    // Retry the request with refreshed credentials
                    refreshToken();
                    return patchUser(userId, userKey);
                }
                // Read response body
                HttpEntity responseEntity = response.getEntity();
                String responseBody = EntityUtils.toString(responseEntity);
                jsonResponse = new JSONObject(responseBody.toString());
                response.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return jsonResponse;
    }

    public static byte[] decryptNewWay(byte[] cipherText) {
        try {
            SecretKeySpec secretKeySpec = getSecretKey(SECRET);
            CipherMetaDataHolder cipherMetaDataHolder = getCipherMetaDataHolderFromCipherText(cipherText);

            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION, CIPHER_TRANSFORMATION_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec,
                    new GCMParameterSpec(GCM_TAG_LENGTH, cipherMetaDataHolder.getIvBase64Decoded()));
            return cipher.doFinal(cipherMetaDataHolder.getCipherBase64Decoded());


        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return new byte[0];
        }
    }

    private static CipherMetaDataHolder getCipherMetaDataHolderFromCipherText(byte[] cipherTextBytes) {

        CipherMetaDataHolder cipherMetaDataHolder = new CipherMetaDataHolder();
        cipherMetaDataHolder.setIvAndOriginalCipherText(cipherTextBytes);
        return cipherMetaDataHolder;
    }

    private static SecretKeySpec getSecretKey(String customSecretKey) {

        return new SecretKeySpec(customSecretKey.getBytes(), 0, customSecretKey.getBytes().length,
                DEFAULT_SYMMETRIC_CRYPTO_ALGORITHM);
    }
}
