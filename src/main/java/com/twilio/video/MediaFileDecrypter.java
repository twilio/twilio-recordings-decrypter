package com.twilio.video;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.twilio.Twilio;
import com.twilio.http.HttpMethod;
import com.twilio.http.NetworkHttpClient;
import com.twilio.http.Request;
import com.twilio.http.Response;
import com.twilio.http.TwilioRestClient;
import com.twilio.rest.Domains;

import org.apache.http.impl.client.HttpClientBuilder;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static javax.crypto.Cipher.DECRYPT_MODE;

public class MediaFileDecrypter {

    private static final Pattern newlinePatternTabsAndSpaces = Pattern.compile("\r\n|\r|\n|\t|\\s");
    private static final Pattern keyPattern = Pattern.compile("-----[BEGIN|END]([A-Z ]+) KEY-----");

    //Load PKCS #8 private key from the specified filename and returns it as a PrivateKey object.
    public static PrivateKey loadPrivateKey(final String key) throws NoSuchAlgorithmException, InvalidKeySpecException {

        //Remove header and footer of file
        String sanitized = keyPattern.matcher(key).replaceAll("");
        sanitized = newlinePatternTabsAndSpaces.matcher(sanitized).replaceAll("");

        final byte[] keyBytes = Base64.getDecoder().decode(sanitized);
        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    //Print usage instructions
    private static void printHelp() {
        System.out.println(
                "This program downloads and decrypts an encrypted Twilio Video Recording or Composition");
        System.out.println("\nUsage:\n" +
                "java -jar twilio-media-decrypter.jar ./privateKeyPkcs8.pem API_KEY:API_SECRET SidToDecrypt " +
                "./decrypted_video.mkv");
        System.out.println("Where:\n" +
                "\t./privateKeyPkcs8.pem is the path to a file containing your PKCS8-formatted private " +
                "key.\n" +
                "\tAPI_KEY:API_SECRET: Twilio's API key and secret for your account\n" +
                "\tSidToDecrypt: the Recording or Composition SID you want to download and decrypt\n" +
                "\t./decrypted_video.mkv: Path to local destination");
    }

    public static void main(final String... args) {

        if (args.length != 4) {
            printHelp();
            return;
        }

        //Obtain path to the file containing the private key
        final String privateKeyStr;
        try {
            privateKeyStr = new String(Files.readAllBytes(Paths.get(args[2])));
        } catch (final IOException e) {
            System.out.println("The file " + args[2] +
                    " containing the private key could not be read. Program will exit now");
            return;
        }

        //Load private key form file
        final PrivateKey privateKey;
        try {
            privateKey = loadPrivateKey(privateKeyStr);
        } catch (final IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("The file " + args[2] + " contains a private key that can't be parsed. " +
                    "Check that the file contains a PKCS8 formatted key. Program will exit now.");
            return;
        }

        System.out.println("Private key loaded successfully ...");

        //Obtain Twilio's API key and secret from command line args.
        String[] credentials = args[0].split(":");
        final String apiKeySid = credentials[0];
        final String apiKeySecret = credentials[1];
        //Obtain recording / composition SID from command line args.
        final String mediaFileSid = args[1];
        final URL presignedUrl;

        //Obtain presignedUrl where the encrypted media can be downloaded
        try {
            presignedUrl = getMediaUrl(mediaFileSid, apiKeySid, apiKeySecret);
        } catch (final Exception e) {
            return;
        }

        System.out.println("Presigned media URL obtained successfully ...");

        //Prepare destination file and decrypt
        final Path destinationFile = Paths.get(args[3]);

        System.out.println("Starting media decryption ...");
        try {
            decryptFile(presignedUrl, privateKey, destinationFile);
        } catch (IOException e) {
            System.out.println("There was an error decrypting the file in your local system. Program will exit now.");
            return;
        } catch (final GeneralSecurityException e) {
            System.out.println(
                    "There was an error creating the cryptographic material to decrypt the file. Please check that " +
                            "the private key is in PKCS#8 format, and that the public key used to encrypt the file is" +
                            " derived from this private key. Program will exit now.");
            return;
        }

        System.out.println("Media decryption completed successfully.");
    }

    //Obtains the presignedUrl associated to a given Recording / Composition SID
    private static URL getMediaUrl(final String mediaFileSid, final String apiKeySid,
                                   final String apiKeySecret) throws IOException {
        final NetworkHttpClient networkHttpClient =
                new NetworkHttpClient(
                        HttpClientBuilder
                                .create()
                                .disableRedirectHandling()
                                .useSystemProperties());
        final TwilioRestClient restClient =
                new TwilioRestClient
                        .Builder(apiKeySid, apiKeySecret)
                        .httpClient(networkHttpClient)
                        .build();

        Twilio.setRestClient(restClient);
        
        String pathSection;
        if(mediaFileSid.startsWith("RT")){
        	pathSection="/Recordings/";
        } else if (mediaFileSid.startsWith("CJ")){
        	pathSection="/Compositions/";
        } else {
        	throw new RuntimeException("The provided SidToDecrypt is neither a RecordingSid nor a CompositionSid");
        }
        
        final Request request = new Request(
                HttpMethod.GET,
                Domains.VIDEO.toString(),
                "/v1" + pathSection + mediaFileSid + "/Media/",
                restClient.getRegion());
        final Response response = restClient.request(request);

        if (response.getStatusCode() == 302) {
            final ObjectNode node;
            try {
                node = new ObjectMapper().readValue(response.getStream(), ObjectNode.class);
            } catch (final IOException e) {
                System.out.println("Error reading response from server");
                throw e;
            }

            final String presignedUrlStr = String.valueOf(node.get("redirect_to").asText());
            final URL presignedUrl;
            try {
                presignedUrl = new URL(presignedUrlStr);
            } catch (final IllegalArgumentException | NullPointerException | MalformedURLException e) {
                System.out.println("The URL " + presignedUrlStr + " is not a valid URL. Program will exit now.");
                return null;
            }

            return presignedUrl;
        } else {
            System.out.println("The server responded with " + response.getStatusCode() +
                    " code. Media file will not be downloaded.\n" + response.getContent());
            return null;
        }
    }

    //Decrypts the file downloaded from mediaFileUrl using privateKey to decrypt the envelope
    private static void decryptFile(final URL mediaFileUrl,
                                    final PrivateKey privateKey,
                                    final Path destination) throws GeneralSecurityException, IOException {

        final HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) mediaFileUrl.openConnection();
        } catch (final IOException e) {
            System.out.println("Error occurred while trying to connect to " + mediaFileUrl + ". Program will exit now");
            return;
        }


        if (conn.getResponseCode() == 403) {
            System.out.println(
                    "The pre-signed URL TTL has expired. Please obtain a new URL from the Video Recordings/Compositions Service. " +
                            "Program will exit now.");
            return;
        } else if (conn.getResponseCode() != 200) {
            System.out.println(
                    "The response code " + conn.getResponseCode() +
                            " from the server is not valid (should be 302). Program will exit now.");
            return;
        }

        // AWS stores the key and the initialization vector as metadata that we nee to retrieve from the request. The
        // key is encrypted with the public_key that the user provided.
        final byte[] cekWrapped = Base64.getDecoder().decode(conn.getHeaderField("x-amz-meta-x-amz-key").getBytes());
        final byte[] iv = Base64.getDecoder().decode(conn.getHeaderField("x-amz-meta-x-amz-iv").getBytes());
        // Now we need to decrypt the envelope
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm());
        cipher.init(DECRYPT_MODE, privateKey);
        final byte[] decryptedSymmetricKeyBytes = cipher.doFinal(cekWrapped);
        final SecretKeySpec cek = new SecretKeySpec(decryptedSymmetricKeyBytes, "AES");

        // Once we have the symmetric master key, we can decrypt the contents
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        try {
            cipher.init(DECRYPT_MODE, cek, new IvParameterSpec(iv));
        } catch (final InvalidKeyException e) {
            System.out.println(
                    "Invalid key exception. Please make sure that Java Cryptography Extensions with unlimited " +
                            "jurisdiction are installed");
        }
        try (final InputStream in = conn.getInputStream()) {
            try (final CipherInputStream cis = new CipherInputStream(in, cipher)) {
                try (final FileOutputStream fos = new FileOutputStream(destination.toFile())) {
                    byte[] b = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = cis.read(b)) >= 0) {
                        fos.write(b, 0, bytesRead);
                    }
                }
            }
        } finally {
            conn.disconnect();
        }
    }
}
