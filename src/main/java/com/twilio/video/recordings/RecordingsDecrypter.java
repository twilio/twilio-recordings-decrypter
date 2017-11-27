package com.twilio.video.recordings;

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

public class RecordingsDecrypter {

    private static final Pattern newlinePatternTabsAndSpaces = Pattern.compile("\r\n|\r|\n|\t|\\s");
    private static final Pattern keyPattern = Pattern.compile("-----[BEGIN|END]([A-Z ]+) KEY-----");


    public static PrivateKey loadPrivateKey(final String key) throws NoSuchAlgorithmException, InvalidKeySpecException {

        String sanitized = keyPattern.matcher(key).replaceAll("");
        sanitized = newlinePatternTabsAndSpaces.matcher(sanitized).replaceAll("");

        final byte[] keyBytes = Base64.getDecoder().decode(sanitized);
        final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private static void printHelp() {
        System.out.println(
                "This program downloads an encrypted Twilio Video Recording pre-signed URL, downloads the recording " +
                        "file, and decrypts it in your box.");
        System.out.println("\nSample usage\n" +
                "java -jar twilio-recordings-decrypter.jar ./privateKeyPkcs8.pem " +
                "\"https://com-twilio-us1-video-recording.s3.amazonaws.com/ACxx...\" ./decrypted_video.mkv");
        System.out.println("You need to pass three arguments to the program\n" +
                "\t ./privateKeyPkcs8.pem: This is the path to a text file containing your PKCS8-formatted private " +
                "key.\n" +
                "\t\"https://com-twilio-us1-video-recording.s3.amazonaws.com/ACxx...\": A pre-signed URL obtained " +
                "from the video.twilio.com/v1Recordings/RTxxx/Media " +
                "resource\n" +
                "\t./decrypted_video.mkv: Path to local destination");
    }

    public static void main(final String... args) {

        if (args.length != 3) {
            printHelp();
        }

        final String privateKeyStr;
        try {
            privateKeyStr = new String(Files.readAllBytes(Paths.get(args[0])));
        } catch (IOException e) {
            System.out.println("The file " + args[0] +
                    " containing the private key could not be read. Program will exit now");
            return;
        }

        final PrivateKey privateKey;

        try {
            privateKey = loadPrivateKey(privateKeyStr);
        } catch (final IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("The file " + args[0] + " contains a private key that can't be parsed. " +
                    "Check that the file contains a PKCS8 formatted key. Program will exit now.");
            return;
        }

        final URL presignedUrl;
        try {
            presignedUrl = new URL(args[1]);
        } catch (MalformedURLException e) {
            System.out.println("The URL " + args[1] +
                    " is not a valid URL. Program will exit now.");
            return;
        }

        final Path destinationFile = Paths.get(args[2]);

        try {
            decryptFile(presignedUrl, privateKey, destinationFile);
        } catch (IOException e) {
            System.out.println("There was an error decrypting the file in your local system. Program will exit now.");
            return;
        } catch (GeneralSecurityException e) {
            System.out.println(
                    "There was an error creating the cryptographic material to decrypt the file. Please check that " +
                            "the private key is in PKCS#8 format, and that the public key used to encrypt the file is" +
                            " derived from this private key. Program will exit now.");
            return;
        }
    }

    private static void decryptFile(final URL recordingUrl,
                                    final PrivateKey privateKey,
                                    final Path destination) throws GeneralSecurityException, IOException {

        final HttpURLConnection conn;
        try {
            conn = (HttpURLConnection) recordingUrl.openConnection();
        } catch (IOException e) {
            System.out.println("Error occurred while trying to connect to " + recordingUrl + ". Program will exit now");
            return;
        }


        if (conn.getResponseCode() == 403) {
            System.out.println(
                    "The pre-signed URL TTL has expired. Please obtain a new URL from the Video Recordings Service. " +
                            "Program will exit now.");
            return;
        } else if (conn.getResponseCode() != 302) {
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
        cipher.init(DECRYPT_MODE, cek, new IvParameterSpec(iv));
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
