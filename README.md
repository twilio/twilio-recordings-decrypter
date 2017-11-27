# Twilio Recordings Decrypter

This program downloads a Twilio Video Track Recording file. The track is downloaded from the location pointed to by the 
`Media` resource from the Room Recordings REST API. Tracks are encrypted with an asymmetric key, so the you'll need to 
provide the private key from the pair that was used to encrypt the recording.


## Usage

The program requires the following arguments
* The location where the recording can be found. This is a pre-signed URL found in the `Media` REST resource from the Video Recordings REST API
    ```
    curl https://video.twilio.com/v1/Recordings/RTxx/Media   -u SKxxxx:API_SECRET  
    ```
* A text file containing the private key from the asymmetric pair used to encrypt the recording. This key must be 
encoded according to the PKCS#8 standard.If you have generated the keypair with `openssl`, it will be in PKCS#1 format.
In order to convert it to PKCS#8 format, you'll need to execute the following command 
    ```
    openssl pkcs8 -in privatekey.pem -topk8 -nocrypt -out privatekey-pkcs8.pem
    ```
* The location where you want the plain recording track to be downloaded.

1. Compile the project
    ```
    mvn clean package
    ```
2. Execute the jar file with the appropriate arguments
    ```
    java -jar target/twilio-recordings-decrypter.jar privatekey-pkcs8.pem "https://com-twilio...." decrypted_video_file.mkv
    ```