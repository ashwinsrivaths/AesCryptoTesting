import java.net.*;
import java.security.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import java.io.*;

public class GreetServer {

    /*
     * For generating a secret key, we can use the KeyGenerator class. Let’s define
     * a method for generating the AES key with the size of n (128, 192, and 256)
     * bits:
     */
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    /*
     * second way for generating hte secret key from password
     * 
     * 
     * In the second approach, the AES secret key can be derived from a given
     * password using a password-based key derivation function like PBKDF2. We also
     * need a salt value for turning a password into a secret key. The salt is also
     * a random value.
     * 
     * We can use the SecretKeyFactory class with the PBKDF2WithHmacSHA256 algorithm
     * for generating a key from a given password.
     * 
     * Let’s define a method for generating the AES key from a given password with
     * 65,536 iterations and a key length of 256 bits:
     */
    // public static SecretKey getKeyFromPassword(String password, String salt)
    // throws NoSuchAlgorithmException, InvalidKeySpecException {
    // SecretKeyFactory factory =
    // SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    // KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536,
    // 256);
    // SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
    // .getEncoded(), "AES");
    // return secret;
    // }

    /*
     * IV is a pseudo-random value and has the same size as the block that is
     * encrypted. We can use the SecureRandom class to generate a random IV.
     */
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String algorithm, String input, SecretKey key,
            IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key,
            IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    // create calculatePower() method to find the value of x ^ y mod P
    private static long calculatePower(long x, long y, long P) {
        long result = 0;
        if (y == 1) {
            return x;
        } else {
            result = ((long) Math.pow(x, y)) % P;
            return result;
        }
    }

    public static void main(String[] args) {

        // throws NoSuchAlgorithmException, InvalidKeyException,
        // NoSuchPaddingException, InvalidAlgorithmParameterException,
        // BadPaddingException, IllegalBlockSizeException {

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        // Diffie-Hellman Algorithm in Java

        try {
            long P, G, x, a, y, b, ka, kb;
            // create Scanner class object to take input from user
            // Scanner sc = new Scanner(System.in);
            // System.out.println("Both the users should be agreed upon the public keys G
            // and P");
            // // take inputs for public keys from the user
            // System.out.println("Enter value for public key G:");
            // G = sc.nextLong();
            // System.out.println("Enter value for public key P:");
            // P = sc.nextLong();
            // // get input from user for private keys a and b selected by User1 and User2
            // System.out.println("Enter value for private key a selected by user1:");
            // a = sc.nextLong();
            // System.out.println("Enter value for private key b selected by user2:");
            // b = sc.nextLong();

            G = 50;
            P = 60;
            a = 5;
            b = 6;
            // call calculatePower() method to generate x and y keys
            x = calculatePower(G, a, P);
            y = calculatePower(G, b, P);
            // call calculatePower() method to generate ka and kb secret keys after the
            // exchange of x and y keys
            // calculate secret key for User1
            ka = calculatePower(y, a, P);
            // calculate secret key for User2
            kb = calculatePower(x, b, P);
            // print secret keys of user1 and user2
            System.out.println("Secret key for User1 is:" + ka);
            System.out.println("Secret key for User2 is:" + kb);

        } catch (Exception e) {
            e.printStackTrace();
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        // RSA algorithm

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        // MyApplication stuff

        // MyApplication uses the AES algorithm in Galois/Counter Mode (GCM) for encrypting and
        // authenticating
        // MyApplication uses a key length of 128 bit as default
        // The usage of GCM results in a 128 bit long TAG which is appended in its
        // complete length to each message and used for authentication.

        // The CCSDS AOS Space Data Link Protocol / AOS Space Data Link Security
        // Protocol implementation: -
        // MyApplication uses AES/GCM as stipulated by CCSDS for securing encrypted channels.
        // Each channel uses a dedicated key.
        // The default key length is 128 bit, the appended TAG (MAC) has a length of 128
        // bit.
        // Each message increases the 96 bit long initialisation vector of GCM by one. -
        // iv
        // A key exchange has to be performed before this vector overflows.
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        // aes algorithm

        try {
            // aes algo first try... -> works well
            // SecretKey key;
            // key = generateKey(128);

            // IvParameterSpec ivParameterSpec = generateIv();
            // // todo; in the above code, the ivParameterSpec is random but I need to generate
            // // it based on the
            // // I am sending this with the the AOs Security header
            // // AES/GCM_Initialisation_Vector._Shall_be_constantly_increasing_and_never_repeating_during_the_usage_of_a_AES_Key.
            // // Initialisation_Vector uint48

            // String input = "asdfkjsdkfjhaksdfhklfdjsfdajksahkd long string";
            // // SecretKey key = AESUtil.generateKey(128);
            // // IvParameterSpec ivParameterSpec = AESUtil.generateIv();
            // String algorithm = "AES/CBC/PKCS5Padding";
            // String cipherText = encrypt(algorithm, input, key, ivParameterSpec);

            // String plainText = decrypt(algorithm, cipherText, key, ivParameterSpec);

            // System.err.println(plainText);

            ////////////////////////////////////////////////////////////
            ////////////////////////////////////////////////////////////
            ////////////////////////////////////////////////////////////
            ////////////////////////////////////////////////////////////aes algo second try... 

            int IV_SIZE = 128;
            byte IV[] = new byte[IV_SIZE];
            SecureRandom secRandom = new SecureRandom();
            secRandom.nextBytes(IV);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            byte[] aadTagData = "dynamicallyblunttech".getBytes();
            int GCM_TAG_LENGTH = 128;
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, IV);


            ///////////////////////////////////////////////////////////////
            


        } catch (Exception e) {
            e.printStackTrace();
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////

    }

    // public static void main(String[] args) throws IOException {
    // // Here, we create a Socket instance named socket
    // ServerSocket serverSocket = new ServerSocket(5001);
    // System.out.println("Listening for clients...");
    // Socket clientSocket = serverSocket.accept();
    // String clientSocketIP = clientSocket.getInetAddress().toString();
    // int clientSocketPort = clientSocket.getPort();
    // System.out.println(
    // "[IP: " + clientSocketIP + " ,Port: " + clientSocketPort + "] " + "Client
    // Connection Successful!");

    // /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // // System.out.println("[IP: " + clientSocketIP + " ,Port: " +
    // clientSocketPort
    // // +"] " + "Client Connection Successful!");

    // DataInputStream dataIn = new DataInputStream(clientSocket.getInputStream());
    // DataOutputStream dataOut = new
    // DataOutputStream(clientSocket.getOutputStream());

    // String clientMessage = dataIn.readUTF();
    // System.out.println(clientMessage);
    // String serverMessage = "Hi this is coming from Server!";
    // dataOut.writeUTF(serverMessage);

    // clientMessage = dataIn.readUTF();
    // System.out.println(clientMessage);

    // dataOut.writeUTF(serverMessage);

    // dataIn.close();
    // dataOut.close();
    // serverSocket.close();
    // clientSocket.close();
    // }

}