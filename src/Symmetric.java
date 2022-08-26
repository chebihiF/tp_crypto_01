import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Symmetric {

    public static void main(String[] args) {
        try {
            SecretKey key = createAESKey();
            System.out.println("The symmetric key : "+ hexString(key.getEncoded()));
            byte[] initializationVector = createInitializationVector();
            String plainText = "this is the message i want to Encrypt";
            try {
                System.out.println("Message : "+plainText);
                System.out.println("Encrypting in progress ...");
                byte[] cipherText = do_AESEncryption(plainText,key,initializationVector);
                System.out.println("Result : "+hexString(cipherText));

                System.out.println("Decrypting in progress ...");
                byte[] plainTextBytes = do_AESDecryption(cipherText,key,initializationVector);
                plainText = new String(plainTextBytes);
                System.out.println("Message : "+ plainText);

                initializationVector = createInitializationVector();
                cipherText = do_AESEncryption(plainText,key,initializationVector);
                System.out.println("Result : "+hexString(cipherText));
                System.out.println("Decrypting in progress ...");
                plainTextBytes = do_AESDecryption(cipherText,key,initializationVector);
                plainText = new String(plainTextBytes);
                System.out.println("Message : "+ plainText);



            } catch (NoSuchPaddingException e) {
                throw new RuntimeException(e);
            } catch (InvalidAlgorithmParameterException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (IllegalBlockSizeException e) {
                throw new RuntimeException(e);
            } catch (BadPaddingException e) {
                throw new RuntimeException(e);
            }

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] createInitializationVector(){
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    // this methode take a plain text and encrypt it to CipherText
    private static byte[] do_AESEncryption(String text, SecretKey key, byte[] initializationVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(text.getBytes());
    }

    // this methode take CipherText and convert to plain text
    private static byte[] do_AESDecryption(byte[] cipherText, SecretKey key, byte[] initializationVector) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(cipherText);
    }

    private static SecretKey createAESKey() throws NoSuchAlgorithmException {
        //Creating a new instance of SecureRandom
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        return key ;
    }

    private static String hexString(byte[] output){
        StringBuilder builder = new StringBuilder();
        for(int i=0; i<output.length; i++){
            builder.append(Integer.toHexString(0xFF & output[i]));
        }
        return builder.toString();
    }

}
