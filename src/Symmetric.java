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
    private static byte[] do_AESEncryption(String text, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(createInitializationVector());
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        return cipher.doFinal(text.getBytes());
    }

    // this methode take CipherText and convert to plain text
    private static byte[] do_AESDecryption(byte[] cipherText, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(createInitializationVector());
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
