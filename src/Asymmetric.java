import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class Asymmetric {

    public static void main(String[] args) {
        try {
            KeyPair keyPair = generateRSAKeyPair();
            System.out.println("Public key : "+hexString(keyPair.getPublic().getEncoded()));
            System.out.println("Private key : "+hexString(keyPair.getPrivate().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] do_RSAEncryption(String plainText, PrivateKey privateKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,privateKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static byte[] do_RSADecryption(byte[] cipherText, PublicKey publicKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,publicKey);
        return cipher.doFinal(cipherText);
    }

    // Generating public and private keys using RSA algorithm
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    private static String hexString(byte[] output){
        StringBuilder builder = new StringBuilder();
        for(int i=0; i<output.length; i++){
            builder.append(Integer.toHexString(0xFF & output[i]));
        }
        return builder.toString();
    }
}
