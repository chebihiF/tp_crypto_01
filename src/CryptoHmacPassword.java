import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class CryptoHmacPassword {

    public static void main(String[] args) {
        try {
            String hello_word = "Hello World";
            System.out.println(generateStrongPasswordHash(hello_word));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateStrongPasswordHash(String password) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        int iterations=100 ;
        byte[] salt = createSalt();
        byte[] hash = createPBEHash(password, iterations, salt, 64);
        return hexString(salt)+":"+hexString(hash);
    }

    private static byte[] createPBEHash(String password, int iterations, byte[] salt, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations,
                keyLength * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return skf.generateSecret(spec).getEncoded();
    }

    private static byte[] createSalt() throws NoSuchAlgorithmException, NoSuchProviderException {
        //use a SecureRandom generator for random salt
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG","SUN");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

    private static String hexString(byte[] output){
        StringBuilder builder = new StringBuilder();
        for(int i=0; i<output.length; i++){
            builder.append(Integer.toHexString(0xFF & output[i]));
        }
        return builder.toString();
    }

}
