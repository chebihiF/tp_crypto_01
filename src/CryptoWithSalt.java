import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class CryptoWithSalt {

    public static void main(String[] args) {
        try {
            byte[] salt = createSalt();
            String hello_world = "Hello World";
            String hash = createHash(hello_world,salt);
            System.out.println("Input : Hello world");
            System.out.println("Output : "+hash);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private static String createHash(String textToHash, byte[] salt) throws NoSuchAlgorithmException{
        //Create MessageDigest instance for SHA-512
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        //Add salted bytes to MessageDigest
        md.update(salt);
        byte[] output = md.digest(textToHash.getBytes());
        return hexString(output);
    }

    //Create Salt
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
