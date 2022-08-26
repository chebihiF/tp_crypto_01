import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Crypto {
    public static void main(String[] args) {

        String msg = "Hello World";
        try {
            hashText(msg);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static void hashText(String s) throws NoSuchAlgorithmException {
        MessageDigest digester = MessageDigest.getInstance("SHA3-512");
        byte[] input = s.getBytes();
        byte[] output = digester.digest(input);
        System.out.println("Input : "+s);
        System.out.println(hexString(output));
    }

    private static String hexString(byte[] output){
        StringBuilder builder = new StringBuilder();
        for(int i=0; i<output.length; i++){
            builder.append(Integer.toHexString(0xFF & output[i]));
        }
        return builder.toString();
    }



}
