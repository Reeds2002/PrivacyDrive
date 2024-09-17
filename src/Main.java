import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Scanner;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Main {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Get file paths from user
//        System.out.print("Enter the path of the file to encrypt: ");
//        String inputFilePath = scanner.nextLine();
//
//        System.out.print("Enter the path for the encrypted file: ");
//        String outputFilePath = scanner.nextLine();
//
        // Get password from user
        System.out.print("Enter a password for encryption: ");
        String password = scanner.nextLine();

        // Perform encryption
        try {
            File inputFile = new File("~/Documents/test.txt");
            File outputFile = new File("~/Documents/testOut.txt");
            String key = generateKeyFromPassword(password);

            encrypt(key, inputFile, outputFile);
            System.out.println("Encryption completed successfully.");
        } catch (Exception e) {
            System.err.println("Encryption failed: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    private static void encrypt(String key, File inputFile, File outputFile) throws Exception {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }

    private static void doCrypto(int cipherMode, String key, File inputFile, File outputFile) throws Exception {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, secretKey);

            try (FileInputStream inputStream = new FileInputStream(inputFile);
                 FileOutputStream outputStream = new FileOutputStream(outputFile)) {

                byte[] inputBytes = new byte[(int) inputFile.length()];
                inputStream.read(inputBytes);

                byte[] outputBytes = cipher.doFinal(inputBytes);

                outputStream.write(outputBytes);
            }
        } catch (Exception ex) {
            throw new Exception("Error encrypting/decrypting file", ex);
        }
    }

    private static String generateKeyFromPassword(String password) throws Exception {
        final int keyLength = 16;
        byte[] key = new byte[keyLength];
        System.arraycopy(password.getBytes(), 0, key, 0, Math.min(password.length(), keyLength));
        return new String(key);
    }
}
