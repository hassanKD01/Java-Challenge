package javachallenge;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.Cipher;


public class RSAUtils {
    private static final String RSA = "RSA";
    
    public static KeyPair generateRSAKkeyPair()throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
 
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }
    
    public static byte[] Encrypt(byte[]  plainText,PublicKey publicKey)throws Exception
    {
        Cipher cipher = Cipher.getInstance(RSA);
 
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
 
        return cipher.doFinal(plainText);
    }
    
    public static String decrypt(byte[] cipherText,PrivateKey privateKey) throws Exception
    {
        Cipher cipher = Cipher.getInstance(RSA);
 
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] result = cipher.doFinal(cipherText);
 
        return new String(result);
    }
    
    public static byte[] generateSignature(PrivateKey privateKey, byte[] plainText) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        Signature sig = Signature.getInstance("SHA1WithRSA");
        sig.initSign(privateKey);
        sig.update(plainText);
        byte[] signatureBytes = sig.sign();
        return signatureBytes;
    }
    
    public static boolean verifySignature(byte[] sentSignature, PublicKey publicKey, String decryptedText) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
        Signature sig = Signature.getInstance("SHA1WithRSA");
        sig.initVerify(publicKey);
        sig.update(decryptedText.getBytes());

        return sig.verify(sentSignature);
    }
}
