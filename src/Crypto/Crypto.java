/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.transform.TransformerException;
import mailapp.Data;
import org.bouncycastle.util.encoders.Base64;


public class Crypto {
    
    	public String Base64Encode(byte[] raw)
	{
		return new String (Base64.encode(raw));
	} 
    
        public byte[] Base64Decode(String raw)
	{
		return Base64.decode(raw.getBytes());
	}
        
        public void createkeyPair(String username) throws TransformerException {
        try {
            KeyPairGenerator kpg;
            //Create a 1024 bit RSA private key
            Data data = new Data();
            kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair kp = kpg.genKeyPair();
            Key publicKey = kp.getPublic();
            Key privateKey = kp.getPrivate();

            KeyFactory fact = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pub = (RSAPublicKeySpec) fact.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec priv = (RSAPrivateKeySpec) fact.getKeySpec(privateKey, RSAPrivateKeySpec.class);

            // Save the file to local drive
            String privateKeyPath = "/home/hoc/Desktop/key/" + username;
            String publicKeyPath = "/home/hoc/Desktop/key/" + username + ".pub";
            saveToFile(publicKeyPath, pub.getModulus(), pub.getPublicExponent());
            saveToFile(privateKeyPath, priv.getModulus(), priv.getPrivateExponent());
            data.insert(username,publicKeyPath,privateKeyPath);
            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException ex) {
            Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
        
        
        
        public void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException  {
        ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }
        
        
        public PrivateKey readpriKey(String keyFileName) throws IOException {
        ObjectInputStream oin
                = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyFileName)));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey priKey = fact.generatePrivate(keySpec);
            return priKey;
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
    
    public PublicKey readpubKey(String keyFileName) throws IOException {
        ObjectInputStream oin
                = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyFileName)));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m,e);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey pubKey = fact.generatePublic(keySpec);
            return pubKey;
        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
        
    private SecretKey generateAESKey(byte[] passphrase)
	{
		SecretKey key = null;
		try 
		{
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] password = md.digest(passphrase);
			key = new SecretKeySpec(password, "AES");
		} 
		catch (NoSuchAlgorithmException e) 
		{
			e.printStackTrace();
		} 

		return key;
	}
  
    private byte[] generateIV() {
        Random r = new SecureRandom();
        byte[] iv = new byte[16];
        r.nextBytes(iv);
        return iv;

    }

    private IvParameterSpec IVDecode(byte[] raw) {
        return new IvParameterSpec(raw);
    }
    
    
    public String rsaEncrypt(String publicKeyPath, String payload) {
                String ciphertext = null; 
                try {
                    PublicKey pubKey = readpubKey(publicKeyPath);
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
                    byte[] ciphertextRaw = cipher.doFinal(payload.getBytes());
                    ciphertext = Base64Encode(ciphertextRaw);
                    
                } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                }
                return ciphertext;
    }
    
    public String rsaDecrypt(String privateKeyPath, String payload) {
                String plaintext = null;
                try {
                    byte[] payloadRaw = Base64Decode(payload);
                    PrivateKey priKey = readpriKey(privateKeyPath);
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.DECRYPT_MODE, priKey);
                    byte[] plaintextRaw = cipher.doFinal(payloadRaw);
                    plaintext = new String (plaintextRaw);
                    
                } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                }
                return plaintext;
    }
    
    public String[] encrypt(String passphrase, String payload)
	{
		String[] messages = new String[2];
		byte[] aesKeyRaw = passphrase.getBytes();
		byte[] ivRaw = generateIV();
		SecretKey aesKey = generateAESKey(aesKeyRaw);
		IvParameterSpec iv = new IvParameterSpec(ivRaw);

		try 
		{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
			byte[] ciphertextRaw = cipher.doFinal(payload.getBytes());

			/* The first 16 bytes will be the IV */
			messages[0] = Base64Encode(ivRaw) + "::" + Base64Encode(aesKeyRaw);
			messages[1] = Base64Encode(ciphertextRaw);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) { 
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                } 
                return messages;
        }
    
    public void encryptFile(String secretKey,String file)
    {
        
                try {
                    String ivEncoded = secretKey.substring(0, secretKey.indexOf("::"));
                    String keyEncoded = secretKey.substring(secretKey.indexOf("::") + 2);
                    byte[] ivRaw = Base64Decode(ivEncoded);
                    byte[] keyRaw = Base64Decode(keyEncoded);
                    SecretKey aesKey = generateAESKey(keyRaw);
                    IvParameterSpec iv = IVDecode(ivRaw);


                    
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
                    
                    File inputFile = new File(file);
                    File outputFile = new File("/home/hoc/Desktop/encrypted");
                    FileInputStream inputStream = new FileInputStream(inputFile);
                    byte[] inputBytes = new byte[(int) inputFile.length()];
                    inputStream.read(inputBytes);
                    
                    
                    byte[] outputBytes = cipher.doFinal(inputBytes);
                    if(!outputFile.exists())
                        outputFile.createNewFile();
                    FileOutputStream outputStream = new FileOutputStream(outputFile,false);
                    outputStream.write(outputBytes);

                    inputStream.close();
                    outputStream.close();
             
          
                    
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                }
    }
    
    public String decrypt(String secretKey, String payload)
	{
		/* The first 16 bytes will be the IV */
		String ivEncoded = secretKey.substring(0, secretKey.indexOf("::"));
		String keyEncoded = secretKey.substring(secretKey.indexOf("::") + 2);
		byte[] ivRaw = Base64Decode(ivEncoded);
		byte[] keyRaw = Base64Decode(keyEncoded);
		SecretKey aesKey = generateAESKey(keyRaw);
		IvParameterSpec iv = IVDecode(ivRaw);

		try 
		{
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
			byte[] plaintext = cipher.doFinal(Base64Decode(payload));
			return new String(plaintext);
		} 
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) 
		{
			e.printStackTrace();
		}

		return null;
	
        }
    
    public void decryptFile(String secretKey,String file) {
                try {
                    /* The first 16 bytes will be the IV */
                    String ivEncoded = secretKey.substring(0, secretKey.indexOf("::"));
                    String keyEncoded = secretKey.substring(secretKey.indexOf("::") + 2);
                    byte[] ivRaw = Base64Decode(ivEncoded);
                    byte[] keyRaw = Base64Decode(keyEncoded);
                    SecretKey aesKey = generateAESKey(keyRaw);
                    IvParameterSpec iv = IVDecode(ivRaw);
                    
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
                    
                    File inputFile = new File(file);
                    File outputFile = new File(file);
                    FileInputStream inputStream = new FileInputStream(inputFile);
                    byte[] inputBytes = new byte[(int) inputFile.length()];
                    inputStream.read(inputBytes);
                    
                    byte[] outputBytes = cipher.doFinal(inputBytes);
                    
                    FileOutputStream outputStream = new FileOutputStream(outputFile, false);
                    outputStream.write(outputBytes);
                    
                    inputStream.close();
                    outputStream.close();
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                }

    }
    
    public String sign(String privateKeyPath, String payload)
    {
		String ciphertext = null;
		try 
		{
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] hash = md.digest(payload.getBytes());
                        PrivateKey priKey = readpriKey(privateKeyPath);
			/* Encrypt the hash using signer's private key */
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, priKey);
			byte[] ciphertextRaw = cipher.doFinal(hash);
			ciphertext = Base64Encode(ciphertextRaw);
		} 
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) 
		{
                    e.printStackTrace();
                } catch (IOException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                }

		return ciphertext;
    }
    
    public boolean authenticate(String publicKeyPath, String signature, String payload)
	{
		try 
		{
			/* Hash the payload */
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] hash = md.digest(payload.getBytes());
                        PublicKey pubKey = readpubKey(publicKeyPath);
			/* Decrypt the signature using the signer's public key */
			byte[] signatureRaw = Base64Decode(signature);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, pubKey);
			byte[] sign = cipher.doFinal(signatureRaw);

			/* Compare the hash with the signature */
			return Arrays.equals(hash, sign);
		} 
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) 
		{
			e.printStackTrace();
		} catch (IOException ex) {
                    Logger.getLogger(Crypto.class.getName()).log(Level.SEVERE, null, ex);
                }

		return false;
	}
    
}
