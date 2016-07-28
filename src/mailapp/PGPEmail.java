package mailapp;

import Crypto.Crypto;
import javax.mail.Message;
import javax.xml.transform.TransformerException;



/**
 * This class represents a PGP email. It's a wrapper of javax.mail.Message
 * @author mdandy
 */
public class PGPEmail
{
	/* PGP email protocol:
	 * PGP combines symmetric-key encryption and public-key encryption. 
	 * The message is encrypted using a symmetric encryption algorithm, 
	 * which requires a symmetric key. Each symmetric key is used only 
	 * once and is also called a session key. The session key is 
	 * protected by encrypting it with the receiver's public key thus 
	 * ensuring that only the receiver can decrypt the session key. The 
	 * encrypted message along with the encrypted session key is sent 
	 * to the receiver. 
	 */

	private final static String BEGIN_EMAIL = "-----BEGIN PGP EMAIL-----";
	private final static String END_EMAIL = "-----END PGP EMAIL-----";
	private final static String BEGIN_KEY = "\n-----BEGIN PGP KEY-----\n";
	private final static String END_KEY = "\n-----END PGP KEY-----\n";
	private final static String BEGIN_MESSAGE = "\n-----BEGIN PGP SIGNED MESSAGE-----\n";
	private final static String END_MESSAGE = "\n-----END PGP SIGNED MESSAGE-----\n";
	private final static String BEGIN_SIGNATURE = "\n-----BEGIN PGP SIGNATURE-----\n";
	private final static String END_SIGNATURE = "\n-----END PGP SIGNATURE-----\n";

	
	public String payload;
	public Message message;
	public boolean isAunthentic;
	
	/**
	 * An enumeration of email type
	 * @author mdandy
	 */
	public enum Type
	{
		NEW,
		REPLY,
		FORWARD
	}

	public void setMessage(Message message)
	{
		this.message = message;
	}

	
	
	/**
	 * Encrypt email content.
	 * @param content the email content
	 * @return the encrypted email content
	 * @throws PGPEmailException 
	 */
	public String[] encryptContent(String payload,String username,String passphrase,String to) throws TransformerException
	{
		String[] result = new String[2];
                result[1] = "";
                 Data data = new Data();
	
		/* Encrypt the message */
		Crypto ce = new Crypto();
		String[] cipher = ce.encrypt(passphrase, payload);
		
		/* Encrypt the key */
		String publicKeyPath = data.getPublicKey(to);
                
                if(publicKeyPath.equals(""))
                {
                    Crypto crypto = new Crypto();
                    ce.createkeyPair(to);
                    data.taiFile();
                    publicKeyPath = data.getPublicKey(to);
                }
                
		String cipherKey = ce.rsaEncrypt(publicKeyPath, cipher[0]);

		/* Sign the message */
		String privateKeyPath = data.getPrivateKey(username);

		String signature = ce.sign(privateKeyPath, payload);
		
		result[1] = PGPEmail.BEGIN_EMAIL;

		result[1] += PGPEmail.BEGIN_KEY;
		result[1] += cipherKey;
		result[1] += PGPEmail.END_KEY;

		result[1] += PGPEmail.BEGIN_MESSAGE;
		result[1] += cipher[1];
		result[1] += PGPEmail.END_MESSAGE;

		result[1] += PGPEmail.BEGIN_SIGNATURE;
		result[1] += signature;
		result[1] += PGPEmail.END_SIGNATURE;

		result[1] += PGPEmail.END_EMAIL;
		result[0] = cipher[0];
		return result;
	}

	/**
	 * Parse an email to PGP email.
	 * @param message the email to be parsed
	 * @return true on successful or false otherwise
	 */
	   public String[] decryptContent(String mBody, String username,String mFrom) {
               String[] resutl = new String[2];
        /* Extract the payload */
        mBody = mBody.replace("\r", "");
        String key = mBody.substring(mBody.indexOf(PGPEmail.BEGIN_KEY) + PGPEmail.BEGIN_KEY.length(),
                mBody.indexOf(PGPEmail.END_KEY));
        String payload = mBody.substring(mBody.indexOf(PGPEmail.BEGIN_MESSAGE) + PGPEmail.BEGIN_MESSAGE.length(),
                mBody.indexOf(PGPEmail.END_MESSAGE));
        String signature = mBody.substring(mBody.indexOf(PGPEmail.BEGIN_SIGNATURE) + PGPEmail.BEGIN_SIGNATURE.length(),
                mBody.indexOf(PGPEmail.END_SIGNATURE));

        Crypto ce = new Crypto();
        Data data = new Data();
        /* Decrypt the key */
        String privateKeyPath = data.getPrivateKey(username);

        String plainKey = ce.rsaDecrypt(privateKeyPath, key);

        /* Decrypt the payload */
        payload = ce.decrypt(plainKey, payload);   
        
        resutl[0] = payload;
        resutl[1] = plainKey;
        return resutl;
    }
           
      public boolean Authentication(String mBody, String username,String mFrom) {

        /* Extract the payload */
        mBody = mBody.replace("\r", "");
        String key = mBody.substring(mBody.indexOf(PGPEmail.BEGIN_KEY) + PGPEmail.BEGIN_KEY.length(),
                mBody.indexOf(PGPEmail.END_KEY));
        String payload = mBody.substring(mBody.indexOf(PGPEmail.BEGIN_MESSAGE) + PGPEmail.BEGIN_MESSAGE.length(),
                mBody.indexOf(PGPEmail.END_MESSAGE));
        String signature = mBody.substring(mBody.indexOf(PGPEmail.BEGIN_SIGNATURE) + PGPEmail.BEGIN_SIGNATURE.length(),
                mBody.indexOf(PGPEmail.END_SIGNATURE));

        Crypto ce = new Crypto();
        Data data = new Data();
        /* Decrypt the key */
        String privateKeyPath = data.getPrivateKey(username);

        String plainKey = ce.rsaDecrypt(privateKeyPath, key);

        /* Decrypt the payload */
        payload = ce.decrypt(plainKey, payload);

        /* Retrieve Public Key */
        String publicKeyPath = data.getPublicKey(mFrom);
        
        return ce.authenticate(publicKeyPath, signature, payload);
        
    }
      
   
}
