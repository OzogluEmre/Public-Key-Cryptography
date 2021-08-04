import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class licensemanager {
	private Cipher cipher;
	public static String encryptSign;
	
	public void RSA() throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.setCipher(Cipher.getInstance("RSA"));
	}
	
	public static PrivateKey get_priv(String filename)
			  throws Exception {//made private so Client can't access the private key

			    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

			    PKCS8EncodedKeySpec spec =new PKCS8EncodedKeySpec(keyBytes);
			    KeyFactory kf = KeyFactory.getInstance("RSA");
			    return kf.generatePrivate(spec);
			  }
	
	 public static PublicKey get_pub(String filename)
			    throws Exception {//Made public so Client can access the public key

			    byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

			    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			    KeyFactory kf = KeyFactory.getInstance("RSA");
			    return kf.generatePublic(spec);
			  }
	
	 public static String sign(String plainText, PrivateKey privateKey) throws Exception {
	        Signature privateSignature = Signature.getInstance("SHA256WithRSA");
	        privateSignature.initSign(privateKey);
	        privateSignature.update(plainText.getBytes("UTF-8"));

	        byte[] signature = privateSignature.sign();
	        return Base64.getEncoder().encodeToString(signature);
	    }
	 
	

	    public static boolean verify(String plainText, String signature, PublicKey publicKey) {
	    		try {

	    	        Signature publicSignature = Signature.getInstance("SHA256WithRSA");
	    	        publicSignature.initVerify(publicKey);
	    	        publicSignature.update(plainText.getBytes("UTF-8"));
	    	       
	    	        byte[] signatureBytes = Base64.getDecoder().decode(signature);
	    	        return publicSignature.verify(signatureBytes);
	    		}
	    		catch(Exception e) {
	    			
	    			return false;
	    		}
	        
	    }

		public Cipher getCipher() {
			return cipher;
		}

		public void setCipher(Cipher cipher) {
			this.cipher = cipher;
		}
	
	


}
