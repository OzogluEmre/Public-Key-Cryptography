import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;

public class main {
	
	public static String user_name;
	public static String serial_no;
	public static String MAC;
	public static String Disk_serial_no="standard"; //MotherboardID is not accessible and Disk Serial Number has different code structures with MacOS and Windows
	public static String Mother_board="Standard";
	public static String plain_text;
	
	public static void getMacAddress(){
	    InetAddress ip;
	    StringBuilder sb = new StringBuilder();
	    try {
	        ip = InetAddress.getLocalHost();
	        NetworkInterface network = NetworkInterface.getByInetAddress(ip);
	        byte[] mac = network.getHardwareAddress();
	        
	        for (int i = 0; i < mac.length; i++) {
	            sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));        
	        }
	        
	    } catch (UnknownHostException e) {
	        e.printStackTrace();
	    } catch (SocketException e){
	        e.printStackTrace();
	    }
	    MAC= sb.toString();
	}
	
	public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
	    Cipher encryptCipher = Cipher.getInstance("RSA");
	    encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

	    byte[] cipherText = encryptCipher.doFinal(plainText.getBytes());
	    
	    return Base64.getEncoder().encodeToString(cipherText);
	}
	public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
	    byte[] bytes = Base64.getDecoder().decode(cipherText);

	    Cipher decriptCipher = Cipher.getInstance("RSA");
	    decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

	    return new String(decriptCipher.doFinal(bytes));
	}//000000000000000000000000000000000000000000000000
	public static String getMd5(String input) 
    { 
        try { 
  
            // Static getInstance method is called with hashing MD5 
            MessageDigest md = MessageDigest.getInstance("MD5"); 
  
            // digest() method is called to calculate message digest 
            //  of an input digest() return array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
            return hashtext; 
        }  
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 
	
	
	//*************************************
	
	public static void gather_plain(File tempfile) throws IOException {
		
		FileReader fr = new FileReader(tempfile);
		BufferedReader br = new BufferedReader(fr);
		
		user_name=br.readLine();
		serial_no=br.readLine();

		getMacAddress();
		
        plain_text = user_name + "$" + serial_no + "$" + MAC + "$" +Disk_serial_no + "$" +Mother_board;

	}
	public static String license_check(File tempfile) throws IOException {
		BufferedReader br = new BufferedReader(new FileReader(tempfile));
	    try {
	        StringBuilder sb = new StringBuilder();
	        String line = br.readLine();

	        while (line != null) {
	            sb.append(line);
	            sb.append("\n");
	            line = br.readLine();
	        }
	        sb.deleteCharAt(sb.length()-1);
	        return sb.toString();
	    } finally {
	        br.close();
	    }
		
		
	}
	

// args[0] for private.key 
// args[1] for public.key
// args[2] for user_serial.txt
	public static void main(String[] args) throws Exception {
		
		licensemanager keyz=new licensemanager();
		File plain = new File(args[2]);
		gather_plain(plain);
		
	    byte[] bytes = Base64.getDecoder().decode(encrypt(plain_text, keyz.get_pub(args[1])).getBytes());
	    String encr = new String(bytes, StandardCharsets.UTF_8);  // byte array to string
	    byte[] bytezz = Base64.getDecoder().decode(keyz.sign(plain_text, keyz.get_priv(args[0])).getBytes());
	    String sign = new String(bytezz, StandardCharsets.UTF_8);  // byte array to string     
        File tempFile = new File("license.txt");
        boolean license_exists = tempFile.exists();
        FileOutputStream out ;
        
        
       if(!(license_exists)) {
  
            System.out.println("Client started...");
            System.out.println("My MAC: "+MAC);
            System.out.println("My DiskID: "+Disk_serial_no);
            System.out.println("My Motherboard ID: "+Mother_board);
            System.out.println("LicenseManager service started...");
            System.out.println("Client -- Raw License Text: "+plain_text);
            System.out.println("Client -- Encrypted License Text: "+encr);
            System.out.println("Client -- MD5fied Plain License Text: "+getMd5(plain_text));
            System.out.println("Server -- Server is being requested...");
            System.out.println("Server -- Incoming Encrpyted Text: "+encr);
            System.out.println("Server -- Decrypted Text: "+decrypt(encrypt(plain_text, keyz.get_pub(args[1])), keyz.get_priv(args[0])));
            System.out.println("Server -- MD5fied Plain License Text: "+getMd5(plain_text));
            System.out.println("Server -- Digital Signature: "+sign);
            
            keyz.verify(plain_text, keyz.sign(plain_text, keyz.get_priv(args[0])), keyz.get_pub(args[1]));
            
            if(keyz.verify(plain_text, keyz.sign(plain_text, keyz.get_priv(args[0])), keyz.get_pub(args[1]))==true) {
            		System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
            		out = new FileOutputStream("license.txt"); 		 
            		out.write(sign.getBytes());
            		out.close();
            		license_check(tempFile);
            		
            }
        }
       else if(Arrays.equals(sign.getBytes(StandardCharsets.ISO_8859_1),Files.readAllBytes(Paths.get("license.txt"))))  // if the computed machines is MacOS ;Change StandardCharsets.ISO_8859_1 with UTF-8 
       {
           System.out.println("Succeed. The license is correct.");
           
       }
        else if(!(sign.equals((license_check(tempFile))))) {
        	    System.out.println("The license file has been broken!!");
        	    System.out.println("Client started...");
            System.out.println("My MAC: "+MAC);
            System.out.println("My DiskID: "+Disk_serial_no);
            System.out.println("My Motherboard ID: "+Mother_board);
            System.out.println("LicenseManager service started...");
            System.out.println("Client -- Raw License Text: "+plain_text);
            System.out.println("Client -- Encrypted License Text: "+encr);
            System.out.println("Client -- MD5fied Plain License Text: "+getMd5(plain_text));
            System.out.println("Server -- Server is being requested...");
            System.out.println("Server -- Incoming Encrpyted Text: "+encr);
            System.out.println("Server -- Decrypted Text: "+decrypt(encrypt(plain_text, keyz.get_pub(args[1])), keyz.get_priv(args[0])));
            System.out.println("Server -- MD5fied Plain License Text: "+getMd5(plain_text));
            System.out.println("Server -- Digital Signature: "+sign);
            
            keyz.verify(plain_text, keyz.sign(plain_text, keyz.get_priv(args[0])), keyz.get_pub(args[1]));
            
            if(keyz.verify(plain_text, keyz.sign(plain_text, keyz.get_priv(args[0])), keyz.get_pub(args[1]))==true) {
            		System.out.println("Client -- Succeed. The license file content is secured and signed by the server.");
            		out = new FileOutputStream("license.txt"); 		 
            		out.write(sign.getBytes());
            		out.close();
            		license_check(tempFile);
            		
            }
        	    
        }
      
        
	    	}
	}
	


