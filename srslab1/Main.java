//package srslab1;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	public static void main(String[] args) throws IOException {
		BufferedReader reader = new BufferedReader(
		        new InputStreamReader(System.in));
		String line=" ";
			while(( (line=reader.readLine())!= " ")) {
				try {
					String polje [] = line.split(" ");
				    String algorithm = "AES/CBC/PKCS5Padding";
				    
				   if(polje[0].equals("init")) {
					  SecretKey key1 = getKeyFromPassword(polje[1]);
					   String kriptirano = encrypt(algorithm,"pocetak kreni", key1, generateIv());
					   File baza = new File("baza.txt");
					   try {
			                FileWriter myWriter = new FileWriter("baza.txt");
			                myWriter.write(kriptirano);
			                myWriter.close();
			              } catch (IOException e) {
			                System.out.println("Greska pri pisanju u bazu.");
			                e.printStackTrace();
			              }
					   calculateHMac(polje[1],kriptirano);
					   System.out.println("Password manager initialized.");
					   
					   
				   } else if (polje[0].equals("put")) {
					   BufferedReader reader2 = null;
                       String text = "";
						try {
							reader2 = new BufferedReader(new FileReader("baza.txt"));
							String line2 = reader2.readLine();
                            
							while (line2 != null) {
								text = text + line2;
								line2 = reader2.readLine();
							}

							reader2.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
						
						
						//System.out.println(text);
						 BufferedReader readerIV = null;
	                      String textIV = null;
	                       
	                      byte[] salt = new byte[16];
	                      try {
	                          File saltf = new File("saltf.bin");
	                          FileInputStream filein = new FileInputStream(saltf);
	                          salt = filein.readAllBytes();
	                      } catch (Exception e) {
	                          System.out.println("pogreska u citanju");
	                      }
	                    
	                      byte[] iv = new byte[16];
	                      try {
	                          File IV = new File("IV.bin");
	                          FileInputStream filein = new FileInputStream(IV);
	                          iv=filein.readAllBytes();
	                      } catch (Exception e) {
	                          System.out.println("pogreska u citanju");
	                      }
	                      
	                      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
	          		    KeySpec spec = new PBEKeySpec(polje[1].toCharArray(), salt, 65536, 256);
	          		    SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
	          		        .getEncoded(), "AES");
							IvParameterSpec IVspec = new IvParameterSpec(iv);
						   String dekriptirano = decrypt(algorithm,text, secret, IVspec);
						   
						   
						   if(checkHMac(polje[1],text)==false){
				                System.out.println("Master password incorrect or integrity check failed");
				                System.exit(0);
				            }else {
				            	String[] parts = dekriptirano.split("\n");
				            	
				                Map<String, String> adrPassMap = new HashMap<>();
				                for (int k = 0; k < parts.length; k++) {
				                	String adrpass[] = new String[2];
				                	adrpass[0]= parts[k].split(" ")[0];
				                	adrpass[1]= parts[k].split(" ")[1];
				                    adrPassMap.put(adrpass[0], adrpass[1]);
				                }
				  
				                adrPassMap.put(polje[2], polje[3]);
				                
				                //pretvaranje u string
				                String finalni = "";
				                int size=0;
				                for (Map.Entry<String,String> entry : adrPassMap.entrySet()) {
				                   finalni= finalni + entry.getKey() + " " + entry.getValue();
				                   size++;
				                   if(size<adrPassMap.size())
				                   finalni = finalni + "\n";
				                }
				             //   System.out.println(finalni);
				                SecretKey key1 = getKeyFromPassword(polje[1]);
								   String kriptirano = encrypt(algorithm,finalni, key1, generateIv());
								   File baza = new File("baza.txt");
								   try {
						                FileWriter myWriter = new FileWriter("baza.txt");
						                myWriter.write(kriptirano);
						                myWriter.close();
						                System.out.println("Stored password for " + polje[2]);
						              } catch (IOException e) {
						                System.out.println("Greska pri pisanju u bazu.");
						                e.printStackTrace();
						              }
								   calculateHMac(polje[1],kriptirano);
				            }
						   
					
				   }else if(polje[0].equals("get")){
					   BufferedReader reader2 = null;
                       String text = "";
						try {
							reader2 = new BufferedReader(new FileReader("baza.txt"));
							String line2 = reader2.readLine();
                            
							while (line2 != null) {
								text = text + line2;
								line2 = reader2.readLine();
							}

							reader2.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
						
						
						 BufferedReader readerIV = null;
	                      String textIV = null;
	                      byte[] salt = new byte[16];
	                      try {
	                          File saltf = new File("saltf.bin");
	                          FileInputStream filein = new FileInputStream(saltf);
	                           salt = filein.readAllBytes();
	                      } catch (Exception e) {
	                          System.out.println("Pogreska pri citanju");
	                      }
	                      byte[] iv = new byte[16];
	                      try {
	                          File IV = new File("IV.bin");
	                          FileInputStream filein = new FileInputStream(IV);
	                      iv=filein.readAllBytes();
	                      } catch (Exception e) {
	                          System.out.println("Pogreska pri citanju");
	                      }
	                      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
	          		    KeySpec spec = new PBEKeySpec(polje[1].toCharArray(), salt, 65536, 256);
	          		    SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
	          		        .getEncoded(), "AES");
							IvParameterSpec IVspec = new IvParameterSpec(iv);
						   String dekriptirano = decrypt(algorithm,text, secret, IVspec);
						   
						   
						   if(checkHMac(polje[1],text)==false){
				                System.out.println("Master password incorrect or integrity check failed");
				                System.exit(0);
				            }else {
				            	//System.out.println(dekriptirano);
				            	String[] parts = dekriptirano.split("\n");
				            	
				                Map<String, String> adrPassMap = new HashMap<>();
				                for (int k = 0; k < parts.length; k++) {
				                	String adrpass[] = new String[2];
				                	adrpass[0]= parts[k].split(" ")[0];
				                	adrpass[1]= parts[k].split(" ")[1];
				                    adrPassMap.put(adrpass[0], adrpass[1]);
				                }
				                String lozinka = adrPassMap.get(polje[2]);
				                if (lozinka== null){
				                    System.out.println("No stored password for " + polje[2]);
				                }else{
				                    System.out.println("Password for " + polje[2] + " is: " + lozinka);
				                }
				            }
				   }
				   
				    
				}catch(Exception e) {
					break;
				}
				}
			reader.close();
	}
	public static final String ALGORITHM = "HmacSHA256";

    public static String calculateHMac(String key, String data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance(ALGORITHM);

        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);
        sha256_HMAC.init(secret_key);

        //return byteArrayToHex(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
        String fileName = "file.bin";

        BufferedOutputStream bs = null;

        try {

            FileOutputStream fs = new FileOutputStream(new File(fileName));
            bs = new BufferedOutputStream(fs);
            bs.write(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
            bs.close();
            bs = null;

        } catch (Exception e) {
            e.printStackTrace();
        }

        if (bs != null) try { bs.close(); } catch (Exception e) {}
        
       
        return byteArrayToHex(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
    }
    public static boolean checkHMac(String key, String data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance(ALGORITHM);

        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes("UTF-8"), ALGORITHM);
        sha256_HMAC.init(secret_key);

        //return byteArrayToHex(sha256_HMAC.doFinal(data.getBytes("UTF-8")));
        String fileName = "file.bin";

           FileInputStream fs = new FileInputStream(new File(fileName));
       byte[] hmacReadBytes = ((InputStream) fs).readAllBytes();
            fs.close();
            fs = null;

       

        byte[] hmacbytes = sha256_HMAC.doFinal(data.getBytes("UTF-8"));
        
       
        return Arrays.equals(hmacbytes,hmacReadBytes);
    }
    
    
    
      public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
      
      
      public static IvParameterSpec generateIv() throws IOException {
    	    byte[] iv = new byte[16];
    	    new SecureRandom().nextBytes(iv);
    	   
           //File IV = new File("IV.bin");
            Path path = Paths.get("IV.bin");
            try {
                Files.write(path, iv);   
            }
            catch (IOException e) {
                e.printStackTrace();
            }
           // System.out.println("upisan vektor " + iv);
    	    return new IvParameterSpec(iv);
    	}
      
      public static SecretKey getKeyFromPassword(String password)
    		    throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
    	  SecureRandom random = new SecureRandom();
    	  byte[] salt = random.generateSeed(16);
       //   System.out.println("salt"+ salt);
          Path path = Paths.get("saltf.bin");
          try {
              Files.write(path, salt);   
          }
          catch (IOException e) {
              e.printStackTrace();
          }
        //  System.out.println("upisan salt "+ salt);
    		    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    		    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
    		    SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
    		        .getEncoded(), "AES");
    		    return secret;
    		}
    	
      public static String encrypt(String algorithm, String input, SecretKey key,
    		    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
    		    InvalidAlgorithmParameterException, InvalidKeyException,
    		    BadPaddingException, IllegalBlockSizeException {
    		    
    		    Cipher cipher = Cipher.getInstance(algorithm);
    		    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    		    byte[] cipherText = cipher.doFinal(input.getBytes());
    		    return Base64.getEncoder()
    		        .encodeToString(cipherText);
    		}
      
      public static String decrypt(String algorithm, String cipherText, SecretKey key,
    		    IvParameterSpec iv){
    		    try {
    		    Cipher cipher = Cipher.getInstance(algorithm);
    		    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    		    byte[] plainText = cipher.doFinal(Base64.getDecoder()
    		        .decode(cipherText));
    		    return new String(plainText);
    		    } catch(Exception e) {
    	            System.out.println("Master password incorrect or integrity check failed\n");
    	            System.exit(0);
    	        }
				return null;
    		    
    		}
    

}
