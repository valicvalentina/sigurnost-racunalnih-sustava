package lab2srs;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class login {

	public static void main(String[] args) throws IOException {
		BufferedReader reader = new BufferedReader(
		        new InputStreamReader(System.in));
		String line=" ";
			while(( (line=reader.readLine())!= " ")) {
				
				try {
					String polje [] = line.split(" ");
					 File baza = new File("bazanew.txt");
					 baza.createNewFile();
					 
					 BufferedReader reader2 = null;
                     String text = "";
						try {
							reader2 = new BufferedReader(new FileReader("bazanew.txt"));
							String line2 = reader2.readLine();
                          
							while (line2 != null) {
								text = text + line2 + "/n";
								line2 = reader2.readLine();
							}

							reader2.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
                        String [] parts = text.split("/n");
                        
                        
                        
						
						Map<String, String> UsernamePassMap = new HashMap<>();
						
						
			                for (int k = 0; k < parts.length; k++) {
			                	String userpass[] = new String[3];
			                	userpass[0]= parts[k].split(" ")[0];
			                	userpass[1]= parts[k].split(" ")[1];
			                	userpass[2]= parts[k].split(" ")[2];
			            UsernamePassMap.put(userpass[0], userpass[1] + " "+userpass[2]);
			                }
						
//UsernamePassMap.forEach((key, value) -> System.out.println(key + ">>:" + value));
			                
			                
						 String username = polje[0];
                         String password = "";
                         Console console = System.console();

                        if (console == null) {
                            System.out.println("No console.");
                            System.exit(0);
                           }
      
       
                   System.out.println("Password:");
                   password = new String(console.readPassword());
  
  
  
						if(UsernamePassMap.get(username) != null) {
							String user = username+".bin";
							//System.out.println(user);

							 byte[] together = Files.readAllBytes(Paths.get(user));
							 //System.out.println(Arrays.toString(together));
							 byte[] salt = new byte[16];
							 salt= Arrays.copyOfRange(together, 0, 16);
							 byte[] hashr = Arrays.copyOfRange(together, 16, together.length);
					            
				                
							 //System.out.println(Arrays.toString(salt));
							//System.out.println(salt+" salt");
							KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
							SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
							
							byte[] hash = factory.generateSecret(spec).getEncoded();
							// System.out.println(Arrays.toString(hashr));
							// System.out.println(Arrays.toString(hash));
							if(Arrays.equals(hashr,hash)) {
String flag = UsernamePassMap.get(username).substring(UsernamePassMap.get(username).length()-1, UsernamePassMap.get(username).length());
                            if(flag.equals("1")) {
                            	 System.out.println("New password:");
        						 String password2 = "";
        						  password2 = new String(console.readPassword());
        				            System.out.println("Repeat new password:");
        				          //  System.out.println(password2);
        				            
        				            String newPassword = new String (console.readPassword());
        				         //   System.out.println(repeatPassword);
        				            if (!password2.equals(newPassword)){
        				                System.out.println("Password change failed. Password mismatch.");
        				                System.exit(0);
        				            }
        				            if (password2.length()<8){
        				                System.out.println("Password has to be at least 8 characters long!");
        				                System.exit(0);
        				            }
        				            
        				            byte[] pass2 = hashiraj(password2,username);
        				        	UsernamePassMap.put(username, pass2 + " " + "0");
        				        	 String finalni = "";
        				                int size=0;
        				                for (Map.Entry<String,String> entry : UsernamePassMap.entrySet()) {
        				                   finalni= finalni + entry.getKey() + " " + entry.getValue();
        				                   size++;
        				                   if(size< UsernamePassMap.size())
        				                   finalni = finalni + "\n";
        				                }
        					            try {
        					                FileWriter myWriter = new FileWriter(baza);
        					                myWriter.write(finalni);
        					                myWriter.close();
        					              } catch (IOException e) {
        					                System.out.println("Greska pri pisanju u bazu.");
        					                e.printStackTrace();
        					              }
        				
                            }

								System.out.println("Login successful.");
								
							}else {
								System.out.println("Username or password incorrect.");
							}
							
							
							
							
						}else {
							System.out.println("Username or password incorrect.");
						}
						
						
	}catch (Exception e) {
		e.printStackTrace();
	}

}
}
	
	
	
	
	
	
	
	
	

	private static byte[] hashiraj(String password, String username) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		 String user = username+".bin";
		 SecureRandom random = new SecureRandom();
   	     byte[] salt = random.generateSeed(16);
         //System.out.println(Arrays.toString(salt));
     
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		
		byte[] hash = factory.generateSecret(spec).getEncoded();
		File write = new File(user);
        FileOutputStream fos = new FileOutputStream(write);
        fos.write(salt);
        fos.write(hash);
        fos.flush();
        fos.close();
		return hash;
	}
}