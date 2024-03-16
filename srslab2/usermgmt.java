package lab2srs;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class usermgmt {
static Map<String, Integer> numbers= new LinkedHashMap<>();
	public static void main(String[] args) throws IOException {
		BufferedReader reader = new BufferedReader(
		        new InputStreamReader(System.in));
		String line=" ";
		int i=0;
		boolean added=false;
			while(( (line=reader.readLine())!= " ")) {
				i++;
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
						//System.out.println(text);
						String [] parts = text.split("/n");
						
						Map<String, String> UsernamePassMap = new HashMap<>();
						if(i>1 && text!="" && added) {
			                for (int k = 0; k < parts.length; k++) {
			                	String userpass[] = new String[3];
			                	userpass[0]= parts[k].split(" ")[0];
			                	userpass[1]= parts[k].split(" ")[1];
			                	userpass[2]= parts[k].split(" ")[2];
			            UsernamePassMap.put(userpass[0], userpass[1] + " "+userpass[2]);
			                }
						}
						//UsernamePassMap.forEach((key, value) -> System.out.println(key + ">>:" + value));
						
					 if(polje[0].equals("add")) {
						 if(!UsernamePassMap.containsKey(polje[1])) {
						 String username = polje[1];
						 System.out.println("Password:");
						 String password = "";
						 Console console = System.console();
                         
						if (console == null) {
					            System.out.println("No console.");
					           System.exit(0);
					        }
						
						
						  password = new String(console.readPassword());
				            System.out.println("Repeat password:");
				            
				            
				            String newPassword = new String (console.readPassword());
				            if (!password.equals(newPassword)){
				                System.out.println("User add failed. Password mismatch.");
				               // System.exit(0);
				            }
				            if (password.length() < 8){
				            	System.out.println("Password has to be at least 8 characters long.");
				               // System.exit(0);
				            }
				            if(password.equals(newPassword)&&password.length() > 7) {
				            byte[] pass = hashiraj(password,username);
				           
				            UsernamePassMap.put(username, pass + " " + "0");
				           // System.out.println(Arrays.toString(pass));
				           
				            String finalni = "";
			                int size=0;
			                for (Map.Entry<String,String> entry : UsernamePassMap.entrySet()) {
			                   finalni= finalni + entry.getKey() + " " + entry.getValue();
			                   size++;
			                   if(size< UsernamePassMap.size())
			                   finalni = finalni + "\n";
			                }
				            //UsernamePassMap.forEach((key, value) -> System.out.println(key + ":" + value));
				          //  System.out.println(finalni);
				            try {
				                FileWriter myWriter = new FileWriter(baza);
				                myWriter.write(finalni);
				                myWriter.close();
				              } catch (IOException e) {
				                System.out.println("Greska pri pisanju u bazu.");
				                e.printStackTrace();
				              }
				            added=true;
				            System.out.println("User " + username + " successfuly added.");
						 }
					 } else {
						 System.out.println("User with this username already exists!"); 
					 }
					 } else if(polje[0].equals("passwd")) {
	//  UsernamePassMap.forEach((key, value) -> System.out.println(key + ":" + value));
						 String username = polje[1];
						 if(UsernamePassMap.containsKey(username)) {
						 System.out.println("Password:");
						 String password = "";
						 Console console = System.console();

						if (console == null) {
					            System.out.println("No console.");
					           System.exit(0);
					        }
						  password = new String(console.readPassword());
				            System.out.println("Repeat password:");
				            
				            
				            String newPassword = new String (console.readPassword());
				            if (!password.equals(newPassword)){
				                System.out.println("Password change failed. Password mismatch.");
				            }
				            if (password.length()< 8){
				                System.out.println("Password has to be at least 8 characters long.");
				            }
				            if(password.equals(newPassword)&&password.length() > 7) {
				            byte[] pass = hashiraj(password,username);
				          //  if(UsernamePassMap.containsKey(username)) {
		String flag = UsernamePassMap.get(username).substring(UsernamePassMap.get(username).length()-1,UsernamePassMap.get(username).length());
				            	UsernamePassMap.put(username, pass + " " + flag);
				            	System.out.println("Password change successful.");
				            }
//				            else {
//				            	System.out.println("User "+username+" does not exist");
//				            }
				            
				          //pretvaranje u string
			                String finalni = "";
			                int size=0;
			                for (Map.Entry<String,String> entry : UsernamePassMap.entrySet()) {
			                   finalni= finalni + entry.getKey() + " " + entry.getValue();
			                   size++;
			                   if(size< UsernamePassMap.size())
			                   finalni = finalni + "\n";
			                }
			                
				           // UsernamePassMap.forEach((key, value) -> System.out.println(key + ":" + value));
				           // System.out.println(finalni);
				            try {
				                FileWriter myWriter = new FileWriter(baza);
				                myWriter.write(finalni);
				                myWriter.close();
				              } catch (IOException e) {
				                System.out.println("Greska pri pisanju u bazu.");
				                e.printStackTrace();
				              }
					 }else {
			            	System.out.println("User "+username+" does not exist");
			            }
				           // System.out.println("Password change successful.");
					 } else if(polje[0].equals("forcepass")) {
						 String username = polje[1];
						 if(UsernamePassMap.containsKey(username)) {
							 String change = UsernamePassMap.get(username).substring(0,UsernamePassMap.get(username).length()-1);
							 change=change+"1";
				            	UsernamePassMap.put(username, change);
					            
				            	 String finalni = "";
					                int size=0;
					                for (Map.Entry<String,String> entry : UsernamePassMap.entrySet()) {
					                   finalni= finalni + entry.getKey() + " " + entry.getValue();
					                   size++;
					                   if(size< UsernamePassMap.size())
					                   finalni = finalni + "\n";
					                }
					           // UsernamePassMap.forEach((key, value) -> System.out.println(key + ":" + value));
					           // System.out.println(finalni);
					            try {
					                FileWriter myWriter = new FileWriter(baza);
					                myWriter.write(finalni);
					                myWriter.close();
					              } catch (IOException e) {
					                System.out.println("Greska pri pisanju u bazu.");
					                e.printStackTrace();
					              }
					            System.out.println("User will be requested to change password on next login.");
				            }else {
				            	System.out.println("User "+username+" does not exist");
				            }
						 
					 } else if(polje[0].equals("del")) {
						 String username = polje[1];
						 if(UsernamePassMap.containsKey(username)) {
				            	UsernamePassMap.remove(username,UsernamePassMap.get(username));
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
					            System.out.println("User successfuly removed.");
				            }else {
				            	System.out.println("User "+username+" does not exist");
				            }
					 }
					 
					 
					 
					 
				} catch (Exception e) {
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
