
package vscan;

/**
 *
 * @author Pascal Tene
 */
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.net.MalformedURLException;
import java.io.InputStreamReader;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

public class Vscan {
    public static void main(String[] args) throws Exception {
        // Begin C1 - The goal of this is to allow connection to some sites with invalid cert.
        //This is important when we want to test self signed certificates in Lab environment
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
        public void checkClientTrusted(X509Certificate[] certs, String authType) {  }
        public void checkServerTrusted(X509Certificate[] certs, String authType) {  } 
            }
        };
        // We should loop through different versions of SSL / TLS: TLSv1.2, TLSv1.1, TLSv1, SSLv3
        // Some details in https://blogs.oracle.com/java-platform-group/entry/diagnosing_tls_ssl_and_https
        String protocol = "SSLv3";
        java.lang.System.setProperty("https.protocols", protocol);
        SSLContext sc = SSLContext.getInstance(protocol);
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        
        // create trusted Host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
      HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);  
      
    // End C1
    // Begin Comment 2: This is to make sure we exit if the user does no provide an argument
    //the argument provided must be https link
    if (args.length == 0) {
            System.out.println("You must enter an https URL as argument");
            System.exit(0);
            } else {
                String s = args[0];
                if (!s.startsWith("https://")) {
                    System.out.println("You must enter a valid https URL as argument");
                    System.out.println("An example is: HttpsScan https://www.example.com");
                    System.exit(0);   
                } else {
        //set the target URL as the first CLI argument    
                     String targetUrl = args[0];
                     System.out.println("Target: " + targetUrl );
        // end comment 2
        // The list of cipher suites that will be used by th eclient to connect to the target repetitively
        // is defined below in an Array list. 
        SSLSocketFactory sf = (SSLSocketFactory) SSLSocketFactory.getDefault();
        String supportedCiphers[] = sf.getSupportedCipherSuites();
            
        /*To get all ciphers, including those that java has disabled by default
        we need to comment out the line jdk.tls.disabledAlgorithms=MD5, SSLv3, DSA, RSA keySize < 2048
        in [JAVA_HOME]/jre/lib/security/java.security. For example C:/program file/java/jdk1.8.0//jre/lib/security/java.security
        
        */
                            
                    
                   
                ArrayList<String>listOfSuccessfulCiphers  = new ArrayList<String>();
                System.out.println("Testing CipherSuites accepted by tartget please wait...");
                     for (int j = 0; j < supportedCiphers.length; j++) {
                         System.out.print(" " + (j+1));
                         System.out.print(" Connecting with " + supportedCiphers[j]);
                         //set the current cipher suite as the one for next connection
                         System.setProperty("https.cipherSuites", supportedCiphers[j]);
                         String successfulCipher = new Vscan().connectToUrlForCVE(targetUrl);
                     // Add the successful cipher to the list if the connection did not fail
                        if (successfulCipher.length() != 0){
                            listOfSuccessfulCiphers.add(successfulCipher);
                        }
                    } 
                   System.out.println("\n");
                   System.out.println("List of cipher suites supported by the target:");
                   System.out.println(listOfSuccessfulCiphers);
                   System.out.println("\n");
                   System.out.println("Number of cipher suites supported by the target:"+ listOfSuccessfulCiphers.size());
                   System.out.println("List of vulnerabilities and solution containing work around:");
                   
                   // send the ArrayList containing the list of Successful Ciphers to the CheckWeakCiphers class for evaluation. a
                  CheckWeackCiphers.parseTargetCipher(listOfSuccessfulCiphers, protocol);
                   // test CBC Vulnerabilities; only check one cipher suite with "CBC"
                   Boolean cbctest = false;
                   for (int k=0; k < listOfSuccessfulCiphers.size(); k++){
                       String cCS = listOfSuccessfulCiphers.get(k);
                        if (cCS.toLowerCase().contains("cbc")){
                           if (cbctest == false){
                            
                           cbctest = true;
                           
                       // CheckWeackCiphers.parseTargetCipher(listOfSuccessfulCiphers.get(k));
                           }
                       }
                       }
                   
                   //flolowing print the headers and the contain using a predefined cipher which is expected to work
                    System.setProperty("https.cipherSuites", "TLS_RSA_WITH_AES_128_CBC_SHA");
                     new Vscan().connectToUrl(targetUrl);
            }
    
        }
        
    }
    
    // start
    public String connectToUrlForCVE(String https_url) {
        //This is the main method for connecting to a target URL and collecting the cipher suite used
        URL url;
        String cs = "";
         try {
            url = new URL(https_url);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
                      
            if (con != null) {
            try {
                System.out.print(": Response Code: " + con.getResponseCode());
                String ciphersuite = con.getCipherSuite();
                if (ciphersuite.length() == 0 | ciphersuite == null) {
                    System.out.println(" Failed");
                } else {
                    System.out.println(": Success");
                    cs = ciphersuite;
                 }                                          
               
            } catch (SSLPeerUnverifiedException e) {
                e.printStackTrace();
            } catch (IOException e) {
                //e.printStackTrace();
                System.out.println(": Failed");
                
            }                                     
        }
            
        } catch (MalformedURLException e) {
            e.printStackTrace();
            //System.out.println(e.getMessage());
        return "";
        }catch (IOException e){
            e.printStackTrace();
            return "";
        }
        return cs;
    }
    //end
    
    public void connectToUrl(String https_url) {
    // this method connects to the target URL and print everithing, including HTTP Headers and content
        System.out.println("Target: " + https_url );
        URL url;
        
        try {
            url = new URL(https_url);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            print_https_cert(con);
            print_content(con);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            
        }catch (IOException e){
            e.printStackTrace();
        }
    }
    
    private void print_https_cert(HttpsURLConnection con) {
        if (con != null) {
            try {
                System.out.println("Response Code: " + con.getResponseCode());
                System.out.println("Cipher Suite: " + con.getCipherSuite());
                String cipherSuite = con.getCipherSuite();
                System.out.println("\n");
                System.out.println("\n");
                
                Certificate[] certs = con.getServerCertificates();
                for (Certificate cert : certs) {
                    System.out.println("Certificate type: " + cert.getType());
                    System.out.println("Certificate hash: " + cert.hashCode());
                    System.out.println("Certificate Public Key Algorithm: " + cert.getPublicKey().getAlgorithm());
                    System.out.println("Certificate Public Key format: " + cert.getPublicKey().getFormat());
                    System.out.println("Pkey type: " + cert.getPublicKey());
                    System.out.println("\n");

                }
            } catch (SSLPeerUnverifiedException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            
            // printing HTTP headers
            Map headers = con.getHeaderFields();
            System.out.println("HTTP Headers received from server:");
               //System.out.println("HTTP Header Values" + headers.toString());
                String headerName = null;
                for (int i =1; (headerName = con.getHeaderFieldKey(i)) != null; i++) {
                    System.out.print(headerName);
                    System.out.println(": " + con.getHeaderField(i));
                }
                System.out.println("\n");
            //End printing HTTP Headers
        }
    }

    private void print_content(HttpsURLConnection con) {
        if (con != null) {
            try {
                System.out.println("****URL return content****");
                BufferedReader buff = new BufferedReader(
                        new InputStreamReader(con.getInputStream()));
                String input;

                while ((input = buff.readLine()) != null) {
                    System.out.println(input);
                }
                buff.close();
            } catch (IOException e) {
                //e.printStackTrace();
            }
        }
    }
    
}
