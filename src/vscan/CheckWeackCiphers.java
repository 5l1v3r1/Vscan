
package vscan;

import java.util.ArrayList;
import java.util.HashMap;

/**
 *
 * @author Pascal Tene
 */
//This class recives an ArrayList as input, from Vscan, containing the list of Cipher Suite supported by the tartget
//The Cipher suites are parsed and the CVEs are extracted, then added to a new list that will be sent to a differnet class for further processing.
public class CheckWeackCiphers {
    public static void parseTargetCipher(ArrayList<String> supportedCipherList, String testedProtocol) {
        //We only run this test if the received supported cipher list is NOT empty.
        if (!supportedCipherList.isEmpty()){
        ArrayList<String> vulnerabilityCodeList = new ArrayList<String>();
        ArrayList<String> cveList = new ArrayList<String>();
        HashMap<String, String>listOfCiphersAndGrade = new HashMap<String, String>();
        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", "A");
        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "A");
        listOfCiphersAndGrade.put("TLS_RSA_WITH_AES_128_CBC_SHA256", "A");
        listOfCiphersAndGrade.put("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", "A");
        listOfCiphersAndGrade.put("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", "A");
        listOfCiphersAndGrade.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "A-");
        listOfCiphersAndGrade.put("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", "A-");
        listOfCiphersAndGrade.put("SSL_RSA_WITH_RC4_128_SHA", "E");
        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "C");
        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "A+");
        listOfCiphersAndGrade.put("TLS_RSA_WITH_AES_128_GCM_SHA256", "A+");
        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "A+");
        listOfCiphersAndGrade.put("SSL_RSA_WITH_RC4_128_MD5", "F");
        listOfCiphersAndGrade.put("SSL_RSA_WITH_RC4_128_SHA", "E");
        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "E");
        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "E");
        listOfCiphersAndGrade.put("SSL_RSA_WITH_3DES_EDE_CBC_SHA", "C");
        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "D");
        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", "D");
        listOfCiphersAndGrade.put("TLS_RSA_WITH_AES_128_CBC_SHA", "C");
        listOfCiphersAndGrade.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "C");
        listOfCiphersAndGrade.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "C");
        Boolean cbctested = false;
        Boolean rc4tested = false;
        for (String cipherSuite: listOfCiphersAndGrade.keySet()){
            if (supportedCipherList.contains(cipherSuite)){
            System.out.println(cipherSuite + " Grade " + listOfCiphersAndGrade.get(cipherSuite));
        }
            
        
        //if (cipherSuite.toLowerCase().contains("cbc") && (cbctested == false)){
            if (cipherSuite.toLowerCase().contains("cbc") && (cbctested == false)){
            cbctested = true;
            vulnerabilityCodeList.add("cbc");
            /*//Build a CBC CVEs to the list of CVEs.
            // We should only add cbc to the arrayList, then check the database for all cbc related vulnerabilities
            cveList.add("CVE-2012-2333");
            cveList.add("CVE-2014-8730");
            cveList.add("CVE-2011-3389");
            cveList.add("CVE-2012-1870");
            //System.out.println("you are vulnerable to some Weaknesses in CBC");
            System.out.println(" CVE-2012-2333: CBC vul nerability. Not Vulnerable if running Big-IP version 11.3.0 +. See SOL15401");
            System.out.println(" CVE-2014-8730: CBC vul nerability. Not Vulnerable if running Big-IP version 11.5.2 +. A Patch exist for all supported releases See SOL15882");
            //System.out.println("Your Infrastructure is much safer if you are running the latest Big-IP software release"); */
    }else{
           if (cipherSuite.toLowerCase().contains("rc4") && (rc4tested == false)){  
              rc4tested = true;
              vulnerabilityCodeList.add("rc4");
              /*System.out.println(" CVE-2013-2566: RC4 Vulnerability see F5 SOL16867");
              System.out.println(" CVE-2015-2808: RC4 Vulnerability see F5 SOL14638");*/
           }
        }
        }
       //CheckVulnerabilities.parseCVE(cveList);
        
       try {
       ConnectDB conn = new ConnectDB();
       conn.connectToDB();
       //Call execSQL with the list of codes that will be checked before display
       conn.execSQL(vulnerabilityCodeList);
       } catch (Exception e) {
				System.out.println("Cannot connect to the database.");
       }

       
    }
     else {
    System.out.println("Empty list Protocol "+ testedProtocol+ " not supported.");
}
    }
}
