/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vscan;
import java.util.ArrayList;
import java.util.HashMap;
/**
 *
 * @author Pascal Tene
 */
//This class will take a list of found CVE and vulnerabilities as argument, and compare with data from the map available in this class, then print the result.
public class CheckVulnerabilities {
    public static void parseCVE(ArrayList<String> foundCveList){
        //a map containing CVE as key and a list of attribute: CVSS Score, F5 Solution Link, NVD link, etc...
        //we will add some static data to the map, but...
        //this map should be field with data from an xml file (for speed)
        //or the CVE xml file could be parsed directly but the CVE xml file is big and heavy... we shall see!!
        //The result should be printed or writed to a PDF file.
        HashMap<String, ArrayList<String>> mapofCVEList;
        
        System.out.println(" CVE-2012-2333: CBC vul nerability. Not Vulnerable if running Big-IP version 11.3.0 +. See SOL15401");
        System.out.println(" CVE-2014-8730: CBC vul nerability. Not Vulnerable if running Big-IP version 11.5.2 +. A Patch exist for all supported releases See SOL15882");
        System.out.println(" CVE-2013-2566: RC4 Vulnerability see F5 SOL16867");
        System.out.println(" CVE-2015-2808: RC4 Vulnerability see F5 SOL14638");
        
        /*try {
       ConnectDB conn = new ConnectDB();
       conn.connectToDB();
       conn.execSQL();
       } catch (Exception e) {
				System.out.println("Cannot connect to the database.");
       }
        */
    }
    
}
