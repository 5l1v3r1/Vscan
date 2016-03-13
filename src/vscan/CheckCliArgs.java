/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vscan;

/**
 *
 * @author Pascal Tene
 */
public class CheckCliArgs {
    public static void parseArgs(String[] receivedArgs){  
	System.out.println("checking CLI Args");
	System.out.println("Number of args received: "+ receivedArgs.length);
	if (receivedArgs.length == 0) {
            System.out.println("You must enter an https URL as argument");
            help();
            System.exit(0);
            } else {
                String s = receivedArgs[0];
                if (!s.startsWith("https://")) {
                    System.out.println("You must enter a valid https URL as argument");
                    System.out.println("An example is: HttpsScan https://www.example.com");
                    help();
                    System.exit(0); 
                }
}
    
}
    
    
    public static void help() {
	System.out.println();
	System.out.println( "-h or help : print this message");
	System.out.println( "-s : Target url to scan");
	System.out.println( "-Portscan or port : port to scan on the target URL. Default port will be scanned if a port number is not given");
	System.out.println( "-r : port range to scan");
	System.out.println( "-f File_name: File to output the scan results");
	System.out.println( "-v or version : Prints the version of this software");
	System.out.println( "Ciphers List of ciphers to test: or version : test the target site with the suplied list of ciphers");
	System.out.println( "Scanports [list of ports to scan] : scans the target for open ports");
	System.out.println( "ScanHttps  [https url] : scans the target https url");
	System.out.println( "ScanHttp  [http url] : scans the target http url");
	System.out.println( "Scandefaultports  [target URL or IP Address] : scans the target to detect default open ports");
	System.out.println( "ScanAllPorts  [target URL or IP Address] : scans the target to detect any open ports between 1 to 65536");

}
}
