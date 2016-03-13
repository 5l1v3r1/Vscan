/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vscan;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

/**
 *
 * @author Pascal Tene
 */
public class ConnectToUrlForContent {
     public static void connectToUrl(String https_url) {
    // this method connects to the target URL and print everithing, including HTTP Headers and content
        System.out.println("Target: " + https_url );
        URL url;
        
        try {
            url = new URL(https_url);
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            //print_https_cert(con);
            print_content(con);
        } catch (MalformedURLException e) {
            System.out.println("There is a problem with the provided URL");
            //e.printStackTrace();
            
        }catch (IOException e){
            System.out.println("We have a problem please check the provided URL");
            //e.printStackTrace();
        }
    }
     
     
      private static void print_content(HttpsURLConnection con) {
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
