/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package vscan;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;

/**
 *
 * @author Pascal Tene
 */
public class ConnectDB {
    
     Connection connection;
	public ConnectDB() throws Exception	{
	try {
	Class.forName("com.mysql.jdbc.Driver").newInstance();
	System.out.println("Connected To MySQL");
	} catch (ClassNotFoundException e) {
	System.out.println("Error: Cannot load the driver");
	}

	}

	public void connectToDB() throws Exception {
		try {
			connection = DriverManager.getConnection (
				"jdbc:mysql://localhost/vscan", "root", "jt.pas");
			System.out.println("Connected to the database.");
			} catch (Exception e) {
				System.out.println("Cannot connect to the database.");
			}
		}
        
        public void execSQL(ArrayList<String> recivedlisOfCodes) {
            ArrayList<String> listOfCodes = new ArrayList<String>();
            listOfCodes = recivedlisOfCodes;
            System.out.println("Number of vulnerabilities found: "+listOfCodes.size());
            for (String code: listOfCodes){
               // System.out.println("Curently in execSQL "+code); This can show the elements of the list of codes received for debugging.
            try {
                Statement stmt = connection.createStatement();
                ResultSet rs = stmt.executeQuery("Select * from vulnerabilities");
                while (rs.next()) {
                    if(rs.getString(2).equalsIgnoreCase(code)){
                    System.out.println("\n");
                    System.out.println(rs.getString(1)+ ":  " + rs.getString(2)+ " " + rs.getString(3)+ " " + rs.getString(4)+ "\n Category: " + rs.getString(5)+ " \n CVSS Base Score: " + rs.getString(6)+ " \n Severity: " + rs.getString(7)
                           + " \n Ask F5 Solution: " + rs.getString(11)+ " \n Solution link: " + rs.getString(10) + " \n Last updated: " + rs.getString(9));
                }
                }
            } catch (Exception e) {
                System.out.println("Error executing SQL");
            }
            System.out.println();
            }
            
           
        }

    
}
