import java.io.IOException;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.commons.io.IOUtils;
import org.apache.poi.ss.usermodel.Cell;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.BufferedReader;
import java.io.FileInputStream;
import org.apache.poi.ss.usermodel.DataFormatter;

public class start
{
    public static int count;
    public static String testability;
    public static String tc_name;
    public static String jar_filepath;    
    public static String test_data;
    public static String test_data_tab;
    public static String test_result;
    public static String test_cycle;
    DataFormatter df;
    
    public start() {
        this.df = new DataFormatter();
    }
    
    public static void main(final String[] args) throws IOException, Throwable {
        final DataFormatter df = new DataFormatter();
        final FileInputStream StartInput = new FileInputStream("c:\\TA\\TestConfig.xlsx");
        final XSSFWorkbook StartInputWB = new XSSFWorkbook(StartInput);
        final XSSFSheet sheet = StartInputWB.getSheet("Config");
        //System.out.println("Amount of Row in test config : "+ sheet.getLastRowNum());
        //System.out.println("Total test case = " + sheet.getLastRowNum());
        start.count = 1;
        //while (start.count <= sheet.getLastRowNum()) {
        for(start.count = 1; start.count <= sheet.getLastRowNum(); start.count++){	            
            System.out.println(" ");
            System.out.println("Test case no. " +start.count);
            final XSSFRow row = sheet.getRow(start.count);
            start.testability = row.getCell(0).toString();            
            start.jar_filepath = row.getCell(2).toString();
            start.tc_name = row.getCell(1).toString();
            start.test_data = row.getCell(3).toString();
            start.test_result = row.getCell(4).toString();
            start.test_cycle = df.formatCellValue(row.getCell(5));
            //System.out.println("test cycle from start.jar = " + start.test_cycle);
            System.out.println("Test Case Name : " + start.tc_name);
            if (start.testability.equals("Y") || start.testability.equals("y)")) {
                //System.out.println("Test Case Name : " + start.tc_name);
                //System.out.println("Round : " + start.count);
                //ProcessBuilder processBuilder = new ProcessBuilder();

    	        // Run this on Windows, cmd, /c = terminate after this run
    	        //processBuilder.command("cmd.exe", "/c", "java", "-jar", start.jar_filepath, start.tc_name, start.test_data, start.test_result);
                //System.out.println("processBUilder  = " + processBuilder);
    	        
    	        //Process process = processBuilder.start();
                //process.waitFor()  ;
    	        /*try {

    	            Process process = processBuilder.start();
                    process.waitFor()  ;
    				// blocked :(
    	            BufferedReader reader =
    	                    new BufferedReader(new InputStreamReader(process.getInputStream()));

    	            String line;
    	            while ((line = reader.readLine()) != null) {
    	                System.out.println(line);
    	            }

    	            int exitCode = process.waitFor();
    	            System.out.println("\nExited with error code : " + exitCode);

    	        } catch (IOException e) {
    	            e.printStackTrace();
    	        } catch (InterruptedException e) {
    	            e.printStackTrace();
    	        }*/

    	    
// {fact rule=os-command-injection@v1.0 defects=1}
                
                
                
                
                
// defect
                final Process p = Runtime.getRuntime().exec("cmd /c start /wait java -jar " + start.jar_filepath + " " + start.tc_name + " " + start.test_data + " " + start.test_result + " " + start.test_cycle );
                p.waitFor(); //   wait(); //    waitFor();
                System.out.println("Test Case " + start.tc_name + " completed");
               
    
                //p.isAlive();
// {/fact}
                //System.out.println("wait for = " +p.waitFor());
             
                //System.out.println(" p = " + p);
                //String output = IOUtils.toString(p.getInputStream());
                //System.out.println("wait for = " +p.waitFor());
                //p.exitValue();
                //do{
                	//System.out.println("wait for = " +p.waitFor());
                //}	
                //while(p.waitFor() == 0 );
                //p.waitFor();
                
                	
            }//if
                
                
               
                //Thread.sleep(5000);
            
            else {
            	System.out.println("Test Case " + start.tc_name + " not selected for execution");
            }
           // ++start.count;
        }//for
        System.out.println("     ");
        System.out.println("Test completed");
    }
   
    }




























































/*import java.io.IOException;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.ss.usermodel.Cell;
import java.io.InputStream;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import java.io.FileInputStream;
import org.apache.poi.ss.usermodel.DataFormatter;

public class start
{
    public static int count;
    public static String testability;
    public static String tc_name;
    public static String jar_filepath;
    public static String url;
    public static String test_data;
    public static String test_data_tab;
    public static String test_result;
    public static String test_cycle;
    public static int inputRow;
    DataFormatter df;
    
    public start() {
        this.df = new DataFormatter();
    }
    
    public static void main(final String[] args) throws IOException, Throwable {
        final DataFormatter df = new DataFormatter();
        final FileInputStream StartInput = new FileInputStream("C:\\TA\\TestConfig.xlsx");
        @SuppressWarnings("resource")
		final XSSFWorkbook StartInputWB = new XSSFWorkbook(StartInput);
        final XSSFSheet sheet = StartInputWB.getSheet("Config");
        start.count = 1;
        //while (start.count <= sheet.getLastRowNum()) {
        //System.out.println("No. of rows : " + sheet.getLastRowNum());
        for(inputRow = 1; inputRow<=sheet.getLastRowNum(); inputRow++) {
            System.out.println("Total test case = " + sheet.getLastRowNum());
            //System.out.println("Now running test case : " + inputRow);
            final XSSFRow row = sheet.getRow(start.count);
            start.testability = row.getCell(0).toString();
            start.tc_name = row.getCell(1).toString();
            start.jar_filepath = row.getCell(2).toString();
            //start.url = row.getCell(3).toString();
            start.test_data = row.getCell(3).toString();
            start.test_result = row.getCell(4).toString();
            start.test_cycle = df.formatCellValue((Cell)row.getCell(5));
            System.out.println("test cycle from start.jar = " + start.test_cycle);
            //System.out.println("Test Case Name : " + start.tc_name);
            if (start.testability.equalsIgnoreCase("Y")) {
                System.out.println("Test Case Name : " + start.tc_name);
                System.out.println("Round : " + start.count);
                System.out.println("test cycle from start.jar = " + start.test_cycle);
                final Process p = Runtime.getRuntime().exec("cmd /c start /wait java -jar " + start.jar_filepath + " " + start.tc_name + " " + start.test_data + " " + start.test_result + " " + start.test_cycle);
                System.out.println(p);
                p.waitFor();
                System.out.println("wait for = " +p.waitFor());
                System.out.println("Test Case " + start.tc_name + " completed");
            }
            else {
            	System.out.println("Test Case " + start.tc_name + " not selected for execution");
            }
            //start.count;
        }//while
        System.out.println("test is done");
    }
}*/