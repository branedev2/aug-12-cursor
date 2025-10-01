import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import java.io.*;
import java.sql.*;
import java.util.Base64;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;

@WebServlet("/VulnerableApp")
public class VulnerableApp extends HttpServlet {

    // 🚨 Hardcoded secrets
    private static final String JWT_SECRET = "hardcodedSecretKeyForJWT123!";
    private static final String DB_PASSWORD = "SuperSecretP@ssword";

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter out = response.getWriter();

        // 🚨 Reflected XSS
        String q = request.getParameter("q");
        out.println("<html><body>Search results for: " + q + "</body></html>");

        // 🚨 SQL Injection
        String user = request.getParameter("user");
        String pass = request.getParameter("pass");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/app", "root", DB_PASSWORD);
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                out.println("Welcome, " + rs.getString("fullname"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
// {fact rule=os-command-injection@v1.0 defects=1}
        }

        // 🚨 Command Injection
        String cmd = request.getParameter("cmd");
        if (cmd != null) {
// defect
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                out.println(line + "<br>");
            }
// {/fact}
        }

        // 🚨 Insecure JWT decoding (no signature verification)
        String token = request.getParameter("token");
        if (token != null) {
            String[] parts = token.split("\\.");
            String payload = new String(Base64.getDecoder().decode(parts[1]));
            out.println("JWT payload: " + payload);
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter out = response.getWriter();

        // 🚨 Insecure file upload
        Part filePart = request.getPart("file");
        String fileName = filePart.getSubmittedFileName();
        File uploads = new File("/tmp/uploads");
        File file = new File(uploads, fileName);
        try (InputStream input = filePart.getInputStream()) {
            Files.copy(input, file.toPath());
            out.println("File uploaded: " + file.getAbsolutePath());
        }

        // 🚨 XXE vulnerability
        String xml = request.getParameter("xml");
        if (xml != null) {
            try {
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false); // insecure
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document doc = builder.parse(new ByteArrayInputStream(xml.getBytes()));
                out.println("Root element: " + doc.getDocumentElement().getNodeName());
            } catch (Exception e) {
                e.printStackTrace(out);
            }
        }

        // 🚨 Insecure deserialization
        String objectData = request.getParameter("payload");
        if (objectData != null) {
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(objectData)))) {
                Object obj = ois.readObject();
                out.println("Deserialized object: " + obj.toString());
            } catch (Exception e) {
                e.printStackTrace(out);
            }
        }
    }
}
