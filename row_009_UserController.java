package com.vontobel.devops.gitops.springbootdastexample.controller;

import com.vontobel.devops.gitops.springbootdastexample.model.User;
import com.vontobel.devops.gitops.springbootdastexample.repository.UserRepository;
import jakarta.websocket.server.PathParam;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.ModelAndView;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Enumeration;
import org.apache.commons.text.StringEscapeUtils;
import java.util.HashMap;
import java.util.Map;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


@RestController
public class UserController {
  private final UserRepository userRepository;
  private final DataSource dataSource;

  public UserController(UserRepository userRepository, DataSource dataSource) {
    this.userRepository = userRepository;
    this.dataSource = dataSource;
  }

  @GetMapping("/users")
  public List<User> getUsers() {
    return userRepository.findAll();
  }

  @GetMapping("/users/search")
  public User injection(@PathParam("username") String username) throws SQLException {
    if (username == null) {
      return null;
    } 
    return userRepository.findUserByUsername(dataSource, username);
  }

  // New route with XSS vulnerability
  @GetMapping("/greet")
  public String greet(@RequestParam("name") String name) {
    // Directly including user input in the response without sanitization
    return "<html><body><h1>Hello, " + name + "!</h1></body></html>";
  }

  @PostMapping("/upload")
  public String uploadFile(@RequestPart("file") MultipartFile file) {
    // Vulnerable file upload: no validation or sanitization
    String uploadDir = "/usr/src/app/uploads/";
    Path uploadPath = Paths.get(uploadDir);

    try {
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
            System.out.println("Created directory: " + uploadPath.toAbsolutePath());
        }

        Path filePath = uploadPath.resolve(file.getOriginalFilename());
        System.out.println("Saving file to: " + filePath.toAbsolutePath());
        file.transferTo(filePath.toFile());

        return "File uploaded successfully: " + file.getOriginalFilename();
    } catch (IOException e) {
      e.printStackTrace(); // Log the stack trace for debugging
      return "File upload failed: " + e.getMessage();
    }
  }

  // New route to serve the upload form
  @GetMapping("/upload-form")
  public String showUploadForm() {
    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>File Upload</title>"
        + "</head>"
        + "<body>"
        + "    <h1>Upload a File</h1>"
        + "    <form method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\">"
        + "        <label for=\"file\">Choose file to upload:</label>"
        + "        <input type=\"file\" id=\"file\" name=\"file\">"
        + "        <button type=\"submit\">Upload</button>"
        + "    </form>"
        + "</body>"
        + "</html>";
  }


  @PostMapping("/update-user")
  public String updateUser(@RequestParam("id") int id, @RequestParam("name") String name) {
    // Simulate updating user information without CSRF protection
    try {
      User user = userRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("Invalid user ID"));
      //user.setName(name);
      //userRepository.save(user);
      return "User updated successfully: ";
    } catch (Exception e) {
      e.printStackTrace(); // Log the stack trace for debugging
      return "User update failed: " + e.getMessage();
    }
  }


  @GetMapping("/edit-user-form")
  public String showEditUserForm(@RequestParam("id") int id) {
    User user = userRepository.findById(id).orElse(null);
    if (user == null) {
      return "User not found";
    }
    System.out.println("User found: " + user);
    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>Edit User</title>"
        + "</head>"
        + "<body>"
        + "    <h1>Edit User</h1>"
        + "    <form method=\"post\" action=\"/update-user\">"
        + "        <input type=\"hidden\" name=\"id\" value=\"" + user.getUid() + "\">"
        + "        <label for=\"name\">Name:</label>"
        + "        <input type=\"text\" id=\"name\" name=\"name\" value=\"" + user.getUsername() + "\">"
        + "        <button type=\"submit\">Update</button>"
        + "    </form>"
        + "</body>"
        + "</html>";
  }

  @GetMapping("/view-profile")
  public String viewProfile(jakarta.servlet.http.HttpServletRequest request) {
    // Check for the presence of the "user" cookie
    jakarta.servlet.http.Cookie[] cookies = request.getCookies();
    String userId = null;
    if (cookies != null) {
        for (jakarta.servlet.http.Cookie cookie : cookies) {
            if ("user".equals(cookie.getName())) {
                userId = cookie.getValue();
                break;
            }
        }
    }

    if (userId == null) {
        return "Unauthorized access";
    }

    // Fetch the user information using the userId from the cookie
    User user = userRepository.findById(Integer.parseInt(userId)).orElse(null);
    if (user == null) {
        return "User not found";
    }

    // Debugging line to print the user object
    System.out.println("User found: " + user);

    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>View Profile</title>"
        + "</head>"
        + "<body>"
        + "    <h1>View Profile</h1>"
        + "    <p>ID: " + user.getUid() + "</p>"
        + "    <p>Name: " + user.getUsername() + "</p>"
        + "    <p>Email: " + user.getEmail() + "</p>"
        + "</body>"
        + "</html>";
  }

  // New route to serve the login form
  @GetMapping("/login-form")
  public String showLoginForm() {
    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>Login</title>"
        + "</head>"
        + "<body>"
        + "    <h1>Login</h1>"
        + "    <form method=\"post\" action=\"/login\">"
        + "        <label for=\"username\">Username:</label>"
        + "        <input type=\"text\" id=\"username\" name=\"username\">"
        + "        <label for=\"password\">Password:</label>"
        + "        <input type=\"password\" id=\"password\" name=\"password\">"
        + "        <button type=\"submit\">Login</button>"
        + "    </form>"
        + "</body>"
        + "</html>";
  }

  // New route to handle login submission
  @PostMapping("/login")
  public String handleLogin(@RequestParam("username") String username, @RequestParam("password") String password) {
    if ("admin".equals(username) && "admin".equals(password)) {
      // Set a cookie for successful login
      jakarta.servlet.http.Cookie cookie = new jakarta.servlet.http.Cookie("user", "1");
      cookie.setHttpOnly(true);  
      cookie.setPath("/");
      cookie.setMaxAge(60 * 60); // 1 hour

      HttpServletResponse response = 
            ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getResponse();
      response.addCookie(cookie);

      return "Login successful!";
    } else {
      return "Invalid username or password.";
    }
  }

  // New route to serve the create user form
  @GetMapping("/create-user-form")
  public String showCreateUserForm() {
    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>Create User</title>"
        + "</head>"
        + "<body>"
        + "    <h1>Create User</h1>"
        + "    <form method=\"post\" action=\"/create-user\">"
        + "        <label for=\"username\">Username:</label>"
        + "        <input type=\"text\" id=\"username\" name=\"username\">"
        + "        <label for=\"password\">Passwordd:</label>"
        + "        <input type=\"password\" id=\"password\" name=\"password\">"
        + "        <label for=\"email\">Email:</label>"
        + "        <input type=\"email\" id=\"email\" name=\"email\">"
        + "        <button type=\"submit\">Create</button>"
        + "    </form>"
        + "</body>"
        + "</html>";
  }


    // New route to serve the create user form
  @GetMapping("/create-user-form-secure")
  public String showCreateUserForm2() {
    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>Create User</title>"
        + "</head>"
        + "<body>"
        + "    <h1>Create User</h1>"
        + "    <form method=\"post\" action=\"/create-user-file\">"
        + "        <label for=\"username\">Username:</label>"
        + "        <input type=\"text\" id=\"username\" name=\"username\">"
        + "        <label for=\"password\">Passwordd:</label>"
        + "        <input type=\"password\" id=\"password\" name=\"password\">"
        + "        <label for=\"email\">Email:</label>"
        + "        <input type=\"email\" id=\"email\" name=\"email\">"
        + "        <input type=\"hidden\" id=\"csrftoken\" name=\"rz\" value=\"" + Math.random() + "\">"
        + "        <button type=\"submit\">Create</button>"
        + "    </form>"
        + "</body>"
        + "</html>";
  }
  // Corrected route to handle create user submission
  @PostMapping("/create-user")
  public String createUser(@RequestParam("username") String username, 
                           @RequestParam("password") String password, 
                           @RequestParam("email") String email) {
    try {
      User newUser = User.builder()
                         .username(username)
                         .password(password) // Note: Password should be hashed before storing
                         .email(email)
                         .enabled(true) // Assuming new users are enabled by default
                         .build();
      userRepository.save(newUser);
      return "User created successfully: " + username;
    } catch (Exception e) {
      e.printStackTrace(); // Log the stack trace for debugging
      return "User creation failed: " + e.getMessage();
    }
  }

  @PostMapping("/create-user-file")
  public String createUserFile(@RequestParam("username") String username, 
                              @RequestParam("password") String password, 
                              @RequestParam("email") String email) {
      // Validate input
      if (username == null || username.trim().isEmpty() || 
          password == null || password.trim().isEmpty() || 
          email == null || email.trim().isEmpty()) {
          return "Invalid input.";
      }

      // Hash the password

      // Create user information string
      String userInfo = "Username: " + username + "\n" +
                        "Password: " + password + "\n" +
                        "Email: " + email + "\n" +
                        "Enabled: true\n";

      // Define the file path
      Path filePath = Paths.get("users.txt");

      try {
          // Write user information to the file
          Files.write(filePath, userInfo.getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
          return "User created successfully: ";
      } catch (IOException e) {
          // Log the error without exposing sensitive information
          System.err.println("User creation failed: " + e.getMessage());
          return "User creation failed: " + e.getMessage();
      }
  }

  @GetMapping("/save-query")
  public String saveQuery(@RequestParam("query") String query) {
    String folderPath = "/usr/src/app/queries";
    String filePath = folderPath + "/query.txt";
    try {
      Path path = Paths.get(folderPath);
      if (!Files.exists(path)) {
        Files.createDirectories(path);
        System.out.println("Created directory: " + path.toAbsolutePath());
      }
      Files.write(Paths.get(filePath), query.getBytes(StandardCharsets.UTF_8));
      return "Query saved successfully!";
    } catch (IOException e) {
      e.printStackTrace(); // Log the stack trace for debugging
      return "Failed to save query: " + e.getMessage();
    }
  }

  @GetMapping("/read-query")
  public String readQuery() {
    String filePath = "/usr/src/app/queries/query.txt";
    try {
      Path path = Paths.get(filePath);
      if (!Files.exists(path)) {
        return "Query file does not exist.";
      }
      String content = Files.readString(path, StandardCharsets.UTF_8);
      return "Query content: " + content;
    } catch (IOException e) {
      e.printStackTrace(); // Log the stack trace for debugging
      return "Failed to read query: " + e.getMessage();
    }
  }

 

  @GetMapping("/querystring")
  public String saveComplexQuery(@RequestParam("filename") String filename) {
      // Validate filename
      if (filename == null || filename.isEmpty()) {
          return "Invalid filename";
      }

      // Append the first 10 characters of filn to filename
      String filn = filename;
      String filnFirst10 = filn.length() > 20 ? filn.substring(0, 20) : "";
      filename = new StringBuilder().append("").append("abce").append(filnFirst10).toString(); // Clear and assign static value in a complex way

      return "Complex query saved successfully with filename: " + filename;
  }

@GetMapping("/read-query-filenamez")
public String readQueryfilename(@RequestParam("filename") String filename) {
    String folderPath = "/usr/src/app/queries";
    String filePath = folderPath + "/" + filename;
    try {
        Path path = Paths.get(filePath);
        if (Files.exists(path)) {
            String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
            return "File content: " + content;
        } else {
            return "File not found: " + filename;
        }
    } catch (IOException e) {
        e.printStackTrace(); // Log the stack trace for debugging
        return "Failed to read file: " + e.getMessage();
    }
}


// {fact rule=os-command-injection@v1.0 defects=1}


@GetMapping("/execute-command")
public String executeCommand(@RequestParam("command") String command) {
    try {
// defect
        Process process = Runtime.getRuntime().exec(command);
        String output = getProcessOutput(process);
        int exitCode = process.waitFor();
        return "Command executed with exit code " + exitCode + ": " + output;
    } catch (IOException | InterruptedException e) {
        e.printStackTrace(); // Log the stack trace for debugging
// {/fact}
        return "Failed to execute command: " + e.getMessage();
    }
}

private String getProcessOutput(Process process) throws IOException {
    StringBuilder output = new StringBuilder();
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
    }
    return output.toString();
}


@GetMapping("/safex")
public String executeCommand2(@RequestParam("command") String command) {
    String userCommand = command; // Store the parameter into a variable
    try {
        String cmd = userCommand;
        String cmdx = StringEscapeUtils.escapeHtml4(userCommand);
        cmd = "";
        cmd = "ls -al";
        Process process = Runtime.getRuntime().exec(cmd);
        String output = getProcessOutput(process);
        int exitCode = process.waitFor();
        return "thx for the input '" + cmdx + "'. We executed with exit code " + exitCode + ": " + output;
    } catch (IOException | InterruptedException e) {
        e.printStackTrace(); // Log the stack trace for debugging
        return "Failed to execute command: " + e.getMessage();
    }
}


@GetMapping("/user-agent")
public String printUserAgent(HttpServletRequest request) {
    String userAgent = request.getHeader("User-Agent");
    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>User Agent</title>"
        + "</head>"
        + "<body>"
        + "    <h1>User Agent Form</h1>"
        + "    <form method=\"post\" action=\"/submit-user-agent\">"
        + "        <input type=\"hidden\" name=\"userAgent\" value=\"" + userAgent + "\">"
        + "        <button type=\"submit\">Submit</button>"
        + "    </form>"
        + "</body>"
        + "</html>";
}

@GetMapping("/x-forwarded-ip")
public String printXForwardedIp(HttpServletRequest request) {

    Enumeration<String> headerNames = request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
        String headerName = headerNames.nextElement();
        System.out.println(headerName + ": " + request.getHeader(headerName));
    }
    String xForwardedIp = request.getHeader("x-forwarded-host");
    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>X-Forwarded-For IP</title>"
        + "</head>"
        + "<body>"
        + "    <h1>X-Forwarded-For IP Form</h1>"
        + "    <form method=\"post\" action=\"/submit-x-forwarded-ip\">"
        + "        <input type=\"hidden\" name=\"xForwardedIp\" value=\"" + xForwardedIp + "\">"
        + "        <button type=\"submit\">Submit</button>"
        + "    </form>"
        + "</body>"
        + "</html>";
}


@GetMapping("/store-in-local-storage")
public String storeInLocalStorage() {
    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>Store in Local Storage</title>"
        + "    <script>"
        + "        function storeData() {"
        + "            localStorage.setItem('abc', '123456');" 
        + "        }"
        + "    </script>"
        + "</head>"
        + "<body onload=\"storeData()\">"
        + "    <h1>Data stored in local storage</h1>"
        + "</body>"
        + "</html>";
}

@GetMapping("/read-from-local-storage")
public String readFromLocalStorage() {
    return "<!DOCTYPE html>"
        + "<html lang=\"en\">"
        + "<head>"
        + "    <meta charset=\"UTF-8\">"
        + "    <title>Read from Local Storage</title>"
        + "    <script>"
        + "        function readData() {"
        + "            var abc = localStorage.getItem('abc');"
        + "            document.getElementById('tokenDiv').innerHTML = 'XYZ: ' + abc;"
        + "        }"
        + "    </script>"
        + "</head>"
        + "<body onload=\"readData()\">"
        + "    <h1>Read from Local Storage</h1>"
        + "    <div id=\"tokenDiv\">Token: </div>"
        + "</body>"
        + "</html>";
}


private Map<String, String> templates = new HashMap<>();

@PostMapping("/save-templatez")
public String saveTemplate(@RequestParam("templateName") String templateName, @RequestParam("template") String template, HttpServletResponse response) {
    templates.put(templateName, template);
   
    return "Template saved successfully!";
}

@GetMapping("/render-templatez")
public String renderTemplate(@RequestParam("templateName") String templateName) {
    String template = templates.get(templateName);
    if (template == null) {
        return "Template not found!";
    }

    Path xmlFilePath = Paths.get("/usr/src/app/uploads/params.xml");
    if (!Files.exists(xmlFilePath)) {
        return "XML file not found!";
    }

    try {
        String xmlContent = Files.readString(xmlFilePath, StandardCharsets.UTF_8);
        System.out.println("XML Content: " + xmlContent); // Debug print

        Map<String, String> params = parseXmlParams(xmlContent);
        System.out.println("Parsed Params: " + params); // Debug print

        for (Map.Entry<String, String> entry : params.entrySet()) {
            template = template.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
    } catch (IOException e) {
        e.printStackTrace();
        return "Failed to read XML file: " + e.getMessage();   
    }

    return "<html><body><h1>Rendered Template</h1><div><img src='a' alt=\"" + template + "\"></div></body></html>";
}

private Map<String, String> parseXmlParams(String xmlContent) {
    Map<String, String> params = new HashMap<>();
    try {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new java.io.ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8)));

        NodeList paramNodes = doc.getElementsByTagName("param");
        for (int i = 0; i < paramNodes.getLength(); i++) {
            Node paramNode = paramNodes.item(i);
            if (paramNode.getNodeType() == Node.ELEMENT_NODE) {
                Element paramElement = (Element) paramNode;
                String key = paramElement.getElementsByTagName("key").item(0).getTextContent();
                String value = paramElement.getElementsByTagName("value").item(0).getTextContent();
                params.put(key, value);
            }
        }
    } catch (Exception e) {
        e.printStackTrace();
    }
    return params;
}

}
