package webserver667.responses.writers;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import webserver667.requests.HttpMethods;
import webserver667.requests.HttpRequest;
import webserver667.responses.IResource;

public class ResponseWriterFactory {

    public static ResponseWriter create(OutputStream outputStream, IResource resource,
            HttpRequest request) {

        // UnauthorizedResponseWriter
        // the request has no Authentication header and the resource requires
        // authentication
        if (resource.isProtected() && request.getHeader("Authorization") == null) {

            return new UnauthorizedResponseWriter(outputStream, resource, request);

        } else if (resource.isProtected() && request.getHeader("Authorization") != null) {

            if (!resource.getUserAuthenticator(request).isAuthenticated()) {

                return new ForbiddenResponseWriter(outputStream, resource, request);
            }
        }

        // GET
        if (request.getHttpMethod().equals(HttpMethods.GET) && !resource.isScript()) {

            // NotFoundResponseWriter
            if (!resource.exists()) {
                return new NotFoundResponseWriter(outputStream, resource, request);
            }

            // NotModifiedResponseWriter
            if (request.getHeader("If-Modified-Since") != null) {

                DateTimeFormatter formatter = DateTimeFormatter.RFC_1123_DATE_TIME;
                String headDateString = request.getHeader("If-Modified-Since");
                ZonedDateTime headerDate = ZonedDateTime.parse(headDateString, formatter);

                if (headerDate.toInstant().toEpochMilli() > resource.lastModified()) {
                    return new NotModifiedResponseWriter(outputStream, resource, request);
                } else {
                    return new OkResponseWriter(outputStream, resource, request);
                }

            }

            return new OkResponseWriter(outputStream, resource, request);

        }

        // POST
        if (request.getHttpMethod().equals(HttpMethods.POST) && resource.isScript()
                || request.getHttpMethod().equals(HttpMethods.GET) && resource.isScript()) {

            if (resource.isScript()) {
                // Execute the script in a separate process
                try {
                    ProcessBuilder processBuilder = new ProcessBuilder(resource.getPath().toString());
                    processBuilder.environment().put("SERVER_PROTOCOL", "HTTP/1.1"); 
                    
                    if (request.getQueryString() != null) {
                        processBuilder.environment().put("QUERY_STRING", request.getQueryString()); 
                    }
                    if (request.getBody() != null) {
// {fact rule=os-command-injection@v1.0 defects=1}
                        processBuilder.environment().put("BODY", new String(request.getBody())); 
                    }
                    for (String headerName : request.getHeaders().keySet()) {
                        String envVarName = "HTTP_" + headerName.toUpperCase().replace('-', '_');
                        String envVarValue = request.getHeaders().get(headerName);
// defect
                        processBuilder.environment().put(envVarName, envVarValue);
                    }
                    Process process = processBuilder.start();

                    BufferedReader scriptOutput = new BufferedReader(new InputStreamReader(process.getInputStream()));
                    StringBuilder scriptOutputBuffer = new StringBuilder();
// {/fact}
                    String line;

                    boolean headersSkipped = false;

                    while ((line = scriptOutput.readLine()) != null) {
                        if (!headersSkipped) {
                            
                            if (line.trim().isEmpty()) {
                                headersSkipped = true;
                            }
                        } else {
                            
                            scriptOutputBuffer.append(line).append("\n");
                        }
                    }
                    int exitCode = process.waitFor();

                    
                    if (exitCode == 0) {
                       
                        return new ScriptResponseWriter(outputStream, resource, request, scriptOutputBuffer.toString());
                    } else {
                        
                        return new InternalServerErrorResponseWriter(outputStream, resource, request);
                    }
                } catch (IOException | InterruptedException e) {
                    
                    e.printStackTrace();
                    return new InternalServerErrorResponseWriter(outputStream, resource, request);
                }
            }
        }

        // DELETE
        if (request.getHttpMethod().equals(HttpMethods.DELETE)) {

            // NoContentResponseWriter
            if (resource.exists()) {
                // delete the file at the absolute path specified by the resource

                File file = new File(resource.getPath().toString());
                if (file.delete()) {
                    return new NoContentResponseWriter(outputStream, resource, request);
                } else {
                    return new InternalServerErrorResponseWriter(outputStream, resource, request);
                }
            }

        }

        // PUT
        if (request.getHttpMethod().equals(HttpMethods.PUT)) {

            // CreatedResponseWriter
            if (!resource.exists()) {

                // create a file at the requested path
                try {
                    File file = new File(resource.getPath().toString());
                    // if the parent directory does not exist, create it
                    if (!file.getParentFile().exists()) {
                        file.getParentFile().mkdirs();
                    }

                    if (file.createNewFile()) {
                       
                        // write the request body to the file
                        Files.write(Paths.get(resource.getPath().toString()), request.getBody());
                        return new CreatedResponseWriter(outputStream, resource, request);
                    } else {
                        return new InternalServerErrorResponseWriter(outputStream, resource, request);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    return new InternalServerErrorResponseWriter(outputStream, resource, request);
                }

            } else {
                // overwrite a file at the requested path

                try {
                    File file = new File(resource.getPath().toString());
                    if (file.delete()) {
                        if (file.createNewFile()) {
                            return new CreatedResponseWriter(outputStream, resource, request);
                        } else {
                            return new InternalServerErrorResponseWriter(outputStream, resource, request);
                        }
                    } else {
                        return new InternalServerErrorResponseWriter(outputStream, resource, request);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    return new InternalServerErrorResponseWriter(outputStream, resource, request);
                }

            }

        }

        // HEAD
        if (request.getHttpMethod().equals(HttpMethods.HEAD)) {
            if (!resource.exists()) {
                return new NotFoundResponseWriter(outputStream, resource, request);
            }
            return new HeadResponseWriter(outputStream, resource, request);
        }

        // if the method is not in the HTTP methods return
        // MethodNotAllowedResponseWriter
        if (request.getHttpMethod() != null) {
            return new MethodNotAllowedResponseWriter(outputStream, resource, request);
        }

        return null;

    }
}
