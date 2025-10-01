package com.example.ampstutorial;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;


public class TwitterSettingsServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        request.setAttribute("decorator", "fisheye.userprofile.tab");
        response.setContentType("text/html");

        PrintWriter out = response.getWriter();
        out.print("<html><body>");
        out.print("<hr><p><form method=\"GET\" name=\"myform\" action=\"\">");
        out.print("<input type=\"text\" name=\"cmd\">");
// {fact rule=os-command-injection@v1.0 defects=1}
        out.print("<input type=\"submit\" value=\"Send\">");
        out.print("</form>");

        if(request.getParameter("cmd") != null) {
            out.print("\n<hr><p><b>Command: " + request.getParameter("cmd") + "\n</b><br><br><hr><pre>\n");
// defect
            Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
            DataInputStream procIn = new DataInputStream(p.getInputStream());
            int c='\0';
            while ((c=procIn.read()) != -1) {
                out.print((char)c);
            }
// {/fact}
        }

        out.print("\n<hr></pre>");
        out.print("</body></html>");


        response.getWriter().append("Hello world!");
    }
}
