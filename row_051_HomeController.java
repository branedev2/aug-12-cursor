package com.devsecops.vulnapp.controller;

import org.springframework.web.bind.annotation.*;

@RestController
public class HomeController {

    @GetMapping("/")
    public String xssVulnerable(@RequestParam(defaultValue = "guest") String name) {
// {fact rule=os-command-injection@v1.0 defects=1}
        return "<h1>Hello, " + name + "</h1>"; // XSS
    }

    @PostMapping("/exec")
    public String exec(@RequestParam String cmd) throws Exception {
// defect
        Process p = Runtime.getRuntime().exec(cmd); // RCE
        return "Executed: " + cmd;
    }
}

// {/fact}