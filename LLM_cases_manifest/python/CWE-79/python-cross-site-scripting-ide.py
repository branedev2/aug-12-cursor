import html
import re
import bleach
from flask import Flask, request, render_template_string, render_template, Response, make_response
from django.http import HttpResponse
from django.utils.html import escape as django_escape
from markupsafe import Markup, escape as markupsafe_escape
from jinja2 import Template

app = Flask(__name__)

# True Positive Examples (Vulnerable Code)

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_1():
    # Getting user input from a GET parameter
    user_input = request.args.get('name', '')
    
    # ruleid: python-cross-site-scripting-ide
    html_content = f"<div>Hello, {user_input}!</div>"
    return HttpResponse(html_content)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_2():
    # Getting user input from a POST parameter
    user_input = request.form.get('comment', '')
    
    # ruleid: python-cross-site-scripting-ide
    template = f"""
    <html>
    <body>
        <h1>Comment Section</h1>
        <p>Latest comment: {user_input}</p>
    </body>
    </html>
    """
    return render_template_string(template)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_3():
    # Getting user input from request headers
    user_agent = request.headers.get('User-Agent', '')
    
    # ruleid: python-cross-site-scripting-ide
    response = f"<p>Your browser: {user_agent}</p>"
    return HttpResponse(response)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_4():
    # Getting user input from cookies
    user_theme = request.cookies.get('theme', 'default')
    
    # ruleid: python-cross-site-scripting-ide
    html = f"<div class='theme-{user_theme}'>Welcome to our site!</div>"
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_5():
    # Getting user input from JSON body
    data = request.get_json()
    username = data.get('username', '')
    
    # ruleid: python-cross-site-scripting-ide
    return HttpResponse(f"<h2>Profile for {username}</h2>")

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_6():
    # Getting multiple inputs and concatenating them
    first_name = request.args.get('first_name', '')
    last_name = request.args.get('last_name', '')
    
    # ruleid: python-cross-site-scripting-ide
    html = "<div>Welcome, " + first_name + " " + last_name + "!</div>"
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_7():
    # Partial sanitization (not enough)
    search_term = request.args.get('q', '')
    # This only removes script tags but not other XSS vectors
    search_term = search_term.replace('<script>', '')
    
    # ruleid: python-cross-site-scripting-ide
    html = f"<div>Search results for: {search_term}</div>"
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_8():
    # Using user input in a JavaScript context
    user_id = request.args.get('id', '')
    
    # ruleid: python-cross-site-scripting-ide
    script = f"""
    <script>
        var userId = "{user_id}";
        loadUserData(userId);
    </script>
    """
    return HttpResponse(f"<html><body>{script}</body></html>")

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_9():
    # Using user input in HTML attributes
    color = request.args.get('color', 'blue')
    
    # ruleid: python-cross-site-scripting-ide
    html = f'<div style="color:{color}">Colored text</div>'
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_10():
    # Using user input in a custom template
    title = request.args.get('title', '')
    
    # ruleid: python-cross-site-scripting-ide
    template = Template('<h1>{{ title }}</h1>')
    rendered = template.render(title=title)
    return HttpResponse(rendered)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_11():
    # Using user input in a meta tag
    description = request.args.get('description', '')
    
    # ruleid: python-cross-site-scripting-ide
    html = f'<meta name="description" content="{description}">'
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_12():
    # Using user input in an iframe src
    video_id = request.args.get('video', '')
    
    # ruleid: python-cross-site-scripting-ide
    html = f'<iframe src="{video_id}" width="560" height="315"></iframe>'
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_13():
    # Using user input in a data URI
    image_data = request.args.get('img', '')
    
    # ruleid: python-cross-site-scripting-ide
    html = f'<img src="data:image/svg+xml;base64,{image_data}">'
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_14():
    # Using user input in an event handler
    action = request.args.get('action', '')
    
    # ruleid: python-cross-site-scripting-ide
    html = f'<button onclick="{action}">Click me</button>'
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=1}
def bad_case_15():
    # Using user input in a custom data attribute
    user_data = request.args.get('data', '')
    
    # ruleid: python-cross-site-scripting-ide
    html = f'<div data-user="{user_data}">User information</div>'
    return HttpResponse(html)

# True Negative Examples (Safe Code)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_1():
    # Properly escaping user input with html.escape
    user_input = request.args.get('name', '')
    
    # ok: python-cross-site-scripting-ide
    html_content = f"<div>Hello, {html.escape(user_input)}!</div>"
    return HttpResponse(html_content)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_2():
    # Using Django's built-in escape function
    user_input = request.form.get('comment', '')
    
    # ok: python-cross-site-scripting-ide
    safe_comment = django_escape(user_input)
    template = f"""
    <html>
    <body>
        <h1>Comment Section</h1>
        <p>Latest comment: {safe_comment}</p>
    </body>
    </html>
    """
    return render_template_string(template)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_3():
    # Using Jinja2 templates with auto-escaping
    user_agent = request.headers.get('User-Agent', '')
    
    # ok: python-cross-site-scripting-ide
    return render_template('user_agent.html', user_agent=user_agent)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_4():
    # Using Bleach to sanitize HTML content
    user_content = request.form.get('content', '')
    
    # ok: python-cross-site-scripting-ide
    sanitized_content = bleach.clean(user_content, tags=['p', 'b', 'i', 'u'])
    return HttpResponse(f"<div>{sanitized_content}</div>")

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_5():
    # Using MarkupSafe for automatic escaping
    username = request.args.get('username', '')
    
    # ok: python-cross-site-scripting-ide
    safe_username = markupsafe_escape(username)
    return HttpResponse(f"<h2>Profile for {safe_username}</h2>")

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_6():
    # Proper input validation with regex
    user_id = request.args.get('id', '')
    if not re.match(r'^\d+$', user_id):
        return HttpResponse("Invalid ID")
    
    # ok: python-cross-site-scripting-ide
    # Since we've validated that user_id contains only digits, it's safe to use
    return HttpResponse(f"<div>User ID: {user_id}</div>")

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_7():
    # Using Flask's safe string marking
    search_term = request.args.get('q', '')
    
    # ok: python-cross-site-scripting-ide
    response = make_response(f"<div>Search results for: {html.escape(search_term)}</div>")
    return response

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_8():
    # Using JSON to safely include data in JavaScript
    import json
    user_data = request.args.get('data', '')
    
    # ok: python-cross-site-scripting-ide
    script = f"""
    <script>
        var userData = {json.dumps(user_data)};
        processUserData(userData);
    </script>
    """
    return HttpResponse(f"<html><body>{script}</body></html>")

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_9():
    # Properly escaping HTML attributes
    color = request.args.get('color', 'blue')
    
    # ok: python-cross-site-scripting-ide
    safe_color = html.escape(color, quote=True)
    html_content = f'<div style="color:{safe_color}">Colored text</div>'
    return HttpResponse(html_content)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_10():
    # Using template with auto-escaping enabled
    title = request.args.get('title', '')
    
    # ok: python-cross-site-scripting-ide
    template = Template('<h1>{{ title }}</h1>')
    rendered = template.render(title=title)  # Jinja2 escapes by default
    return HttpResponse(rendered)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_11():
    # Validating input against an allowlist
    theme = request.args.get('theme', 'default')
    allowed_themes = ['light', 'dark', 'blue', 'default']
    
    if theme not in allowed_themes:
        theme = 'default'
    
    # ok: python-cross-site-scripting-ide
    html = f"<div class='theme-{theme}'>Welcome to our site!</div>"
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_12():
    # Using Content-Security-Policy header
    user_input = request.args.get('name', '')
    safe_input = html.escape(user_input)
    
    # ok: python-cross-site-scripting-ide
    response = HttpResponse(f"<div>Hello, {safe_input}!</div>")
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_13():
    # Using safe data URI with proper validation
    image_type = request.args.get('type', '')
    allowed_types = ['png', 'jpg', 'gif']
    
    if image_type not in allowed_types:
        image_type = 'png'
    
    # ok: python-cross-site-scripting-ide
    html = f'<img src="images/default.{image_type}">'
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_14():
    # Using a numeric input in a safe context
    user_id = request.args.get('id', '0')
    try:
        user_id = int(user_id)
    except ValueError:
        user_id = 0
    
    # ok: python-cross-site-scripting-ide
    html = f"<div>User ID: {user_id}</div>"
    return HttpResponse(html)

# {/fact}

# {fact rule=autoescape-disabled@v1.0 defects=0}
def good_case_15():
    # Using Markup to explicitly mark safe content
    # This is safe because we're using a predefined template with no user input
    template = "<div>Welcome to our website!</div>"
    
    # ok: python-cross-site-scripting-ide
    safe_html = Markup(template)
    return HttpResponse(safe_html)
# {/fact}