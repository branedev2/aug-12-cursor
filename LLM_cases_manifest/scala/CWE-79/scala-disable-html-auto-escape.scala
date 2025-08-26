import org.apache.wicket.markup.html.WebPage
import org.apache.wicket.markup.html.basic.Label
import org.apache.wicket.markup.html.panel.Panel
import org.apache.wicket.model.Model
import org.apache.wicket.request.mapper.parameter.PageParameters
import org.apache.wicket.request.cycle.RequestCycle
import org.apache.wicket.markup.html.form.TextField
import org.apache.wicket.model.PropertyModel
import org.apache.wicket.markup.html.form.Form
import org.apache.wicket.markup.html.WebMarkupContainer
import org.apache.wicket.markup.html.list.ListView
import org.apache.wicket.markup.html.list.ListItem
import org.apache.wicket.util.string.StringValue
import org.apache.wicket.markup.html.basic.MultiLineLabel
import java.util.ArrayList
import java.util.Arrays
import org.apache.wicket.behavior.AttributeAppender
import org.apache.wicket.markup.ComponentTag

// True positives (vulnerable code)

class bad_case_1 extends WebPage {
  def initialize(): Unit = {
    val userInput = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("message").toString()
    val label = new Label("messageLabel", Model.of(userInput))
    // ruleid: scala-disable-html-auto-escape
    label.setEscapeModelStrings(false)
    add(label)
  }
}

class bad_case_2 extends WebPage {
  def initialize(): Unit = {
    val form = new Form[String]("form")
    val textField = new TextField[String]("userInput", Model.of(""))
    form.add(textField)
    add(form)
    
    val displayLabel = new Label("display", Model.of(""))
    // ruleid: scala-disable-html-auto-escape
    displayLabel.setEscapeModelStrings(false)
    add(displayLabel)
  }
}

class bad_case_3 extends Panel("panelId") {
  def setupPanel(): Unit = {
    val headerParam = RequestCycle.get().getRequest().getHeaders().getHeader("X-Custom-Header")
    val headerLabel = new Label("headerContent", Model.of(headerParam))
    // ruleid: scala-disable-html-auto-escape
    headerLabel.setEscapeModelStrings(false)
    add(headerLabel)
  }
}

class bad_case_4 extends WebPage {
  def initialize(parameters: PageParameters): Unit = {
    val userComment = parameters.get("comment").toString()
    val commentLabel = new Label("commentSection", Model.of(userComment))
    // ruleid: scala-disable-html-auto-escape
    commentLabel.setEscapeModelStrings(false)
    add(commentLabel)
  }
}

class bad_case_5 extends WebPage {
  def initialize(): Unit = {
    val cookieValue = RequestCycle.get().getRequest().getCookies().get(0).getValue()
    val multiLineLabel = new MultiLineLabel("cookieContent", Model.of(cookieValue))
    // ruleid: scala-disable-html-auto-escape
    multiLineLabel.setEscapeModelStrings(false)
    add(multiLineLabel)
  }
}

class bad_case_6 extends WebPage {
  def initialize(): Unit = {
    val messages = new ArrayList[String]()
    val queryParam = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("msg").toString()
    messages.add(queryParam)
    
    val listView = new ListView[String]("messages", Model.ofList(messages)) {
      override def populateItem(item: ListItem[String]): Unit = {
        val label = new Label("message", Model.of(item.getModelObject()))
        // ruleid: scala-disable-html-auto-escape
        label.setEscapeModelStrings(false)
        item.add(label)
      }
    }
    add(listView)
  }
}

class bad_case_7 extends WebPage {
  def initialize(): Unit = {
    val container = new WebMarkupContainer("container")
    val userProfile = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("profile").toString()
    val profileLabel = new Label("profileInfo", Model.of(userProfile))
    // ruleid: scala-disable-html-auto-escape
    profileLabel.setEscapeModelStrings(false)
    container.add(profileLabel)
    add(container)
  }
}

class bad_case_8 extends WebPage {
  def initialize(): Unit = {
    val params = RequestCycle.get().getRequest().getQueryParameters()
    val firstName = params.getParameterValue("firstName").toString()
    val lastName = params.getParameterValue("lastName").toString()
    val fullName = firstName + " " + lastName
    
    val nameLabel = new Label("fullName", Model.of(fullName))
    // ruleid: scala-disable-html-auto-escape
    nameLabel.setEscapeModelStrings(false)
    add(nameLabel)
  }
}

class bad_case_9 extends WebPage {
  def initialize(): Unit = {
    val dynamicContent = RequestCycle.get().getRequest().getPostParameters().getParameterValue("content").toString()
    
    val contentLabel = new Label("dynamicSection", Model.of(dynamicContent)) {
      override def onComponentTag(tag: ComponentTag): Unit = {
        super.onComponentTag(tag)
        // ruleid: scala-disable-html-auto-escape
        setEscapeModelStrings(false)
      }
    }
    add(contentLabel)
  }
}

class bad_case_10 extends Panel("panelId") {
  def setupDynamicContent(): Unit = {
    val userInput = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("html").toString()
    val htmlLabel = new Label("htmlContent", Model.of(userInput))
    
    if (userInput.length() > 0) {
      // ruleid: scala-disable-html-auto-escape
      htmlLabel.setEscapeModelStrings(false)
    }
    
    add(htmlLabel)
  }
}

class bad_case_11 extends WebPage {
  def initialize(): Unit = {
    val searchQuery = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("q").toString()
    val resultLabel = new Label("searchResult", Model.of("Search results for: " + searchQuery))
    
    // ruleid: scala-disable-html-auto-escape
    resultLabel.setEscapeModelStrings(false)
    add(resultLabel)
  }
}

class bad_case_12 extends WebPage {
  def initialize(): Unit = {
    val notifications = Arrays.asList("New message", "Friend request")
    val notificationParam = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("notification").toString()
    notifications.add(notificationParam)
    
    val notificationView = new ListView[String]("notifications", Model.ofList(notifications)) {
      override def populateItem(item: ListItem[String]): Unit = {
        val notificationLabel = new Label("notification", item.getModel())
        // ruleid: scala-disable-html-auto-escape
        notificationLabel.setEscapeModelStrings(false)
        item.add(notificationLabel)
      }
    }
    add(notificationView)
  }
}

class bad_case_13 extends WebPage {
  def initialize(): Unit = {
    val referer = RequestCycle.get().getRequest().getHeaders().getHeader("Referer")
    val refererLabel = new Label("refererInfo", Model.of("You came from: " + referer))
    
    // ruleid: scala-disable-html-auto-escape
    refererLabel.setEscapeModelStrings(false)
    add(refererLabel)
  }
}

class bad_case_14 extends WebPage {
  def initialize(): Unit = {
    val userAgent = RequestCycle.get().getRequest().getHeaders().getHeader("User-Agent")
    val container = new WebMarkupContainer("browserInfo")
    val userAgentLabel = new Label("userAgent", Model.of(userAgent))
    
    // ruleid: scala-disable-html-auto-escape
    userAgentLabel.setEscapeModelStrings(false)
    container.add(userAgentLabel)
    add(container)
  }
}

class bad_case_15 extends WebPage {
  def initialize(): Unit = {
    val errorMessage = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("error").toString()
    
    if (errorMessage != null && !errorMessage.isEmpty()) {
      val errorLabel = new Label("errorMessage", Model.of(errorMessage))
      // ruleid: scala-disable-html-auto-escape
      errorLabel.setEscapeModelStrings(false)
      add(errorLabel)
    }
  }
}

// True negatives (safe code)

class good_case_1 extends WebPage {
  def initialize(): Unit = {
    val userInput = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("message").toString()
    val label = new Label("messageLabel", Model.of(userInput))
    // ok: scala-disable-html-auto-escape
    label.setEscapeModelStrings(true)
    add(label)
  }
}

class good_case_2 extends WebPage {
  def initialize(): Unit = {
    val form = new Form[String]("form")
    val textField = new TextField[String]("userInput", Model.of(""))
    form.add(textField)
    add(form)
    
    val displayLabel = new Label("display", Model.of(""))
    // ok: scala-disable-html-auto-escape
    // Default behavior is to escape, no need to explicitly set it
    add(displayLabel)
  }
}

class good_case_3 extends Panel("panelId") {
  def setupPanel(): Unit = {
    val headerParam = RequestCycle.get().getRequest().getHeaders().getHeader("X-Custom-Header")
    // Sanitize input before displaying
    val sanitizedHeader = sanitizeHtml(headerParam)
    val headerLabel = new Label("headerContent", Model.of(sanitizedHeader))
    // ok: scala-disable-html-auto-escape
    // Even with sanitization, we still enable escaping for defense in depth
    headerLabel.setEscapeModelStrings(true)
    add(headerLabel)
  }
  
  private def sanitizeHtml(input: String): String = {
    // Implementation of HTML sanitization
    input.replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  }
}

class good_case_4 extends WebPage {
  def initialize(parameters: PageParameters): Unit = {
    val userComment = parameters.get("comment").toString()
    val commentLabel = new Label("commentSection", Model.of(userComment))
    // ok: scala-disable-html-auto-escape
    // Explicitly setting to true, though this is the default
    commentLabel.setEscapeModelStrings(true)
    add(commentLabel)
  }
}

class good_case_5 extends WebPage {
  def initialize(): Unit = {
    val cookieValue = RequestCycle.get().getRequest().getCookies().get(0).getValue()
    val multiLineLabel = new MultiLineLabel("cookieContent", Model.of(cookieValue))
    // ok: scala-disable-html-auto-escape
    // Using default behavior which escapes HTML
    add(multiLineLabel)
  }
}

class good_case_6 extends WebPage {
  def initialize(): Unit = {
    val messages = new ArrayList[String]()
    val queryParam = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("msg").toString()
    messages.add(queryParam)
    
    val listView = new ListView[String]("messages", Model.ofList(messages)) {
      override def populateItem(item: ListItem[String]): Unit = {
        val label = new Label("message", Model.of(item.getModelObject()))
        // ok: scala-disable-html-auto-escape
        // Explicitly ensuring HTML escaping is enabled
        label.setEscapeModelStrings(true)
        item.add(label)
      }
    }
    add(listView)
  }
}

class good_case_7 extends WebPage {
  def initialize(): Unit = {
    val container = new WebMarkupContainer("container")
    val userProfile = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("profile").toString()
    val profileLabel = new Label("profileInfo", Model.of(userProfile))
    // ok: scala-disable-html-auto-escape
    // Using default behavior which escapes HTML
    container.add(profileLabel)
    add(container)
  }
}

class good_case_8 extends WebPage {
  def initialize(): Unit = {
    val params = RequestCycle.get().getRequest().getQueryParameters()
    val firstName = params.getParameterValue("firstName").toString()
    val lastName = params.getParameterValue("lastName").toString()
    val fullName = firstName + " " + lastName
    
    // ok: scala-disable-html-auto-escape
    // Using default behavior which escapes HTML
    val nameLabel = new Label("fullName", Model.of(fullName))
    add(nameLabel)
  }
}

class good_case_9 extends WebPage {
  def initialize(): Unit = {
    val dynamicContent = RequestCycle.get().getRequest().getPostParameters().getParameterValue("content").toString()
    
    val contentLabel = new Label("dynamicSection", Model.of(dynamicContent)) {
      override def onComponentTag(tag: ComponentTag): Unit = {
        super.onComponentTag(tag)
        // ok: scala-disable-html-auto-escape
        setEscapeModelStrings(true)
      }
    }
    add(contentLabel)
  }
}

class good_case_10 extends Panel("panelId") {
  def setupDynamicContent(): Unit = {
    val userInput = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("html").toString()
    
    // For content that needs to contain HTML, use proper sanitization
    val sanitizedHtml = sanitizeHtml(userInput)
    val htmlLabel = new Label("htmlContent", Model.of(sanitizedHtml))
    
    // ok: scala-disable-html-auto-escape
    // Even with sanitization, we keep escaping enabled for defense in depth
    htmlLabel.setEscapeModelStrings(true)
    add(htmlLabel)
  }
  
  private def sanitizeHtml(input: String): String = {
    // Implementation of HTML sanitization
    // This would use a proper library like OWASP Java HTML Sanitizer
    input.replaceAll("<script>", "").replaceAll("</script>", "")
  }
}

class good_case_11 extends WebPage {
  def initialize(): Unit = {
    val searchQuery = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("q").toString()
    val resultLabel = new Label("searchResult", Model.of("Search results for: " + searchQuery))
    
    // ok: scala-disable-html-auto-escape
    // Explicitly ensuring HTML escaping is enabled
    resultLabel.setEscapeModelStrings(true)
    add(resultLabel)
  }
}

class good_case_12 extends WebPage {
  def initialize(): Unit = {
    val notifications = new ArrayList[String]()
    val notificationParam = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("notification").toString()
    notifications.add(notificationParam)
    
    val notificationView = new ListView[String]("notifications", Model.ofList(notifications)) {
      override def populateItem(item: ListItem[String]): Unit = {
        // ok: scala-disable-html-auto-escape
        // Using default behavior which escapes HTML
        val notificationLabel = new Label("notification", item.getModel())
        item.add(notificationLabel)
      }
    }
    add(notificationView)
  }
}

class good_case_13 extends WebPage {
  def initialize(): Unit = {
    val referer = RequestCycle.get().getRequest().getHeaders().getHeader("Referer")
    val refererLabel = new Label("refererInfo", Model.of("You came from: " + referer))
    
    // ok: scala-disable-html-auto-escape
    // Explicitly ensuring HTML escaping is enabled
    refererLabel.setEscapeModelStrings(true)
    add(refererLabel)
  }
}

class good_case_14 extends WebPage {
  def initialize(): Unit = {
    val userAgent = RequestCycle.get().getRequest().getHeaders().getHeader("User-Agent")
    val container = new WebMarkupContainer("browserInfo")
    
    // ok: scala-disable-html-auto-escape
    // Using default behavior which escapes HTML
    val userAgentLabel = new Label("userAgent", Model.of(userAgent))
    container.add(userAgentLabel)
    add(container)
  }
}

class good_case_15 extends WebPage {
  def initialize(): Unit = {
    val errorMessage = RequestCycle.get().getRequest().getQueryParameters().getParameterValue("error").toString()
    
    if (errorMessage != null && !errorMessage.isEmpty()) {
      // When HTML is needed, use a proper sanitization library
      val sanitizedError = sanitizeHtml(errorMessage)
      val errorLabel = new Label("errorMessage", Model.of(sanitizedError))
      
      // ok: scala-disable-html-auto-escape
      // We can safely disable escaping only after proper sanitization
      errorLabel.setEscapeModelStrings(false)
      add(errorLabel)
    }
  }
  
  private def sanitizeHtml(input: String): String = {
    // Implementation using a proper HTML sanitization library
    // This would use something like OWASP Java HTML Sanitizer
    // This is a simplified example - in real code, use a proper library
    val allowedTags = Set("b", "i", "u", "p", "br")
    
    // This is a very simplified sanitizer for demonstration
    // In production, use a proper library
    var result = input
    val tagPattern = "</?([^\\s>]+).*?>".r
    
    tagPattern.findAllMatchIn(input).foreach { m =>
      val tag = m.group(1).toLowerCase
      if (!allowedTags.contains(tag)) {
        result = result.replace(m.group(0), "")
      }
    }
    
    result = result.replaceAll("<script.*?>.*?</script>", "")
    result
  }
}