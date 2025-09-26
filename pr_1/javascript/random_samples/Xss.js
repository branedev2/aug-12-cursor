//{fact rule=cross-site-scripting@v1.0 defects=1}

function setLanguageOptions() {
    var href = document.location.href,
        deflt = href.substring(href.indexOf("default=")+8);
    document.write("<OPTION value=1>"+deflt+"</OPTION>");
    document.write("<OPTION value=2>English</OPTION>");
}

//{/fact}