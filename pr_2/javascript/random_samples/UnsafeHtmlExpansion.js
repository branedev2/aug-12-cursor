//{fact rule=autoescape-disabled@v1.0 defects=1}

function expandSelfClosingTags(html) {
	var rxhtmlTag = /<(?!img|area)(([a-z][^\w\/>]*)[^>]*)\/>/gi;
	return html.replace(rxhtmlTag, "<$1></$2>"); // BAD
}


//{/fact}