// {fact rule=cwe-no-maifest-id@v1.0 defects=1}
// ruleid: insufficient-postmessage-origin-validation
window.addEventListener("message", function (evt) {
  console.log('Inline without origin check!');
});
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=1}
function oldHandler(evt) {
  console.log('Normal function handler without origin check!');
};

// ruleid: insufficient-postmessage-origin-validation
window.addEventListener("message", oldHandler, false);
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=1}
// ruleid: insufficient-postmessage-origin-validation
window.addEventListener('message', (evt) => {
  console.log('Inline arrow function without origin check!');
});
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=1}
// ruleid: insufficient-postmessage-origin-validation
window.addEventListener('message', evt => {
  console.log('Inline arrow function without parenthesis & origin check!');
});
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=1}
const handler = (evt) => {
  console.log('Arrow function handler without origin check!');
};

// ruleid: insufficient-postmessage-origin-validation
window.addEventListener("message", handler, false);
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=0}
// ok: insufficient-postmessage-origin-validation
window.addEventListener("message", function (evt) {
  if (evt.origin == "http://example.com") {
    console.log('Normal inline function declaration with origin validation');
  }
});
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=0}
// ok: insufficient-postmessage-origin-validation
function normalHandler(evt) {
  if (evt.origin == "http://example.com") {
    console.log('Normal function handler with origin validation');
  }
};

window.addEventListener('message', normalHandler, false);
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=0}
// ok: insufficient-postmessage-origin-validation
window.addEventListener('message', (evt) => {
  if (evt.origin !== "http://example.com") {
    console.log('Inline arrow function declaration with origin validation');
  }
});
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=0}
// ok: insufficient-postmessage-origin-validation
const arrowHandler = (evt) => {
  if (evt.origin == "http://example.com") {
    console.log('Arrow function handler with origin validation');
  }
};

window.addEventListener('message', arrowHandler, false);
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=0}
const globalRegex = RegExp('/^http://www\.example\.com$/', 'g');

// ok: insufficient-postmessage-origin-validation
window.addEventListener("message", (evt) => {
  if (globalRegex.test(evt.origin)) {
    console.log(message.data);
  }
});
// {/fact}
