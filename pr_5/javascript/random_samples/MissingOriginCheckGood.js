//{fact rule=method-input-validation@v1.0 defects=0}

function postMessageHandler(event) {
    console.log(event.origin)
    // GOOD: the origin property is checked
    if (event.origin === 'https://www.example.com') {
        // do something
    }
}

window.addEventListener('message', postMessageHandler, false);

//{/fact}