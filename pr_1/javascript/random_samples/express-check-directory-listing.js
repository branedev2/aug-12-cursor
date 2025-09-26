const serveIndex = require('serve-index');
var express = require('express');
var app = express();

var serve = serveIndex('public/ftp', {
    icons: true
})

// {fact rule=cwe-no-maifest-id@v1.0 defects=1}
var server = http.createServer(function onRequest(req, res) {
    var done = finalhandler(req, res)
    // ruleid: express-check-directory-listing
    serve(req, res, function onNext(err) {
        if (err) return done(err)
        index(req, res, done)
    })
})
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=1}
// ruleid: express-check-directory-listing
app.use('/ftp', serveIndex('ftp', {
    icons: true
}));
// {/fact}

// {fact rule=cwe-no-maifest-id@v1.0 defects=0}
// ok
app.use(bodyParser.text({
    type: '*/*'
}));
// {/fact}
