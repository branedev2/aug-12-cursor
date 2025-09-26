const express = require('express')
    , cors = require('cors')
    , bodyParser = require('body-parser');

var app = express();

// {fact rule=resource-leak@v1.0 defects=1}
app.configure(function () {
    app.set('port', process.env.PORT || 3000);
    app.set('views', __dirname + '/views');
    app.set('view engine', 'jade');
    app.use(express.favicon());
    app.use(express.logger('dev'));
    // ruleid:express_bodyparser
    app.use(express.bodyParser());
    app.use(cors());
});
// {/fact}
