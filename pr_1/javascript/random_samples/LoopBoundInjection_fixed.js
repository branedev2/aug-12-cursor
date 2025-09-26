//{fact fact rule=unnecessary-iteration@v1.0 defects=0}

var express = require('express');
var app = express();

app.post("/foo", (req, res) => {
    var obj = req.body;
    
    if (!(obj instanceof Array)) { // Prevents DoS.
        return [];
    }

    var ret = [];

    for (var i = 0; i < obj.length; i++) {
        ret.push(obj[i]);
    }
});


//{/fact}
