//{fact rule=cross-site-scripting@v1.0 defects=1}

var express = require('express'),
    fs = require('fs');

express().get('/list-directory', function(req, res) {
    fs.readdir('/public', function (error, fileNames) {
        var list = '<ul>';
        fileNames.forEach(fileName => {
            // BAD: `fileName` can contain HTML elements
            list += '<li>' + fileName + '</li>';
        });
        list += '</ul>'
        res.send(list);
    });
});


//{/fact}