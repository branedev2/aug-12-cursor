// {fact rule=insecure-connection@v1.0 defects=1}
// ruleid:javascript-prompt
var name = prompt('what is your name');
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
// ruleid: javascript-alert
alert('your name is ' + name);
alert('not', 'a', 'valid', 'alert')
// {/fact}

// {fact rule=insecure-connection@v1.0 defects=1}
// ruleid: javascript-confirm
if ( confirm("pushem!") == true) {
    r = "x";
} else {
    // {/fact}

    // {fact rule=insecure-connection@v1.0 defects=1}
    r = "Y";
    // ruleid: javascript-debugger
    debugger;
}
// {/fact}
