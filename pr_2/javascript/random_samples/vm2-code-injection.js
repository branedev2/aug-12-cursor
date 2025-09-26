'use strict';

const fs = require('fs');
const {VM, NodeVM} = require('vm2');
const express = require("express");
const app = express();

// {fact rule=code-injection@v1.0 defects=1}
async function test1(code, input) {
  code = `
    console.log(${input})
  `;

  const sandbox = {
    setTimeout,
    fs: {
      watch: fs.watch
    }
  };

  // ruleid: vm2-code-injection
  return new VM({
    timeout: 40 * 1000,
    sandbox
  }).run(code);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function test2(input) {
  const sandbox = {
    setTimeout,
    fs: {
      watch: fs.watch
    }
  };

  // ruleid: vm2-code-injection
  const nodeVM = new NodeVM({timeout: 40 * 1000, sandbox});
  return nodeVM.run('console.log(' + input + ')')
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=1}
function test3(input) {
  const sandbox = {
    setTimeout,
    fs: {
      watch: fs.watch
    }
  };

  const nodeVM = new NodeVM({timeout: 40 * 1000, sandbox});
  // ruleid: vm2-code-injection
  const script = new VMScript(`console.log(${input})`)
  return nodeVM.run(script)
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
async function okTest1(code) {
  code = `
    console.log("Hello world")
  `;

  const sandbox = {
    setTimeout,
    fs: {
      watch: fs.watch
    }
  };

  return new VM({
    timeout: 40 * 1000,
    sandbox
  }).run(code);
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function okTest2() {
  const sandbox = {
    setTimeout,
    fs: {
      watch: fs.watch
    }
  };

  const nodeVM = new NodeVM({timeout: 40 * 1000, sandbox});
  return nodeVM.run('console.log("Hello world")')
}
// {/fact}

// {fact rule=code-injection@v1.0 defects=0}
function okTest3() {
  const sandbox = {
    setTimeout,
    fs: {
      watch: fs.watch
    }
  };

  const nodeVM = new NodeVM({timeout: 40 * 1000, sandbox});
  const script = new VMScript('console.log("Hello world")')
  return nodeVM.run(script)
}
// {/fact}


function call() {
    app.get("/add/:num1/:num2", function (req, res) {
        let code = req.body
        test1(code, req.params.num2)
        test2(req.params.num1)
        test3(req.params.num3)
    });
}
