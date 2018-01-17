# exacl

A rewrite of exacl with ES6 features and bugfix.
.This module is an express/connect middleware module for enforcing an Apache Shiro inspired authorization system.

## Installation

    $ npm install exacl


## Basic usage
```js
var express = require('express')
var app = express()
var authorizer = require('express-acl')

app.get('/restricted', authorizer.isPermitted("restricted:view"), function(req, res) {
  // Restricted content
  ...
})
```

## Documentation

### Definitions

**Permission** - a statement that defines access to an explicit activity, behaviour or action.

**Principal** - usually a website user, assigned permissions to enable access to sets of activities, behaviours, or actions.

### Permission Wildcard Expressions

To practically assign sets of permissions to principals, __exacl__ supports a wildcard enabled permission statement syntax that closely follows the syntax used by [Apache Shiro](http://shiro.apache.org/permissions.html).
A collection of permissions assigned to a principal are compiled by the system into a regular expression.

* Permission statements are composed of from parts delimited by colons ```:```.
* Wildcard ```?``` and ```*``` can be used to match one or more characters within an expression part.
* Examples:

| Expression | Description |
| ---------- | ----------- |
| ```'system:*'``` | **String** - has all permissions for system. Works for a single permission statement only |
| ```[ 'system:*', 'activity:create', 'admin:users:roles:get:* ]``` | **Array** - has all permissions for system and create permissions for activity and can retrieve all roles of all users|

### Initialization

Create a new authorizer in for example a file name authorization.js:
```js
var authorizer = require('exacl');

module.exports = authorizer;
```

### Options
Setting options at initialization sets the default for that authorizer. The following options are available:

- _withPrincipal_ - A Principal, usually a user, is expected to be represented by an object with a permissions property referring to either a single permission or an array of permissions. Defaults to req.user or req.session.user.
- _onDenied_ - Callback function for when permission is denied. Defaults to setting the res.status to 403.

#### Setting the default principal
withPrincipal can be specified using an array, a function or an asynchronous function.
```js
// Use any object that has a "permissions" parameter (array)
var user = {
  username    : 'thisismyusername'
  permissions : [ 'account:view', 'payment:view' ]
}
authorizer.options.withPrincipal = user
// OR use a function that returns a valid subject
authorizer.options.withPrincipal = (req, res) => {
  var user = {
    username    : 'thisismyusername'
    permissions : [ 'account:view', 'payment:view' ]
  }
  return user
}
// OR use an asynchronous function that return a promise.
authorizer.options.withPrincipal = async (req, res) => {
  var user = await {
    username    : 'thisismyusername'
    permissions : [ 'account:view', 'payment:view' ]
  }
  return user
}
```
#### Setting the default onDenied callback
onDenied must be an express/connect compatible middleware function
```js
authorizer.options.onDenied = (err, res) => {
  res.status(403).send({error: err});
}
```

### Express Middleware

__exacl__ uses a fluent API to generate express middleware for enforcing permissions.
```js
const authorization = require("../authorization.js"); // Where the authorizer was configured previously.

app.get('/restricted', authorization.authorizer..isPermitted("restricted:view"), (req, res) => {
  // Restricted content
  ...
})
```