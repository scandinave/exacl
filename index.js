/**
 * MIT License

Copyright (c) [year] [fullname]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

/**
 * Base class to handle ACL permission
 */
class Authorizer {


  /**
   * Check that the Princical has the correct permission.
   * @param {*} permissions The permissions to check against Principal permissions
   * @return {expressMiddleWare} The middelware function.
   */
  static isPermitted(...permissions) {
    return (req, res, next) => {
      Authorizer.withPrincipal(req).then(principal => {
        if (Authorizer.checkPermissions(principal, Authorizer.flattenPermissions(permissions))) {
          next();
        } else {
          Authorizer.onDenied(new Error('You are not allowed to access this resources'), res);
        }
      }).catch(err => {
        Authorizer.onDenied(err, res);
      });
    };
  }

  /**
   * Check that the Princical has the correct permission.
   * @param {*} principal The principal against which validate permissions
   * @param {*} permissions The permissions to check against Principal permissions
   * @return {boolean} true if the principal has correct permission. False otherwise.
   */
  static checkPermissions(principal, permissions) {

    const principalPermissions = Authorizer.compilePermissions(principal.permissions);
    let found = false;
    let i = 0;
    while (found === false && permissions.length !== 0 && i < permissions.length) {
      found = new RegExp(principalPermissions).test(permissions[i]);
      i++;
    }

    return found;
  }
  /**
   * Return the principal object.
   * @param {request} req the request object.
   * @param {request} res the request response object.
   * @param {request} done the done object.
   * @return {user} The principal object
   */
  static withPrincipal(req, res, done) {
    const principal = req.user || (req.session ? req.session.user || null : null);
    if (principal === null) {
      throw new Error(`No principal found. 
      You must pass a user object in the request, in the request.session or 
      defined the withPrincipal function of the authorizer`);
    } else if (!principal.permissions) {
      throw new Error(`Principal object found. but it does do contains a 'permissions' property`);
    } else {
      return principal;
    }
  }

  /**
   * Invoke when something went wrong during the authorization process.
   * Can be override to defined custom error handling.
   * @param {*} err The error throwed.
   * @param {*} res The request response object.
   * @return {void}
   */
  static onDenied(err, res) {
    res.status(403).send({error: err});
  }

  /**
   * Compile permissions string as regex.
   * @param {array} permissions Principal permissions.
   * @return {array} An array of compile permissions.
   */
  static compilePermissions(permissions) {
    permissions = Authorizer.flattenPermissions(permissions);
    if (permissions.length === 1) {
      permissions[0] = permissions[0].replace(new RegExp('[\*]', 'g'), '[a-zA-Z0-9\-_:\*]*')
        .replace(new RegExp('[\?]', 'g'), '[a-zA-Z0-9\-_:\?]?').replace(new RegExp('[\?]', 'g'), '[a-zA-Z0-9\-_:\+]+');
    } else {
      permissions = permissions.reduce((previousPermission, currentPermission) => {
        currentPermission = currentPermission.replace(new RegExp('[\*]', 'g'), '[a-zA-Z0-9\-_:\*]*')
          .replace(new RegExp('[\?]', 'g'), '[a-zA-Z0-9\-_:\?]?').replace(new RegExp('[\?]', 'g'), '[a-zA-Z0-9\-_:\+]+');

        return `${previousPermission})|(${currentPermission}`;
      });
    }

    return `^(${permissions})$`;
  }

  /**
   * Merge string and array into a single array.
   * @param {*} permissions A list of permission string or array of permission string
   * @return {array} The flatten array that contains all the permission.
   */
  static flattenPermissions(permissions) {
    let flatPermissions = [];
    if (!Array.isArray(permissions)) {
      flatPermissions.push(permissions);
    } else {
      permissions.forEach(permission => {
        if (Array.isArray(permission)) {
          flatPermissions = flatPermissions.concat(permission);
        } else {
          flatPermissions.push(permission);
        }
      });
    }

    return flatPermissions;
  }
}

module.exports = Authorizer;