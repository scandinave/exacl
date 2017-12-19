const Authorizer = require('../index');
const expect = require('chai').expect;
const should = require('chai').should();
const assert = require('assert');

// Ignore mocha globals
/* global describe */
/* global it */

const permission = 'private:users:view';
const permissionWildcard = 'private:users:*';
const permissions = ['private:users:add', 'private:users:*', 'private:applications:*:logs'];
const principal = {
  id: '1',
  name: 'Principal',
  permissions
};

describe('Flatten array', () => {
  it('sould return array when passed single string', () => {
    const flattenArray = Authorizer.flattenPermissions(permission);
    expect(flattenArray).to.be.an('array');
    expect(flattenArray).to.have.length(1);
  });

  it('sould return array when passed array', () => {
    const flattenArray = Authorizer.flattenPermissions(permissions);
    expect(flattenArray).to.be.an('array');
    expect(flattenArray).to.have.length(3);
  });

  it('sould return array when passed an array of string and array', () => {
    const flattenArray = Authorizer.flattenPermissions([permission, permissions]);
    expect(flattenArray).to.be.an('array');
    expect(flattenArray).to.have.length(4);
  });
});

describe('Permissions compilation', () => {
  it('sould return the compile form of one permission', () => {
    expect(Authorizer.compilePermissions(permission)).to.be.equals('^(private:users:view)$');
  });

  it('sould return the compile form of a wildcard permission', () => {
    const compilePermission = Authorizer.compilePermissions(permissionWildcard);
    expect(compilePermission).to.be.equals('^(private:users:[a-zA-Z0-9\-_:\*\]*)$');
  });

  it('sould return the compile form of an array of permissions', () => {
    const arrayCompiled = Authorizer.compilePermissions(permissions);
    expect(arrayCompiled).to.be.equals('^(private:users:add)|(private:users:[a-zA-Z0-9\-_:\*]*)|(private:applications:[a-zA-Z0-9\-_:\*]*:logs)$');
  });
});

describe('Principal check', () => {
  it('should return a principal object with permission when principal passed as request object', () => {
    const req = {
      user: principal
    };
    try {
      Authorizer.withPrincipal(req);
      assert(true);
    } catch (err) {
      assert(false);
    }
  });

  it('should return a principal object with permission when principal passed as request session object', () => {
    const req = {
      session: {
        user: principal
      }
    };
    try {
      Authorizer.withPrincipal(req);
      assert(true);
    } catch (err) {
      assert(false);
    }
  });

  it('should return failed when not principal is not present ether in request or session', () => {
    try {
      Authorizer.withPrincipal(principal);
      assert(false);
    } catch (err) {
      assert(true);
    }
  });

  it('should failed when principal is undefined', () => {
    try {
      Authorizer.withPrincipal({});
      assert(false);
    } catch (err) {
      assert(true);
    }
  });

  it('should failed when principal permission is undefined', () => {
    try {
      Authorizer.withPrincipal({
        user: {}
      });
      assert(false);
    } catch (err) {
      assert(true);
    }
  });

  describe('Principal check', () => {
    it('should return that the principal has correct permissions', () => {
      expect(Authorizer.checkPermissions(principal, [permissions])).to.be.equal(true);
      expect(Authorizer.checkPermissions(principal, [permissionWildcard])).to.be.equal(true);
    });

    it('should return that the principal has no permissions', () => {
      expect(Authorizer.checkPermissions(principal, permission)).to.be.equal(false);
    });
  });
});