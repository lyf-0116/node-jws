/*global module*/
var Buffer = require('safe-buffer').Buffer;
var DataStream = require('./data-stream');
var jwa = require('jwa');
var Stream = require('stream');
var toString = require('./tostring');
var util = require('util');
var JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;

function isObject(thing) {
  return Object.prototype.toString.call(thing) === '[object Object]';
}

function assertNoDuplicateKeys(json) {
  var index = 0;

  function skipWhitespace() {
    while (index < json.length) {
      var code = json.charCodeAt(index);
      if (code !== 0x20 && code !== 0x09 && code !== 0x0a && code !== 0x0d)
        break;
      index++;
    }
  }

  function parseString() {
    var start = index;
    index++;

    while (index < json.length) {
      var char = json.charAt(index);
      if (char === '\\') {
        index += 2;
      } else if (char === '"') {
        index++;
        return JSON.parse(json.slice(start, index));
      } else {
        index++;
      }
    }

    throw new SyntaxError('Invalid JSON string');
  }

  function parseNumber() {
    var start = index;
    while (index < json.length) {
      var char = json.charAt(index);
      if (char === ',' || char === ']' || char === '}' || char === ' ' ||
          char === '\t' || char === '\n' || char === '\r')
        break;
      index++;
    }
    if (start === index)
      throw new SyntaxError('Invalid JSON number');
  }

  function parseArray() {
    index++;
    skipWhitespace();
    if (json.charAt(index) === ']') {
      index++;
      return;
    }

    while (index < json.length) {
      parseValue();
      skipWhitespace();

      var delimiter = json.charAt(index);
      index++;
      if (delimiter === ']')
        return;
      if (delimiter !== ',')
        throw new SyntaxError('Invalid JSON array');
    }
  }

  function parseObject() {
    index++;
    skipWhitespace();
    if (json.charAt(index) === '}') {
      index++;
      return;
    }

    var keys = Object.create(null);
    while (index < json.length) {
      skipWhitespace();
      if (json.charAt(index) !== '"')
        throw new SyntaxError('Invalid JSON object key');

      var key = parseString();
      if (keys[key])
        throw new SyntaxError('Duplicate key in JSON object');
      keys[key] = true;

      skipWhitespace();
      if (json.charAt(index) !== ':')
        throw new SyntaxError('Invalid JSON object');
      index++;
      parseValue();
      skipWhitespace();

      var delimiter = json.charAt(index);
      index++;
      if (delimiter === '}')
        return;
      if (delimiter !== ',')
        throw new SyntaxError('Invalid JSON object');
    }
  }

  function parseValue() {
    skipWhitespace();
    var char = json.charAt(index);
    if (char === '{') {
      parseObject();
    } else if (char === '[') {
      parseArray();
    } else if (char === '"') {
      parseString();
    } else if (char === '-' || (char >= '0' && char <= '9')) {
      parseNumber();
    } else if (json.slice(index, index + 4) === 'true') {
      index += 4;
    } else if (json.slice(index, index + 5) === 'false') {
      index += 5;
    } else if (json.slice(index, index + 4) === 'null') {
      index += 4;
    } else {
      throw new SyntaxError('Invalid JSON value');
    }
  }

  parseValue();
  return false;
}

function safeJsonParse(thing) {
  if (isObject(thing))
    return thing;
  try {
    var parsed = JSON.parse(thing);
    assertNoDuplicateKeys(thing);
    return parsed;
  }
  catch (e) { return undefined; }
}

function headerHasDuplicateKeys(jwsSig) {
  var encodedHeader = jwsSig.split('.', 1)[0];
  var header = Buffer.from(encodedHeader, 'base64').toString('binary');
  try {
    JSON.parse(header);
  } catch (e) {
    return false;
  }
  try {
    assertNoDuplicateKeys(header);
    return false;
  } catch (e) {
    return true;
  }
}

function headerFromJWS(jwsSig) {
  var encodedHeader = jwsSig.split('.', 1)[0];
  return safeJsonParse(Buffer.from(encodedHeader, 'base64').toString('binary'));
}

function securedInputFromJWS(jwsSig) {
  return jwsSig.split('.', 2).join('.');
}

function signatureFromJWS(jwsSig) {
  return jwsSig.split('.')[2];
}

function payloadFromJWS(jwsSig, encoding) {
  encoding = encoding || 'utf8';
  var payload = jwsSig.split('.')[1];
  return Buffer.from(payload, 'base64').toString(encoding);
}

function isValidJws(string) {
  return JWS_REGEX.test(string) && !!headerFromJWS(string);
}

function jwsVerify(jwsSig, algorithm, secretOrKey) {
  if (!algorithm) {
    var err = new Error("Missing algorithm parameter for jws.verify");
    err.code = "MISSING_ALGORITHM";
    throw err;
  }
  jwsSig = toString(jwsSig);
  var signature = signatureFromJWS(jwsSig);
  var securedInput = securedInputFromJWS(jwsSig);
  var algo = jwa(algorithm);
  if (headerHasDuplicateKeys(jwsSig))
    return false;
  return algo.verify(securedInput, signature, secretOrKey);
}

function jwsDecode(jwsSig, opts) {
  opts = opts || {};
  jwsSig = toString(jwsSig);

  if (!isValidJws(jwsSig))
    return null;

  var header = headerFromJWS(jwsSig);

  if (!header)
    return null;

  var payload = payloadFromJWS(jwsSig);
  if (header.typ === 'JWT' || opts.json)
    payload = JSON.parse(payload, opts.encoding);

  return {
    header: header,
    payload: payload,
    signature: signatureFromJWS(jwsSig)
  };
}

function VerifyStream(opts) {
  opts = opts || {};
  var secretOrKey = opts.secret;
  secretOrKey = secretOrKey == null ? opts.publicKey : secretOrKey;
  secretOrKey = secretOrKey == null ? opts.key : secretOrKey;
  if (/^hs/i.test(opts.algorithm) === true && secretOrKey == null) {
    throw new TypeError('secret must be a string or buffer or a KeyObject')
  }
  var secretStream = new DataStream(secretOrKey);
  this.readable = true;
  this.algorithm = opts.algorithm;
  this.encoding = opts.encoding;
  this.secret = this.publicKey = this.key = secretStream;
  this.signature = new DataStream(opts.signature);
  this.secret.once('close', function () {
    if (!this.signature.writable && this.readable)
      this.verify();
  }.bind(this));

  this.signature.once('close', function () {
    if (!this.secret.writable && this.readable)
      this.verify();
  }.bind(this));
}
util.inherits(VerifyStream, Stream);
VerifyStream.prototype.verify = function verify() {
  try {
    var valid = jwsVerify(this.signature.buffer, this.algorithm, this.key.buffer);
    var obj = jwsDecode(this.signature.buffer, this.encoding);
    this.emit('done', valid, obj);
    this.emit('data', valid);
    this.emit('end');
    this.readable = false;
    return valid;
  } catch (e) {
    this.readable = false;
    this.emit('error', e);
    this.emit('close');
  }
};

VerifyStream.decode = jwsDecode;
VerifyStream.isValid = isValidJws;
VerifyStream.verify = jwsVerify;

module.exports = VerifyStream;
