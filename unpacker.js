var fs = require('fs');
var crypto = require('crypto');

function bufferToArrayBuffer(buffer) {
  var ab = new ArrayBuffer(buffer.length);
  var view = new Uint8Array(ab);
  for (var i = 0; i < buffer.length; i++) {
    view[i] = buffer[i];
  }
  return ab;
}

var littleEndian = (function() {
  var buffer = new ArrayBuffer(2);
  new DataView(buffer).setInt16(0, 256, true);
  return new Int16Array(buffer)[0] === 256;
})();

function BitStream(byteArray) {
  var mask = 0;
  var index = -1;

  this.next = function bs_next() {
    if (mask == 0) {
      index++;
      mask = (1 << 7);
    }

    var bit = (byteArray[index] & mask) ? 1 : 0;
    mask >>= 1;
    return bit;
  }

  this.hasMoreBits = function bs_has_more_bits() {
    return index < byteArray.length - 1 || mask
  }
}

function CRLFilterUnpacker(crlfilter) {
  this.version = null;
  this.logp = null;
  this.crls = {};

  var offset = 0;
  var dv = new DataView(crlfilter);

  this.version = dv.getUint32(offset, littleEndian);
  console.log('version = ' + this.version);
  offset += 4;

  this.logp = dv.getUint8(offset);
  console.log('logp = ' + this.logp);
  offset += 1;

  while (offset < dv.byteLength) {
    // new issuer
    var issuer = '';
    for (var i = 0; i < 20; i++) {
      var cc = dv.getUint8(offset + i);
      issuer += (cc + 0x100).toString(16).substr(1);
    }

    this.crls[issuer] = [];
    offset += 20;

    var length = dv.getUint32(offset, littleEndian);
    offset += 4;

    for (var i = 0; i < length; i++) {
      var bits = dv.getUint8(offset + i);
      this.crls[issuer].push(bits);
    }

    offset += i;

    var filterStart = '';
    for (var i = 0; i < Math.min(length, 2); i++) {
      var bits = this.crls[issuer][i];
      filterStart += (bits + 0x100).toString(2).substr(1);
    }

    console.log('[' + length + '] ' + filterStart + ' ...');
  }
}

function decodeGCS(bs, logp) {
  function readUnary() {
    var n = 0;
    while (bs.hasMoreBits() && bs.next() != 1) n++;
    if (!bs.hasMoreBits()) return -1;
    return n;
  }

  function readBinary() {
    var n = 0;
    for (var i = 0; i < logp; i++) {
      n = (n << 1) | bs.next();
    }
    return n;
  }

  var gcs = [];
  var previous = 0;
  while (true) {
    var q = readUnary();
    if (q == -1) break;
    var r = readBinary();

    var diff = q*(1 << logp) + r;
    var entry = previous + diff;
    gcs.push(entry);
    previous = entry;
  }

  return gcs;
}

function hash_and_truncate(n, nbits) {
  var hash_as_hex = crypto.createHash('sha1').update(n).digest('hex');
  return parseInt(hash_as_hex.substr(-nbits / 4), 16);
}

var crlfilter = new ArrayBuffer(0);
var input = fs.createReadStream('crlfilter');
input.on('data', function(data) {
  var ab = bufferToArrayBuffer(data);

  var updated = new Uint8Array(crlfilter.byteLength + ab.byteLength);
  updated.set(new Uint8Array(crlfilter), 0);
  updated.set(new Uint8Array(ab), crlfilter.byteLength);
  crlfilter = updated.buffer;
});

input.on('end', function() {
  // common name + org name + org unit name for the first issuer
  var issuer = crypto.createHash('sha1').update(
    'VeriSign Class 3 Extended Validation SSL SGC CAVeriSign, Inc.VeriSign Trust Network'
  ).digest('hex').substr(0, 40 /* issuer hash length is fixed-size, 20 bytes */);

  var unpacker = new CRLFilterUnpacker(crlfilter);

  var bs = new BitStream(unpacker.crls[issuer]);
  var gcs = decodeGCS(bs, unpacker.logp);
  console.log(gcs[0]); // should be 37
  console.log(gcs[1]); // should be 209

  var cert = '11:27:50:68:93:B1:3F:F8:84:7C:BA:53:8E:DD:D5'; // first cert
  var nbits = 20; // FIXME needs to come from the server
  var certHash = hash_and_truncate(cert, nbits);
  if (gcs.indexOf(certHash) !== -1) {
    console.log('found cert in CRL, as expected!');
  }
});
