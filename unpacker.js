var fs = require('fs');

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

function CRLFilterUnpacker() {
  this.version = null;
  this.logp = null;
  this.remainingBytesInIssuer = 0;

  this.process = function crlfilterunpacker_process(dv) {
    var offset = 0;

    if (this.version === null) {
      this.version = dv.getUint32(offset, littleEndian);
      console.log('version = ' + this.version);
      offset += 4;
    }

    if (this.logp === null) {
      this.logp = dv.getUint8(offset);
      console.log('logp = ' + this.logp);
      offset += 1;
    }

    offset += Math.min(
      this.remainingBytesInIssuer, dv.byteLength - offset);

    if (offset == dv.byteLength) {
      // skip this block, as it consists of entries for a single issuer
      this.remainingBytesInIssuer -= dv.byteLength;
      return;
    }

    while (offset < dv.byteLength) {
      // new issuer
      var issuer = '';
      for (var i = 0; i < 20; i++) {
        var cc = dv.getUint8(offset + i);
        issuer += cc;
      }

      offset += 20;

      var length = dv.getUint32(offset, littleEndian);
      offset += 4;

      var filterStart = '';
      for (var i = 0; i < 2; i++) {
        var bits = dv.getUint8(offset + i);
        filterStart += (bits + 0x100).toString(2).substr(1);
      }

      // skip the remaining entries
      offset += length;
      console.log('[' + length + '] ' + filterStart + ' ...');
    }

    this.remainingBytesInIssuer = offset - dv.byteLength;
  }
}

var unpacker = new CRLFilterUnpacker();
var input = fs.createReadStream('crlfilter');
input.on('data', function(data) {
  var ab = bufferToArrayBuffer(data);
  var dv = new DataView(ab);
  unpacker.process(dv);
});
