const fs = require('fs');
const path = require('path');
const async = require('async');
const crypto = require('crypto');
const BigNumber = require('bignumber.js');
const request = require('request');
const reverse = require("buffer-reverse")
const bufferEqual = require('buffer-equal');

var blockIndex = 0;
var UINT32_MAX = 0xffffffff;

// Use JSON RPC for checking correctness.
var vertcoinRequest = function(method, params, callback, retry) {
  if(retry === undefined) retry = true;
  var time = Date.now()
  var requestBody = {
    jsonrpc: "1.0",
    id: time,
    method: method,
    params: params
  };
  request.post('http://localhost:5888/',{ 'auth' : {
    user : 'vertcoinrpc',
    pass : 'f78cc64b-d02b-4b8c-8295-a42fc15039e0'
  }, 'body' : JSON.stringify(requestBody), 'timeout' : 300}, function(err, result, body) {
    if(err && !retry === false) {
      vertcoind.request(method, params, callback, retry);
    } else {
      try {
        body = JSON.parse(body);
      } catch (e) {
        console.log("Error parsing JSON",e,"\r\nJSON:\r\n",body);
        vertcoind.request(method, params, callback, retry);
        return;
      }
      callback(err, result, body);
    }
  });
}

var processFile = function(fileName, callback) {
  fs.open(path.join(process.env.VERTCOIN_BLOCKS_DIR, fileName), 'r', (err, fd) => {
    readBlocks(fd, callback);
  });
}

var readUInt64LE = function(buffer, offset) {
  return new BigNumber(buffer.toString('hex',offset,offset+8),16).toNumber();
}

var readInt64LE = function(buffer, offset) {
  var low = buffer.readInt32LE(offset);
  var n = buffer.readInt32LE(offset + 4) * 4294967296.0 + low;
  if (low < 0) n += 4294967296;
  return n;
}

var readVarInt = function(buffer, offset) {
  var uint = buffer.readUInt8(offset);
  switch(uint)
  {
    case 253:
      return { value : buffer.readUInt16LE(offset+1), offset : offset+3 };
    case 254:
      return { value : buffer.readUInt32LE(offset+1), offset :  offset+5 };
    case 255:
      return { value : readUInt64(buffer, offset+1), offset : offset+9 };
    default:
      return { value : uint, offset : offset+1 };
  }
}

var readString = function(blockBuffer, offset) {
  var varInt = readVarInt(blockBuffer, offset);
  var buffer = new Buffer(varInt.value);
  blockBuffer.copy(buffer, 0, varInt.offset, varInt.offset+varInt.value);

  return { value : buffer.toString('hex'), offset : varInt.offset + varInt.value };
}

var readHash = function(blockBuffer, offset) {
  return blockBuffer.toString('hex',offset,offset + 32);
}

var readBlock = function(blockBuffer, callback) {
  var debug = false;
  var block = {};

  block.height = blockIndex++;
  block.version = blockBuffer.readUInt32LE(0);


  block.previousBlockHash = readHash(blockBuffer,4);
  block.merkleRoot = readHash(blockBuffer,36);
  block.time = blockBuffer.readUInt32LE(68);
  block.nBits = blockBuffer.readUInt32LE(72);
  block.nonce = blockBuffer.readUInt32LE(76);

  if(debug)
    console.log("Block header", block);


  var blockHeader = new Buffer(80);
  blockBuffer.copy(blockHeader, 0, 0, 80);
  //block.hash = crypto.createHash('sha256').update(crypto.createHash('sha256').update(blockHeader).digest()).digest().toString('hex');

  var txCountVarInt = readVarInt(blockBuffer, 80);
  var txCount = txCountVarInt.value;

  if(debug)
    console.log("Block tx count", txCount);


  var bufferOffset = txCountVarInt.offset;
  block.transactions = [];
  for(var transactionIndex = 0; transactionIndex < txCount; transactionIndex++)
  {
    var transaction = {};
    transaction.inputs = [];
    transaction.outputs = [];
    transaction.version = blockBuffer.readUInt32LE(bufferOffset);
    bufferOffset += 4;
    var inputCountVarInt = readVarInt(blockBuffer, bufferOffset);
    var inputCount = inputCountVarInt.value;
    if(debug)
      console.log("TX input count", inputCount);


    bufferOffset = inputCountVarInt.offset;
    for(var inputIndex = 0; inputIndex < inputCount; inputIndex++)
    {
      var input = {};

      input.transactionHash = readHash(blockBuffer, bufferOffset);
      bufferOffset += 32;
      input.transactionIndex = blockBuffer.readUInt32LE(bufferOffset);
      bufferOffset += 4;
      var scriptString = readString(blockBuffer, bufferOffset);
      input.script = scriptString.value;
      bufferOffset = scriptString.offset;

      if(input.transactionIndex == UINT32_MAX)
      {
          input.coinBase = true;
      }
      input.sequenceNumber = blockBuffer.readUInt32LE(bufferOffset);
      bufferOffset += 4;

      transaction.inputs.push(input);
    }

    var outputCountVarInt = readVarInt(blockBuffer, bufferOffset);
    var outputCount = outputCountVarInt.value;
    if(debug)
      console.log("TX output count", outputCount);

    bufferOffset = outputCountVarInt.offset;
    for(var outputIndex = 0; outputIndex < outputCount; outputIndex++)
    {
      var output = {};

      output.value = readInt64LE(blockBuffer, bufferOffset);
      bufferOffset += 8;
      var scriptString = readString(blockBuffer, bufferOffset);
      output.script = scriptString.value;
      bufferOffset = scriptString.offset;

      transaction.outputs.push(output);
    }
    transaction.lockTime = blockBuffer.readUInt32LE(bufferOffset);
    bufferOffset += 4;

    block.transactions.push(transaction);
  }
  callback(block);
}

var processBlock = function(block, callback) {
  if(block == null) {
    callback();
    return;
  }

  vertcoinRequest("getblockhash",[block.height],(err, result, body) => {
    vertcoinRequest("getblock",[body.result],(err, result, body) => {

      var myBlockMR = reverse(Buffer.from(block.merkleRoot, 'hex'));
      var VTCDBlockMR = Buffer.from(body.result.merkleroot, 'hex');

      console.log("Found block",block.height,"Previous blockhash",block.previousBlockHash,"\r\nMy Merkle Root:",myBlockMR.toString('hex'),"VTCD Merkle Root:",VTCDBlockMR.toString('hex'));

      if(!bufferEqual(myBlockMR, VTCDBlockMR))
      {
        console.error("Found incorrect block (not matching VTCD's Merkle Root for same height)", block);
      }

      callback();
    });
  });


  //callback();
}

var readBlocks = function(fd, callback) {
  var magic = new Buffer(4);
  fs.read(fd, magic, 0, 4, null, (err, num) => {
    if(num == 4 && magic.toString("hex") == 'fabfb5da') {
      var blockLengthBuf = new Buffer(4);
      fs.read(fd, blockLengthBuf, 0, 4, null, (err, num) => {
        var blockLength = blockLengthBuf.readUInt32LE(0);
        var blockBuffer = new Buffer(blockLength);
        fs.read(fd, blockBuffer, 0, blockLength, null, (err, num) => {
          readBlock(blockBuffer, (block) => {
            processBlock(block, () => {
              readBlocks(fd, callback);
            });
          });
        });
      });
    } else {
      callback();
    }
  });
}

var fileQueue = async.queue(processFile, 1);
fileQueue.drain = function() {
  console.log("File queue empty");
}

fs.readdir(process.env.VERTCOIN_BLOCKS_DIR, (err, files) => {
  if(err) {
    console.error("Vertcoin blocks not found");
    exit(-1);
  }

  var blockFiles = [];
  files.forEach(file => {
    if(file.toLowerCase().startsWith("blk") && file.toLowerCase().endsWith(".dat"))
    {
      blockFiles.push(file);
    }
  });

  blockFiles = blockFiles.sort();

  blockFiles.forEach(file => {
    fileQueue.push(file);
  });
});
