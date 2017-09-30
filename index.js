const fs = require('fs');
const path = require('path');
const async = require('async');
const crypto = require('crypto');
const BigNumber = require('bignumber.js');
const request = require('request');
const reverse = require("buffer-reverse")
const bufferEqual = require('buffer-equal');
const vertcoinhash = require('vertcoinhash/build/Release/vertcoinhash');

var blockIndex = 0;
var UINT32_MAX = 0xffffffff;
var lastBlockHash = null;

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
      vertcoinRequest(method, params, callback, retry);
    } else {
      try {
        body = JSON.parse(body);
      } catch (e) {
        console.log("Error parsing JSON",e,"\r\nJSON:\r\n",body);
        vertcoinRequest(method, params, callback, retry);
        return;
      }
      callback(err, result, body);
    }
  });
}



var getBlockHash = function(header) {
  return crypto.createHash('sha256').update(crypto.createHash('sha256').update(header).digest()).digest();
}

var getPOWHash = function(blockHeight, header) {
  if(blockHeight < 208301)
    return vertcoinhash.SumScryptN(vertcoinhash.SumScryptN(header));
  else if(blockHeight < 347000)
    return vertcoinhash.SumLyra2RE(vertcoinhash.SumLyra2RE(header));
  else
    return vertcoinhash.SumLyra2REv2(vertcoinhash.SumLyra2REv2(header));
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

var readBlock = function(block, callback) {
  var debug = false;
  var blockBuffer = block.buffer;

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
  block.hash = getBlockHash(blockHeader).toString('hex');

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

// Blocks come out of order, so store them when the previousHash mismatches our highest tip

var parkedBlocks = [];

var processParkedBlocks = function(callback) {
  if(parkedBlocks.length == 0) {
    callback();
    return;
  }

  console.log("Processing",parkedBlocks.length,"parked blocks");

  var processQueue = async.queue(processBlock, 1);
  processQueue.drain = callback;
  for(var block of parkedBlocks) {
    processQueue.push(block);
  }
}

var processBlock = function(block, callback) {
  var processBlockInternal = function(block, callback) {
    if(block == null) {
      callback();
      return;
    }

    if(!(lastBlockHash == null || block.previousBlockHash == lastBlockHash))
    {
      if(!block.parked) {
        console.log("previousBlockHash not matching last block hash. Storing block");
        block.parked = true;
        parkedBlocks.push(block);
      }
      callback();
      return;
    }

    lastBlockHash = block.hash;
    block.height = blockIndex++;

    vertcoinRequest("getblockhash",[block.height],(err, result, body) => {
      vertcoinRequest("getblock",[body.result],(err, result, body) => {

        var myBlockMR = reverse(Buffer.from(block.merkleRoot, 'hex'));
        var VTCDBlockMR = Buffer.from(body.result.merkleroot, 'hex');
        var myBlockHash = reverse(Buffer.from(block.hash, 'hex'));
        var VTCDBlockHash = Buffer.from(body.result.hash, 'hex');


        var error = false;
        console.log("Found block",block.height,"Blockhash",myBlockHash.toString('hex'),"\r\nVTCD blockhash:",body.result.hash,"\r\nMy Merkle Root:",myBlockMR.toString('hex'),"VTCD Merkle Root:",VTCDBlockMR.toString('hex'));

        if(!bufferEqual(myBlockMR, VTCDBlockMR))
        {
          console.error("Found incorrect block (not matching VTCD's Merkle Root for same height)", block);
          error = true;
        }

        if(!bufferEqual(myBlockMR, VTCDBlockMR))
        {
          console.error("Found incorrect block (not matching VTCD's hash for same height)", block);
          error = true;

        }

        if(error)
        {
          setTimeout(callback, 10000);
        }
        else {
          callback();
        }

      });
    });

  }

  if(block.parked) {
    processBlockInternal(block, callback);
  } else {
    processParkedBlocks(() => { processBlockInternal(block, callback); });
  }

  //callback();
}

var findBlocksWithPrevHash = function(prevBlockHash) {
  var nextBlocks = [];
  for(var block of blocks) {
    if(bufferEqual(block.prevBlockHash,prevBlockHash)) {
      nextBlocks.push(block);
    }
  }
  return nextBlocks;
}

var findLongestChainBlock = function(potentialBlocks) {
  var checks = [];
  for(var block of potentialBlocks) {
    checks.push({ block : block, nextCheckHash : block.hash });
  }

  while(true) {
    var noMoreBlocksFound = [];
    for(var check of checks) {
      var nextBlocks = findBlocksWithPrevHash(check.nextCheckHash);
      if(nextBlocks.length == 0) {
        noMoreBlocksFound.push(check);
      } else {
        check.nextCheckHash = nextBlocks[0].hash;
      }
    }
    for(var check of noMoreBlocksFound) {
      checks.splice(checks.indexOf(check),1);
    }
    if(checks.length == 1) {
      return checks[0].block;
    }
  }
}

var blocks = [];
var sortedBlocks = [];
var sortBlocks = function(callback) {
  var lastBlockHash = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000','hex');
  while(true) {
    var nextBlocks = findBlocksWithPrevHash(lastBlockHash);

    if(nextBlocks.length > 0)
    {
      var nextBlock = nextBlocks[0];
      if(nextBlocks.length > 1) {
        console.log("Found more than one block that might fit. Investigating which has the longest chain");
        nextBlock = findLongestChainBlock(nextBlocks);
      }

      blocks.splice(blocks.indexOf(nextBlock), 1);
      sortedBlocks.push(nextBlock);
      lastBlockHash = nextBlock.hash;
      console.log("Sorted up to height", sortedBlocks.length);
    }
    else
    {
      console.log("Can't find next block. Must be last at ", sortedBlocks.length);
      callback();
      break;
    }
  }
}

var scanBlocks = function(state, callback) {
  var fd = state.fd;
  var magic = new Buffer(4);
  fs.read(fd, magic, 0, 4, null, (err, num) => {
    state.pos += 4;
    if(num == 4 && magic.toString("hex") == 'fabfb5da') {
      delete(magic);
      var blockLengthBuf = new Buffer(4);
      fs.read(fd, blockLengthBuf, 0, 4, null, (err, num) => {
        state.pos += 4;
        var block = { startPos : fd.pos, length : blockLengthBuf.readUInt32LE(0) };
        delete(blockLengthBuf);
        block.buffer = new Buffer(block.length);
        fs.read(fd, block.buffer, 0, block.length, null, (err, num) => {
          state.pos += block.length;
          block.prevBlockHash = Buffer.from(readHash(block.buffer,4), 'hex');
          block.header = new Buffer(80);
          block.buffer.copy(block.header, 0, 0, 80);
          delete(block.buffer);
          block.hash = getBlockHash(block.header);
          delete(block.header);
          blocks.push(block);
          if(blocks.length % 1000 == 0) {
            console.log("\rScanned ",blocks.length,"blocks");
          }
          scanBlocks(state, callback);
        });
      });
    } else {
      callback();
    }
  });
}

var readBlocks = function(fd, callback) {

  var magic = new Buffer(4);
  fs.read(fd, magic, 0, 4, null, (err, num) => {
    fd.pos += 4;
    if(num == 4 && magic.toString("hex") == 'fabfb5da') {
      var blockLengthBuf = new Buffer(4);
      fs.read(fd, blockLengthBuf, 0, 4, null, (err, num) => {
        fd.pos += 4;
        var block = { startPos : fd.pos, length : blockLengthBuf.readUInt32LE(0)};
        block.buffer = new Buffer(block.length);
        fs.read(fd, block.buffer, 0, block.length, null, (err, num) => {
          fd.pos += num;
          readBlock(block, (readBlock) => {
            processBlock(readBlock, () => {
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

var processFile = function(fileName, callback) {
  fs.open(path.join(process.env.VERTCOIN_BLOCKS_DIR, fileName), 'r', (err, fd) => {
    var state = {pos : 0};
    state.fd = fd;
    scanBlocks(state, callback);
  });
}

var fileQueue = async.queue(processFile, 1);
fileQueue.drain = function() {
  console.log("File queue empty");
  sortBlocks(() => {
    console.log("Blocks sorted", sortedBlocks);
  });
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
