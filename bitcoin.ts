/*
 * Bitcoin transaction verification
 */

import bitcoincore  = require('bitcoin-core');
import elliptic     = require('elliptic');
import ripemd160    = require('ripemd160');

import {createHash} from 'crypto';

/*
 * Utilities
 */
namespace Utils {
  export const reverse = (x : Buffer) : Buffer => Buffer.from(new Uint8Array(x).reverse());
  export const parsefixlen = (x : Buffer, n : number) : [Buffer,Buffer] => [                 x.slice(0,n),                     x.slice(n)];
  export const parsefixint = (x : Buffer, n : number) : [number,Buffer] => [parseInt(reverse(x.slice(0,n)).toString('hex'),16),x.slice(n)];
  export const parsevarint = (x : Buffer) : [number,Buffer] => {
    let y : number; [y,x] = parsefixint(x,1);
    switch (y) {
      case 253:     [y,x] = parsefixint(x,2); break;
      case 254:     [y,x] = parsefixint(x,4); break;
      case 255:     [y,x] = parsefixint(x,8); break;
      default:                                break;
    }
    return [y,x];
  };
};

/*
 * Script parsing and assembling
 */
namespace Script {
  // https://en.bitcoin.it/wiki/Script
  let opcodes = ['OP_1NEGATE', 'OP_0', 'OP_1', 'OP_2', 'OP_3', 'OP_4', 'OP_5', 'OP_6', 'OP_7', 'OP_8', 'OP_9', 'OP_10', 'OP_11', 'OP_12', 'OP_13', 'OP_14', 'OP_15', 'OP_16', 'OP_NOP', 'OP_VER', 'OP_IF', 'OP_NOTIF', 'OP_VERIF', 'OP_VERNOTIF', 'OP_ELSE', 'OP_ENDIF', 'OP_VERIFY', 'OP_RETURN', 'OP_TOALTSTACK', 'OP_FROMALTSTACK', 'OP_2DROP', 'OP_2DUP', 'OP_3DUP', 'OP_2OVER', 'OP_2ROT', 'OP_2SWAP', 'OP_IFDUP', 'OP_DEPTH', 'OP_DROP', 'OP_DUP', 'OP_NIP', 'OP_OVER', 'OP_PICK', 'OP_ROLL', 'OP_ROT', 'OP_SWAP', 'OP_TUCK', 'OP_CAT', 'OP_SUBSTR', 'OP_LEFT', 'OP_RIGHT', 'OP_SIZE', 'OP_INVERT', 'OP_AND', 'OP_OR', 'OP_XOR', 'OP_EQUAL', 'OP_EQUALVERIFY', 'OP_RESERVED1', 'OP_RESERVED2', 'OP_1ADD', 'OP_1SUB', 'OP_2MUL', 'OP_2DIV', 'OP_NEGATE', 'OP_ABS', 'OP_NOT', 'OP_0NOTEQUAL', 'OP_ADD', 'OP_SUB', 'OP_MUL', 'OP_DIV', 'OP_MOD', 'OP_LSHIFT', 'OP_RSHIFT', 'OP_BOOLAND', 'OP_BOOLOR', 'OP_NUMEQUAL', 'OP_NUMEQUALVERIFY', 'OP_NUMNOTEQUAL', 'OP_LESSTHAN', 'OP_GREATERTHAN', 'OP_LESSTHANOREQUAL', 'OP_GREATERTHANOREQUAL', 'OP_MIN', 'OP_MAX', 'OP_WITHIN', 'OP_RIPEMD160', 'OP_SHA1', 'OP_SHA256', 'OP_HASH160', 'OP_HASH256', 'OP_CODESEPARATOR', 'OP_CHECKSIG', 'OP_CHECKSIGVERIFY', 'OP_CHECKMULTISIG', 'OP_CHECKMULTISIGVERIFY', 'OP_NOP1', 'OP_CHECKLOCKTIMEVERIFY', 'OP_CHECKSEQUENCEVERIFY', 'OP_NOP4', 'OP_NOP5', 'OP_NOP6', 'OP_NOP7', 'OP_NOP8', 'OP_NOP9', 'OP_NOP10'];
  export const parse = (bin : Buffer) : string[] => {
    if (bin.length === 0) return [];
    let op : number; [op,bin] = Utils.parsefixint(bin,1);
    let asm : string[] = [];
    let buf : Buffer;
         if ( 1 <= op && op <=  75) {                                                      [buf,bin] = Utils.parsefixlen(bin,op); asm.push(buf.toString('hex')); }
    else if (79 <= op && op <= 185)                  asm.push(opcodes[op - 79]);
    else switch (op) {
      case   0:                                      asm.push('OP_FALSE'); break;
      case  76: [op,bin] = Utils.parsefixint(bin,1); asm.push('OP_PUSHDATA1(' + op + ')'); [buf,bin] = Utils.parsefixlen(bin,op); asm.push(buf.toString('hex')); break;
      case  77: [op,bin] = Utils.parsefixint(bin,2); asm.push('OP_PUSHDATA2(' + op + ')'); [buf,bin] = Utils.parsefixlen(bin,op); asm.push(buf.toString('hex')); break;
      case  78: [op,bin] = Utils.parsefixint(bin,4); asm.push('OP_PUSHDATA4(' + op + ')'); [buf,bin] = Utils.parsefixlen(bin,op); asm.push(buf.toString('hex')); break;
      default: throw new Error("unknown opcode: " + op); break;
    }
    return asm.concat(parse(bin));
  };
  let render = (opcode : number, buflensize : number, buf : Buffer) : Buffer => {
    let bufs : Buffer[] = [];
    if (opcode !== undefined) {
      bufs.push(Buffer.from([opcode]));
    }
    if (buf !== undefined) {
      let len = Buffer.alloc(buflensize);
      len.writeUIntLE(buf.length,0,buflensize);
      bufs.push(len);
      bufs.push(buf);
    }
    return Buffer.concat(bufs);
  };
  export const assemble = (asmin : string[]) : Buffer => {
    let asm = Array.from(asmin);
    let bin : Buffer[] = [];
    while (asm.length) {
      let op = asm.shift();
           if (op              === 'OP_FALSE')     { bin.push(render(0,         undefined, undefined)); }
      else if (op.substr(0,2)  !== 'OP')           { bin.push(render(undefined, 1,         Buffer.from(op,         'hex'))); }
      else if (op.substr(0,12) === 'OP_PUSHDATA1') { bin.push(render(76,        1,         Buffer.from(asm.shift(),'hex'))); }
      else if (op.substr(0,12) === 'OP_PUSHDATA2') { bin.push(render(77,        2,         Buffer.from(asm.shift(),'hex'))); }
      else if (op.substr(0,12) === 'OP_PUSHDATA4') { bin.push(render(78,        4,         Buffer.from(asm.shift(),'hex'))); }
      else {    bin.push(render(opcodes.findIndex(x => (x === op)) + 79,        undefined, undefined)); }
    }
    return Buffer.concat(bin);
  };
  let secp256k1 = new elliptic.ec('secp256k1');
  let ripemd = (buf : Buffer) : Buffer => new      ripemd160().update(buf).digest();
  let sha256 = (buf : Buffer) : Buffer => createHash('sha256').update(buf).digest();
  export const run = (scriptsig : string[], scriptpubkey : string[], buildtx : (Buffer,number) => Buffer, debug? : boolean) : boolean => {
    let flag = true;
    let script = Array.from(scriptsig).concat(scriptpubkey);
    let subscr = Array.from(scriptpubkey);
    let stack = [];
    if (debug) console.log(flag,script,stack);
    while (script.length) {
      let op = script.shift();
           if (op.substr(0,2)  !== 'OP')          stack.push(op);
      else if (op.substr(0,11) === 'OP_PUSHDATA') stack.push(script.shift());
      else switch (op) {
        case 'OP_FALSE':   stack.push(''); break;
        case 'OP_1NEGATE': stack.push(-1); break;
        case 'OP_0':       stack.push(0);  break;
        case 'OP_1':       stack.push(1);  break;
        case 'OP_2':       stack.push(2);  break;
        case 'OP_3':       stack.push(3);  break;
        case 'OP_4':       stack.push(4);  break;
        case 'OP_5':       stack.push(5);  break;
        case 'OP_6':       stack.push(6);  break;
        case 'OP_7':       stack.push(7);  break;
        case 'OP_8':       stack.push(8);  break;
        case 'OP_9':       stack.push(9);  break;
        case 'OP_10':      stack.push(10); break;
        case 'OP_11':      stack.push(11); break;
        case 'OP_12':      stack.push(12); break;
        case 'OP_13':      stack.push(13); break;
        case 'OP_14':      stack.push(14); break;
        case 'OP_15':      stack.push(15); break;
        case 'OP_16':      stack.push(16); break;
        case 'OP_NOP':                     break;
        case 'OP_VERIFY':  if (stack.pop() !== true) flag = false; break;
        case 'OP_RETURN':                            flag = false; break;
        case 'OP_DUP': let top = stack.pop(); stack.push(top); stack.push(top); break;
        case 'OP_EQUAL': let x = stack.pop(); let y = stack.pop(); stack.push(x === y); break;
        case 'OP_EQUALVERIFY': script.unshift('OP_VERIFY'); script.unshift('OP_EQUAL'); break;
        case 'OP_RIPEMD160': stack.push(       ripemd(Buffer.from(stack.pop(),'hex')) .toString('hex')); break;
        case 'OP_SHA256':    stack.push(       sha256(Buffer.from(stack.pop(),'hex')) .toString('hex')); break;
        case 'OP_HASH160':   stack.push(ripemd(sha256(Buffer.from(stack.pop(),'hex'))).toString('hex')); break;
        case 'OP_HASH256':   stack.push(sha256(sha256(Buffer.from(stack.pop(),'hex'))).toString('hex')); break;
        case 'OP_CODESEPARATOR': subscr = Array.from(script); break;
        case 'OP_CHECKSIG':
          let pk = secp256k1.keyFromPublic(stack.pop(),'hex');
          let buf = Buffer.from(stack.pop(),'hex');
          let sig = buf.slice(0,-1);
          let hashtype = buf[buf.length - 1];
          let scr = assemble(subscr.filter(x => x !== 'OP_SEPARATOR'));
          if (debug) console.log('subscript:', parse(scr));
          stack.push(pk.verify(sha256(sha256(buildtx(scr,hashtype))),sig));
          break;
        case 'OP_CHECKSIGVERIFY': script.unshift('OP_VERIFY'); script.unshift('OP_CHECKSIG'); break;
        default: throw new Error("unsupported opcode: " + op); break;
      }
      if (debug) console.log(flag,script,stack);
    }
    return flag && stack.pop();
  };
};

/*
 * Transaction parsing and assembling
 */
namespace Transaction {
  export interface parsed {
    version  : number;
    flag     : boolean;
    vin      : {
      txid         : Buffer;
      vout         : number;
      scriptSig    : { asm : string[]; hex : Buffer ; };
      sequence     : number;
    }[];
    vout     : {
      value        : number;
      scriptPubKey : { asm : string[]; hex : Buffer; };
    }[];
    locktime : number;
  };
  export const parse = (bin : Buffer, vrfy : boolean = false) : parsed => {
    let tx : any = {};
    [tx.version,                   bin] = Utils.parsefixint(bin,4);
    [tx.flag,                      bin] = (bin[0] === 0 && bin[1] === 1) ? [true,bin.slice(2)] : [false,bin];
    let vincnt : number; [vincnt,  bin] = Utils.parsevarint(bin);
    tx.vin = [];
    for (let i = 0 ; i < vincnt ; i += 1) {
      tx.vin[i] = { scriptSig: { asm: [] } };
      let buf : Buffer; [buf,      bin] = Utils.parsefixlen(bin,32); tx.vin[i].txid = Utils.reverse(buf);
      [tx.vin[i].vout,             bin] = Utils.parsefixint(bin,4);
      let len : number; [len,      bin] = Utils.parsevarint(bin);
      [tx.vin[i].scriptSig.hex,    bin] = Utils.parsefixlen(bin,len);
      if (vrfy) tx.vin[i].scriptSig.hex = Buffer.alloc(0);
      else      tx.vin[i].scriptSig.asm = Script.parse(tx.vin[i].scriptSig.hex);
      [tx.vin[i].sequence,         bin] = Utils.parsefixint(bin,4);
    }
    let voutcnt : number; [voutcnt,bin] = Utils.parsevarint(bin);
    tx.vout = [];
    for (let i = 0 ; i < voutcnt ; i += 1) {
      tx.vout[i] = { scriptPubKey: {} };
      [tx.vout[i].value,           bin] = Utils.parsefixint(bin,8);
      let len : number; [len,      bin] = Utils.parsevarint(bin);
      [tx.vout[i].scriptPubKey.hex,bin] = Utils.parsefixlen(bin,len);
      tx.vout[i].scriptPubKey.asm = Script.parse(tx.vout[i].scriptPubKey.hex);
    }
    if (tx.flag) throw new Error("flagged transactions not supported");
    [tx.locktime,                  bin] = Utils.parsefixint(bin,4);
    if (bin.length) throw new Error("transaction parsing failed");
    return tx;
  };
  let render = (prefix : number, xlen : number, x : number) : Buffer => {
    let buf : Buffer;
    if (prefix === undefined) { buf = Buffer.alloc(    xlen);                              buf.writeUIntLE(x,0,(xlen > 6) ? 6 : xlen); }
    else {                      buf = Buffer.alloc(1 + xlen); buf.writeUIntLE(prefix,0,1); buf.writeUIntLE(x,1,(xlen > 6) ? 6 : xlen); }
    return buf;
  };
  let fixint = (x : number, n : number) : Buffer => {
    switch (n) {
      case 1: return render(undefined,1,x); break;
      case 2: return render(undefined,2,x); break;
      case 4: return render(undefined,4,x); break;
      case 8: return render(undefined,8,x); break;
      default: throw new RangeError(); break;
    }
  };
  let varint = (x : number) : Buffer => {
         if (x <          0) { throw new RangeError(); }
    else if (x <        253) { return render(undefined,1,x); }
    else if (x <      65536) { return render(253,      2,x); }
    else if (x < 4294967296) { return render(254,      4,x); }
    else {                     return render(255,      8,x); }
  };
  export const assemble = (tx : parsed) : Buffer => {
    let bin : Buffer[] = [];
    bin.push(fixint(tx.version,4));
    bin.push(varint(tx.vin.length));
    for (let i = 0 ; i < tx.vin.length ; i += 1) {
      bin.push(Utils.reverse(tx.vin[i].txid));
      bin.push(       fixint(tx.vin[i].vout,4));
      bin.push(       varint(tx.vin[i].scriptSig.hex.length));
      bin.push(              tx.vin[i].scriptSig.hex);
      bin.push(       fixint(tx.vin[i].sequence,4));
    }
    bin.push(varint(tx.vout.length));
    for (let vout of tx.vout) {
      bin.push(fixint(vout.value,8));
      bin.push(varint(vout.scriptPubKey.hex.length));
      bin.push(       vout.scriptPubKey.hex);
    }
    bin.push(fixint(tx.locktime,4));
    return Buffer.concat(bin);
  };
  export const verify = (tx : parsed, from : parsed[], debug? : boolean) : boolean => {
    for (let i = 0 ; i < tx.vin.length ; i += 1) {
      if (!Script.run(tx.vin[i].scriptSig.asm, from[i].vout[tx.vin[i].vout].scriptPubKey.asm, (subscr,hashtype) => {
        let t = parse(assemble(tx),true);
        t.vin[i].scriptSig.hex =              subscr;
        t.vin[i].scriptSig.asm = Script.parse(subscr);
        switch (hashtype%32) {
          case 1:  // SIGHASH_ALL
            break;
          case 2:  // SIGHASH_NONE
            t.vout = [];
            for (let j = 0 ; j < t.vin.length ; j += 1) if (j !== i) t.vin[j].sequence = 0;
            break;
          case 3:  // SIGHASH_SINGLE
            t.vout = new Array(i + 1);
            for (let j = 0 ; j < i ; j += 1) t.vout[j] = { value: -1, scriptPubKey: { asm: [], hex: Buffer.alloc(0) } };
            for (let j = 0 ; j < t.vin.length ; j += 1) if (j !== i) t.vin[j].sequence = 0;
            break;
          default: // SIGHASH_ANYONECANPAY
            throw new Error("unsupported hashtype: " + hashtype);
            break;
        }
        return Buffer.concat([assemble(t),fixint(hashtype,4)]);
      },debug)) return false;
    }
    return true;
  };
};

let btclient = new bitcoincore({ username: 'chelpis', password: 'chelpis' });
let main = async () => {
  for (let i = 1 ; ; i += 1) {
    let block = await btclient.getBlock(await btclient.getBlockHash(i));
    for (let j = 1 ; j < block.tx.length ; j += 1) {
      let tx = Transaction.parse(Buffer.from(await btclient.getRawTransaction(block.tx[j]),'hex'));
      let from : Transaction.parsed[] = [];
      for (let vin of tx.vin) from.push(Transaction.parse(Buffer.from(await btclient.getRawTransaction(vin.txid.toString('hex')),'hex')));
      console.log(i,j);
      if (!Transaction.verify(tx,from)) {
        console.log(JSON.stringify(tx,(key,value) => (value.type === 'Buffer') ? Buffer.from(value).toString('hex') : value,2));
        Transaction.verify(tx,from,true);
        throw new Error("transaction verification failed");
      }
    }
  }
};

main();

