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
let ripemd = (buf : Buffer) : Buffer => new      ripemd160().update(buf).digest();
let sha256 = (buf : Buffer) : Buffer => createHash('sha256').update(buf).digest();
let sha1   = (buf : Buffer) : Buffer => createHash('sha1')  .update(buf).digest();

/*
 * Script parsing and assembling
 */
namespace Script {
  // https://en.bitcoin.it/wiki/Script
  let opcodes = ['OP_1NEGATE', 'OP_0', 'OP_1', 'OP_2', 'OP_3', 'OP_4', 'OP_5', 'OP_6', 'OP_7', 'OP_8', 'OP_9', 'OP_10', 'OP_11', 'OP_12', 'OP_13', 'OP_14', 'OP_15', 'OP_16', 'OP_NOP', 'OP_VER', 'OP_IF', 'OP_NOTIF', 'OP_VERIF', 'OP_VERNOTIF', 'OP_ELSE', 'OP_ENDIF', 'OP_VERIFY', 'OP_RETURN', 'OP_TOALTSTACK', 'OP_FROMALTSTACK', 'OP_2DROP', 'OP_2DUP', 'OP_3DUP', 'OP_2OVER', 'OP_2ROT', 'OP_2SWAP', 'OP_IFDUP', 'OP_DEPTH', 'OP_DROP', 'OP_DUP', 'OP_NIP', 'OP_OVER', 'OP_PICK', 'OP_ROLL', 'OP_ROT', 'OP_SWAP', 'OP_TUCK', 'OP_CAT', 'OP_SUBSTR', 'OP_LEFT', 'OP_RIGHT', 'OP_SIZE', 'OP_INVERT', 'OP_AND', 'OP_OR', 'OP_XOR', 'OP_EQUAL', 'OP_EQUALVERIFY', 'OP_RESERVED1', 'OP_RESERVED2', 'OP_1ADD', 'OP_1SUB', 'OP_2MUL', 'OP_2DIV', 'OP_NEGATE', 'OP_ABS', 'OP_NOT', 'OP_0NOTEQUAL', 'OP_ADD', 'OP_SUB', 'OP_MUL', 'OP_DIV', 'OP_MOD', 'OP_LSHIFT', 'OP_RSHIFT', 'OP_BOOLAND', 'OP_BOOLOR', 'OP_NUMEQUAL', 'OP_NUMEQUALVERIFY', 'OP_NUMNOTEQUAL', 'OP_LESSTHAN', 'OP_GREATERTHAN', 'OP_LESSTHANOREQUAL', 'OP_GREATERTHANOREQUAL', 'OP_MIN', 'OP_MAX', 'OP_WITHIN', 'OP_RIPEMD160', 'OP_SHA1', 'OP_SHA256', 'OP_HASH160', 'OP_HASH256', 'OP_CODESEPARATOR', 'OP_CHECKSIG', 'OP_CHECKSIGVERIFY', 'OP_CHECKMULTISIG', 'OP_CHECKMULTISIGVERIFY', 'OP_NOP1', 'OP_CHECKLOCKTIMEVERIFY', 'OP_CHECKSEQUENCEVERIFY', 'OP_NOP4', 'OP_NOP5', 'OP_NOP6', 'OP_NOP7', 'OP_NOP8', 'OP_NOP9', 'OP_NOP10'];
  export const p2wpkh_script = (pubkeyhash : string) : string[] => ['OP_DUP','OP_HASH160',pubkeyhash,'OP_EQUALVERIFY','OP_CHECKSIG'];
  export const parse = (bin : Buffer, limit : number = 4294967295) : string[] => {
    limit -= 1;
    if (bin.length === 0 || limit < 0) return [];
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
      default:                                       asm.push('OP_INVALIDOPCODE');                                                                               break;
    }
    return asm.concat(parse(bin,limit));
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
  let top = (s : any[]) : any => s[s.length - 1];
  let secp256k1 = new elliptic.ec('secp256k1');
  let verify = (pk : Buffer, sig : Buffer, msg : Buffer) : boolean => {
    try {
      let pkk = secp256k1.keyFromPublic(pk);
      try {
        if (sig[0] !== 48) throw new RangeError();
        return pkk.verify(msg,sig.slice(0,2 + sig[1])) || pkk.verify(Buffer.from([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),sig.slice(0,2 + sig[1]));
      }
      catch (_) {
        return pkk.verify(msg,sig.slice(0,-1))         || pkk.verify(Buffer.from([1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),sig.slice(0,-1));
      }
    }
    catch (_) {
      return false;
    }
  };
  class Stack {
    store : string[];
    constructor(init_store : string[] = []) { this.store = Array.from(init_store); }
    length() : number { return this.store.length; }
    isempty() : boolean { return this.length() === 0; }
    popbool() : boolean { let x = this.pop(); return x !== ''; }
    popnum() : number {
      let buf = Buffer.from(this.pop(),'hex');
      let w = (buf.length) ? buf[0] : 0;
      let x = (buf.length > 1) ? parseInt(Utils.reverse(buf.slice(1)).toString('hex'),16) : 0;
      let y = 128*x + (w & 127);
      return (w & 128) ? -y : y;
    }
    pop() : any { let x = this.store.pop(); return (x !== '00' && x !== '80') ? x : ''; }
    top(x : number = 0, remove : boolean = false) : any {
      let i = this.store.length - 1 - x;
      return remove ? this.store.splice(i,1)[0] : this.store[i];
    }
    push(x : any) {
      let y : string;
      if (typeof x === 'boolean') y = x ? '01' : '';
      else if (typeof x === 'number') {
        let xx = Math.abs(x);
        let buf = Buffer.alloc((x === 0) ? 0 : (xx < 128) ? 1 : (xx < 32768) ? 2 : (xx < 2147483648) ? 4 : 6);
        if (buf.length > 1) buf.writeUIntLE(xx >> 7,1,buf.length - 1);
        if (buf.length) {
          buf.writeUIntLE(xx & 127,0,1);
          if (x < 0) buf[0] |= 128;
        }
        y = buf.toString('hex');
      }
      else if (typeof x === 'string') y = x;
      else y = x.toString('hex');
      this.store.push(y);
    }
  };
  export const run = (scriptsig : string[], scriptpubkey : string[], buildtx : (Buffer,number) => Buffer, initstack : string[] = [], debug? : boolean) : boolean => {
    let result = true;
    let script = Array.from(scriptsig).concat(scriptpubkey);
    let subscr = Array.from(scriptpubkey);
    let stack = new Stack(initstack);
    let altstack = new Stack();
    let if_level = 0;
    let if_stack : boolean[] = [];
    if (debug) console.log(result,script,stack,if_level,if_stack);
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
        case 'OP_IF':    if_level += 1; if_stack.push( stack.popbool()); if (!top(if_stack)) while (script[0] !== 'OP_ELSE' && script[0] !== 'OP_ENDIF') script.shift(); break;
        case 'OP_NOTIF': if_level += 1; if_stack.push(!stack.popbool()); if (!top(if_stack)) while (script[0] !== 'OP_ELSE' && script[0] !== 'OP_ENDIF') script.shift(); break;
        case 'OP_ELSE':                 if_stack.push(!if_stack.pop());  if (!top(if_stack)) while (script[0] !== 'OP_ELSE' && script[0] !== 'OP_ENDIF') script.shift(); break;
        case 'OP_ENDIF': if_level -= 1; if_stack.pop(); if (if_level < 0) result = false; break;
        case 'OP_VERIFY': if (!stack.popbool()) result = false; break;
        case 'OP_RETURN': result = false; break;
        case 'OP_TOALTSTACK': altstack.push(   stack.pop()); break;
        case 'OP_FROMALTSTACK':  stack.push(altstack.pop()); break;
        case 'OP_2DROP': stack.pop(); stack.pop(); break;
        case 'OP_2DUP':  {                                                                                         let x2 = stack.pop(); let x1 = stack.pop(); stack.push(x1); stack.push(x2);                 stack.push(x1); stack.push(x2);                 break; }
        case 'OP_3DUP':  {                                                                   let x3 = stack.pop(); let x2 = stack.pop(); let x1 = stack.pop(); stack.push(x1); stack.push(x2); stack.push(x3); stack.push(x1); stack.push(x2); stack.push(x3); break; }
        case 'OP_2OVER': {                                             let x4 = stack.pop(); let x3 = stack.pop(); let x2 = stack.pop(); let x1 = stack.pop(); stack.push(x1); stack.push(x2); stack.push(x3); stack.push(x4); stack.push(x1); stack.push(x2); break; }
        case 'OP_2ROT':  { let x6 = stack.pop(); let x5 = stack.pop(); let x4 = stack.pop(); let x3 = stack.pop(); let x2 = stack.pop(); let x1 = stack.pop(); stack.push(x3); stack.push(x4); stack.push(x5); stack.push(x6); stack.push(x1); stack.push(x2); break; }
        case 'OP_2SWAP': {                                             let x4 = stack.pop(); let x3 = stack.pop(); let x2 = stack.pop(); let x1 = stack.pop(); stack.push(x3); stack.push(x4);                                 stack.push(x1); stack.push(x2); break; }
        case 'OP_DEPTH': stack.push(stack.length()); break;
        case 'OP_DROP': stack.pop(); break;
        case 'OP_DUP':  {                                             let x1 = stack.pop(); stack.push(x1); stack.push(x1);                 break; }
        case 'OP_NIP':  {                       let x2 = stack.pop(); let x1 = stack.pop(); stack.push(x2);                                 break; }
        case 'OP_PICK': {                                             let  n = stack.pop(); stack.push(stack.top(n));                       break; }
        case 'OP_ROLL': {                                             let  n = stack.pop(); stack.push(stack.top(n,true));                  break; }
        case 'OP_ROT':  { let x3 = stack.pop(); let x2 = stack.pop(); let x1 = stack.pop(); stack.push(x2); stack.push(x3); stack.push(x1); break; }
        case 'OP_SWAP': {                       let x2 = stack.pop(); let x1 = stack.pop(); stack.push(x2); stack.push(x1);                 break; }
        case 'OP_TUCK': {                       let x2 = stack.pop(); let x1 = stack.pop(); stack.push(x2); stack.push(x1); stack.push(x2); break; }
        case 'OP_SIZE': stack.push(Buffer.from(stack.top(),'hex').length.toString(16)); break;
        case 'OP_EQUAL': stack.push(stack.pop() === stack.pop()); break;
        case 'OP_EQUALVERIFY': script.unshift('OP_VERIFY'); script.unshift('OP_EQUAL'); break;
        case 'OP_1ADD':                               stack.push(         stack.popnum() + 1);                              break;
        case 'OP_1SUB':                               stack.push(         stack.popnum() - 1);                              break;
        case 'OP_2MUL':                               stack.push(         stack.popnum() * 2);              result = false; break;
        case 'OP_2DIV':                               stack.push(         stack.popnum() / 2);              result = false; break;
        case 'OP_NEGATE':                             stack.push(       - stack.popnum());                                  break;
        case 'OP_ABS':                                stack.push(Math.abs(stack.popnum()));                                 break;
        case 'OP_NOT':                                stack.push(         stack.popnum() === 0);                            break;
        case 'OP_0NOTEQUAL':                          stack.push(       !(stack.popnum() === 0));                           break;
        case 'OP_ADD':                                stack.push(         stack.popnum() + stack.popnum());                 break;
        case 'OP_SUB':                                stack.push(       - stack.popnum() + stack.popnum());                 break;
        case 'OP_MUL':                                stack.push(         stack.popnum() * stack.popnum()); result = false; break;
        case 'OP_DIV':     { let x = stack.popnum();  stack.push(         stack.popnum() /  x);             result = false; break; }
        case 'OP_MOD':     { let x = stack.popnum();  stack.push(         stack.popnum() %  x);             result = false; break; }
        case 'OP_LSHIFT':  { let x = stack.popnum();  stack.push(         stack.popnum() << x);             result = false; break; }
        case 'OP_RSHIFT':  { let x = stack.popnum();  stack.push(         stack.popnum() >> x);             result = false; break; }
        case 'OP_BOOLAND': { let x = stack.popbool(); stack.push(         stack.popbool() && x);                            break; }
        case 'OP_BOOLOR':  { let x = stack.popbool(); stack.push(         stack.popbool() || x);                            break; }
        case 'OP_NUMEQUAL':                           stack.push(         stack.popnum() === stack.popnum());               break;
        case 'OP_NUMEQUALVERIFY': script.unshift('OP_VERIFY'); script.unshift('OP_NUMEQUAL'); break;
        case 'OP_NUMNOTEQUAL':        stack.push(stack.popnum() !== stack.popnum()); break;
        case 'OP_LESSTHAN':           stack.push(stack.popnum() >   stack.popnum()); break;
        case 'OP_GREATERTHAN':        stack.push(stack.popnum() <   stack.popnum()); break;
        case 'OP_LESSTHANOREQUAL':    stack.push(stack.popnum() >=  stack.popnum()); break;
        case 'OP_GREATERTHANOREQUAL': stack.push(stack.popnum() <=  stack.popnum()); break;
        case 'OP_MIN':    { let x   = stack.popnum(); let y   = stack.popnum();                         stack.push((x < y) ? x : y);     break; }
        case 'OP_MAX':    { let x   = stack.popnum(); let y   = stack.popnum();                         stack.push((x > y) ? x : y);     break; }
        case 'OP_WITHIN': { let max = stack.popnum(); let min = stack.popnum(); let x = stack.popnum(); stack.push(min <= x && x < max); break; }
        case 'OP_RIPEMD160': stack.push(       ripemd(Buffer.from(stack.pop(),'hex')) .toString('hex')); break;
        case 'OP_SHA1':      stack.push(       sha1  (Buffer.from(stack.pop(),'hex')) .toString('hex')); break;
        case 'OP_SHA256':    stack.push(       sha256(Buffer.from(stack.pop(),'hex')) .toString('hex')); break;
        case 'OP_HASH160':   stack.push(ripemd(sha256(Buffer.from(stack.pop(),'hex'))).toString('hex')); break;
        case 'OP_HASH256':   stack.push(sha256(sha256(Buffer.from(stack.pop(),'hex'))).toString('hex')); break;
        case 'OP_CODESEPARATOR': subscr = Array.from(script); break;
        case 'OP_CHECKSIG': {
          let pk = Buffer.from(stack.pop(),'hex'); let sig = Buffer.from(stack.pop(),'hex');
          stack.push(verify(pk,sig,sha256(sha256(buildtx(assemble(subscr.filter(x => x !== 'OP_CODESEPARATOR')),sig[sig.length - 1])))));
          break;
        }
        case 'OP_CHECKSIGVERIFY': script.unshift('OP_VERIFY'); script.unshift('OP_CHECKSIG'); break;
        case 'OP_CHECKMULTISIG': {
          let M = stack.popnum(); let pks = []; for (let i = 0 ; i < M ; i += 1) pks.push(stack.pop());
          let N = stack.popnum(); let shs = []; for (let i = 0 ; i < N ; i += 1) shs.push(stack.pop());
          if (!stack.isempty() && stack.top() === '') stack.pop();
          let n = 0;
          for (let sh of shs) {
            let sig = Buffer.from(sh,'hex');
            for (let pk of pks) {
              if (verify(Buffer.from(pk,'hex'),sig,sha256(sha256(buildtx(assemble(subscr.filter(x => x !== 'OP_CODESEPARATOR')),sig[sig.length - 1]))))) {
                n += 1;
                break;
              }
            }
          }
          stack.push(n === N);
          break;
        }
        case 'OP_CHECKMULTISIGVERIFY': script.unshift('OP_VERIFY'); script.unshift('OP_CHECKMULTISIG'); break;
        case 'OP_NOP1':  break;
        case 'OP_CHECKLOCKTIMEVERIFY': break;
        case 'OP_CHECKSEQUENCEVERIFY': break;
        case 'OP_NOP4':  break;
        case 'OP_NOP5':  break;
        case 'OP_NOP6':  break;
        case 'OP_NOP7':  break;
        case 'OP_NOP8':  break;
        case 'OP_NOP9':  break;
        case 'OP_NOP10': break;
        case 'OP_INVALIDOPCODE': result = false; break;
        default: throw new Error("unsupported opcode: " + op); break;
      }
      if (debug) console.log(result,script,stack,if_level,if_stack);
    }
    if (!stack.isempty()) result = result && stack.pop();
    if (result                                  &&
        !stack.isempty()                        &&
        scriptpubkey   .length === 3            &&
        scriptpubkey[0]        === 'OP_HASH160' &&
        scriptpubkey[1].length === 40           &&
        scriptpubkey[2]        === 'OP_EQUAL'   &&
        scriptsig.map(x => x.substr(0,2) !== 'OP').reduce((x,y) => x && y,true)) {
      let scriptsig2 = Array.from(scriptsig);
      let scriptpubkey2 = parse(Buffer.from(scriptsig2.pop(),'hex'));
      if (initstack.length) {
        console.assert(scriptpubkey2.length === 2 && scriptpubkey2[0] === 'OP_FALSE');
        scriptpubkey2 = p2wpkh_script(scriptpubkey2[1]);
      }
      result = run(scriptsig2,scriptpubkey2,buildtx,initstack,debug);
    }
    if (!result && scriptsig.length) result = run([],scriptpubkey,buildtx,initstack,debug);
    return result;
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
    witness  : Buffer[][];
    locktime : number;
  };
  let render = (prefix : number, xlen : number, x : number) : Buffer => {
    let buf : Buffer; let len = (xlen > 6) ? 6 : xlen;
    if (prefix === undefined) { buf = Buffer.alloc(    xlen);                              if (x < 0) { buf.writeIntLE(x,0,len) ; buf.writeIntLE(-1,    len,xlen - len); } else buf.writeUIntLE(x,0,len); }
    else {                      buf = Buffer.alloc(1 + xlen); buf.writeUIntLE(prefix,0,1); if (x < 0) { buf.writeIntLE(x,1,len) ; buf.writeIntLE(-1,1 + len,xlen - len); } else buf.writeUIntLE(x,1,len); }
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
      else if (tx.vin[i].vout !== 4294967295) {
                tx.vin[i].scriptSig.asm = Script.parse(tx.vin[i].scriptSig.hex);
      }
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
    tx.witness = Array.from(Array(vincnt).keys()).map(_ => []);
    if (tx.flag) for (let i = 0 ; i < vincnt ; i += 1) {
      let len : number; [len,      bin] = Utils.parsevarint(bin);
      tx.witness[i] = Array(len);
      for (let j = 0 ; j < tx.witness[i].length ; j += 1) {
        [len,                      bin] = Utils.parsevarint(bin);
        [tx.witness[i][j],         bin] = Utils.parsefixlen(bin,len);
      }
    }
    [tx.locktime,                  bin] = Utils.parsefixint(bin,4);
    if (bin.length) throw new Error("transaction parsing failed");
    return tx;
  };
  let enclen = (buf : Buffer) : Buffer => Buffer.concat([varint(buf.length),buf]);
  export const assemble = (tx : parsed) : Buffer => {
    let bin : Buffer[] = [];
    bin.push(fixint(tx.version,4));
    if (tx.flag) bin.push(Buffer.from([0,1]));
    bin.push(varint(tx.vin.length));
    for (let vin of tx.vin) {
      bin.push(Utils.reverse(vin.txid));
      bin.push(       fixint(vin.vout,4));
      bin.push(       enclen(vin.scriptSig.hex));
      bin.push(       fixint(vin.sequence,4));
    }
    bin.push(varint(tx.vout.length));
    for (let vout of tx.vout) {
      bin.push(fixint(vout.value,8));
      bin.push(enclen(vout.scriptPubKey.hex));
    }
    if (tx.flag) for (let witness of tx.witness) {
      bin.push(varint(witness.length));
      for (let item of witness) bin.push(enclen(item));
    }
    bin.push(fixint(tx.locktime,4));
    return Buffer.concat(bin);
  };
  export const verify = (tx : parsed, from : parsed[], debug? : boolean) : boolean => {
    for (let i = 0 ; i < tx.vin.length ; i += 1) {
      let scriptSig = tx.vin[i].scriptSig.asm;
      let scriptPubKey = from[i].vout[tx.vin[i].vout].scriptPubKey.asm;
      let initStack = tx.witness[i].map(x => x.toString('hex'));
      let buildtx : (Buffer,number) => Buffer;
           if (tx.flag && scriptPubKey.length === 3 && scriptPubKey[0] === 'OP_HASH160' && scriptPubKey[1].length === 40 && scriptPubKey[2] === 'OP_EQUAL') {
        console.assert(scriptSig.length === 1);
        console.assert(tx.witness[i].length === 2);
        buildtx = (_,hashtype) => {
          let bin : Buffer[] = [];
          bin.push(fixint(tx.version,4));                                                                                                      // 1. nVersion of the transaction (4-byte little endian)
          bin.push(sha256(sha256(Buffer.concat(tx.vin.map(vin => Buffer.concat([Utils.reverse(      vin.txid),fixint(      vin.vout,4)])))))); // 2. hashPrevouts (32-byte hash)
          bin.push(sha256(sha256(Buffer.concat(tx.vin.map(vin => fixint(vin.sequence,4))))));                                                  // 3. hashSequence (32-byte hash)
          bin.push(                                              Buffer.concat([Utils.reverse(tx.vin[i].txid),fixint(tx.vin[i].vout,4)]));     // 4. outpoint (32-byte hash + 4-byte little endian)
          let scriptCode = Script.parse(Buffer.from(scriptSig[0],'hex'));                                                                      // 5. scriptCode of the input (serialized as scripts inside CTxOuts)
          console.assert(scriptCode.length === 2 && scriptCode[0] === 'OP_FALSE' && scriptCode[1].length === 40);
          bin.push(enclen(Script.assemble(Script.p2wpkh_script(scriptCode[1]))));
          bin.push(fixint(from[i].vout[tx.vin[i].vout].value,8));                                                                              // 6. value of the output spent by this input (8-byte little endian)
          bin.push(fixint(tx.vin[i].sequence,4));                                                                                              // 7. nSequence of the input (4-byte little endian)
          bin.push(sha256(sha256(Buffer.concat(tx.vout.map(vout => Buffer.concat([fixint(vout.value,8),enclen(vout.scriptPubKey.hex)]))))));   // 8. hashOutputs (32-byte hash)
          bin.push(fixint(tx.locktime,4));                                                                                                     // 9. nLocktime of the transaction (4-byte little endian)
          bin.push(fixint(hashtype,4));                                                                                                        // 10. sighash type of the signature (4-byte little endian)
          if (debug) console.log(JSON.stringify(bin,(key,value) => (value.type === 'Buffer') ? Buffer.from(value).toString('hex') : value,2));
          return Buffer.concat(bin);
        };
      }
      else buildtx = (subscr,hashtype) => {
        let t = parse(assemble(tx),true);
        t.vin[i].scriptSig.hex =              subscr;
        t.vin[i].scriptSig.asm = Script.parse(subscr);
        switch (hashtype & 31) {
          case 2:  // SIGHASH_NONE
            t.vout = [];
            for (let j = 0 ; j < t.vin.length ; j += 1) if (j !== i) t.vin[j].sequence = 0;
            break;
          case 3:  // SIGHASH_SINGLE
            t.vout = t.vout.slice(0,i + 1);
            for (let j = 0 ; j < i ; j += 1) t.vout[j] = { value: -1, scriptPubKey: { asm: [], hex: Buffer.alloc(0) } };
            for (let j = 0 ; j < t.vin.length ; j += 1) if (j !== i) t.vin[j].sequence = 0;
            break;
          default: // SIGHASH_ALL
            break;
        }
        // SIGHASH_ANYONECANPAY
        if (hashtype & 128) t.vin = t.vin.slice(i,i + 1);
        if (debug) console.log(JSON.stringify(t,(key,value) => (value.type === 'Buffer') ? Buffer.from(value).toString('hex') : value,2));
        return Buffer.concat([assemble(t),fixint(hashtype,4)]);
      };
      if (!Script.run(scriptSig,scriptPubKey,buildtx,initStack,debug)) return false;
    }
    return true;
  };
};

let btclient = new bitcoincore({ username: 'chelpis', password: 'chelpis' });
let main = async () => {
  for (let i = 306736 ; ; i += 1) {
    let block = await btclient.getBlock(await btclient.getBlockHash(i));
    for (let j = 1 ; j < block.tx.length ; j += 1) {
      console.log(i,j);
      let tx = Transaction.parse(Buffer.from(await btclient.getRawTransaction(block.tx[j]),'hex'));
      let from : Transaction.parsed[] = [];
      for (let vin of tx.vin) from.push(Transaction.parse(Buffer.from(await btclient.getRawTransaction(vin.txid.toString('hex')),'hex')));
      if (!Transaction.verify(tx,from)) {
        console.log(JSON.stringify(tx,(key,value) => (value.type === 'Buffer') ? Buffer.from(value).toString('hex') : value,2));
        Transaction.verify(tx,from,true);
        throw new Error("transaction verification failed");
      }
    }
  }
};

main();

