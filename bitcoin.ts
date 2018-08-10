/*
 * Bitcoin transaction verification
 */

import bitcoincore  = require('bitcoin-core');
import elliptic     = require('elliptic');
import ripemd160    = require('ripemd160');

import {createHash} from 'crypto';
import {sprintf}    from 'sprintf-js';

let id = (x : any) : any => x;
let revend = (s : string) : string => {
  if (s.length%2 !== 0) throw new RangeError();
  let r = ''; for (let i = 0 ; i < s.length ; i += 2) r = s.substr(i,2) + r;
  return r;
};
let ripemd = (msg : string, enc = 'hex') : string => new      ripemd160().update(Buffer.from(msg,enc)).digest('hex');
let sha256 = (msg : string, enc = 'hex') : string => createHash('sha256').update(Buffer.from(msg,enc)).digest('hex');

let fixint = (x : number, n : number) : string => revend(sprintf(sprintf('%%0%dx',2*n),x));
let varint = (x : number) : string => (x < 0) ? '' : (x < 253) ? fixint(x,1) : (x < 65536) ? 'fd' + fixint(x,2) : (x < 4294967296) ? 'fe' + fixint(x,4) : 'ff' + fixint(x,8);
let parsefixlen = (s : string, n : number, f = id) : [string,string] => [f(s.substr(0,2*n)),s.substring(2*n)];
let parsefixint = (s : string, n : number) : [number,string] => [parseInt(revend(s.substr(0,2*n)),16),s.substring(2*n)];
let parsevarint = (s : string) : [number,string] => {
  let t : number; [t,s] = parsefixint(s,1);
  switch (t) {
    case 253:     [t,s] = parsefixint(s,2); break;
    case 254:     [t,s] = parsefixint(s,4); break;
    case 255:     [t,s] = parsefixint(s,8); break;
    default:                                break;
  }
  return [t,s];
};
let parseflag = (s : string) : [boolean,string] => (s.substr(0,4) === '0001') ? [true,s.substring(4)] : [false,s];
let filtersig = (s : string) : string => {
  if (s.substr(0,2) === '30') {
    let n = s.length/2;
    let t = s.split('[');
    if (t.length === 2) switch(t[1]) {
      case 'ALL]':          s = t[0] + '01'; break;
      case 'NONE]':         s = t[0] + '02'; break;
      case 'SINGLE]':       s = t[0] + '03'; break;
      case 'ANYONECANPAY]': s = t[0] + '80'; break;
      default:                               break;
    }
    else if (n === 71 || n === 72 || n === 73) switch (s.substring(2*(n - 1))) {
      case '01': s = s.substr(0,2*(n - 1)) + '[ALL]';          break;
      case '02': s = s.substr(0,2*(n - 1)) + '[NONE]';         break;
      case '03': s = s.substr(0,2*(n - 1)) + '[SINGLE]';       break;
      case '80': s = s.substr(0,2*(n - 1)) + '[ANYONECANPAY]'; break;
      default:                                                 break;
    }
  }
  return s;
};

/*
 * https://en.bitcoin.it/wiki/Script
 */
let opcodes = ['OP_1NEGATE', 'OP_0', 'OP_1', 'OP_2', 'OP_3', 'OP_4', 'OP_5', 'OP_6', 'OP_7', 'OP_8', 'OP_9', 'OP_10', 'OP_11', 'OP_12', 'OP_13', 'OP_14', 'OP_15', 'OP_16', 'OP_NOP', 'OP_VER', 'OP_IF', 'OP_NOTIF', 'OP_VERIF', 'OP_VERNOTIF', 'OP_ELSE', 'OP_ENDIF', 'OP_VERIFY', 'OP_RETURN', 'OP_TOALTSTACK', 'OP_FROMALTSTACK', 'OP_2DROP', 'OP_2DUP', 'OP_3DUP', 'OP_2OVER', 'OP_2ROT', 'OP_2SWAP', 'OP_IFDUP', 'OP_DEPTH', 'OP_DROP', 'OP_DUP', 'OP_NIP', 'OP_OVER', 'OP_PICK', 'OP_ROLL', 'OP_ROT', 'OP_SWAP', 'OP_TUCK', 'OP_CAT', 'OP_SUBSTR', 'OP_LEFT', 'OP_RIGHT', 'OP_SIZE', 'OP_INVERT', 'OP_AND', 'OP_OR', 'OP_XOR', 'OP_EQUAL', 'OP_EQUALVERIFY', 'OP_RESERVED1', 'OP_RESERVED2', 'OP_1ADD', 'OP_1SUB', 'OP_2MUL', 'OP_2DIV', 'OP_NEGATE', 'OP_ABS', 'OP_NOT', 'OP_0NOTEQUAL', 'OP_ADD', 'OP_SUB', 'OP_MUL', 'OP_DIV', 'OP_MOD', 'OP_LSHIFT', 'OP_RSHIFT', 'OP_BOOLAND', 'OP_BOOLOR', 'OP_NUMEQUAL', 'OP_NUMEQUALVERIFY', 'OP_NUMNOTEQUAL', 'OP_LESSTHAN', 'OP_GREATERTHAN', 'OP_LESSTHANOREQUAL', 'OP_GREATERTHANOREQUAL', 'OP_MIN', 'OP_MAX', 'OP_WITHIN', 'OP_RIPEMD160', 'OP_SHA1', 'OP_SHA256', 'OP_HASH160', 'OP_HASH256', 'OP_CODESEPARATOR', 'OP_CHECKSIG', 'OP_CHECKSIGVERIFY', 'OP_CHECKMULTISIG', 'OP_CHECKMULTISIGVERIFY', 'OP_NOP1', 'OP_CHECKLOCKTIMEVERIFY', 'OP_CHECKSEQUENCEVERIFY', 'OP_NOP4', 'OP_NOP5', 'OP_NOP6', 'OP_NOP7', 'OP_NOP8', 'OP_NOP9', 'OP_NOP10'];
let parsescript = (s : string) : string => {
  if (!s) throw new Error("empty script");
  let asm : string;
  let op : number; [op,s] = parsefixint(s,1);
       if ( 1 <= op && op <=  75) {      [asm,s] = parsefixlen(s,op); asm = filtersig(asm); }
  else if (79 <= op && op <= 185)                                     asm = opcodes[op - 79];
  else switch (op) {
    case   0:                                                         asm = 'OP_FALSE';                       break;
    case  76: [op,s] = parsefixint(s,1); [asm,s] = parsefixlen(s,op); asm = 'OP_PUSHDATA1(' + op + ')' + asm; break;
    case  77: [op,s] = parsefixint(s,2); [asm,s] = parsefixlen(s,op); asm = 'OP_PUSHDATA2(' + op + ')' + asm; break;
    case  78: [op,s] = parsefixint(s,4); [asm,s] = parsefixlen(s,op); asm = 'OP_PUSHDATA4(' + op + ')' + asm; break;
    default: throw new Error("unknown opcode"); break;
  }
  return s ? asm + ' ' + parsescript(s) : asm;
};
let asmscript = (inputscript : string[]) : string => {
  let raw = '';
  let script = JSON.parse(JSON.stringify(inputscript));
  while (script.length) {
    let op = script.shift();
         if (op.substr(0,2)  !== 'OP')           { op = filtersig(op);  raw +=        fixint(op.length/2,1) + op; }
    else if (op.substr(0,12) === 'OP_PUSHDATA1') { op = script.shift(); raw += '4c' + fixint(op.length/2,1) + op; }
    else if (op.substr(0,12) === 'OP_PUSHDATA2') { op = script.shift(); raw += '4d' + fixint(op.length/2,2) + op; }
    else if (op.substr(0,12) === 'OP_PUSHDATA4') { op = script.shift(); raw += '4e' + fixint(op.length/2,4) + op; }
    else raw += fixint(opcodes.findIndex(element => (element === op)) + 79,1);
  }
  return raw;
};

interface transaction {
  raw      : string;
  txid     : string;
  version  : number;
  flag     : boolean;
  vin      : {
    txid      : string;
    vout      : number;
    scriptSig : { asm : string; hex : string; };
    sequence  : number;
  }[];
  vout     : {
    value        : number;
    scriptPubKey : { asm : string; hex : string; };
  }[];
  locktime : number;
}

let btclient = new bitcoincore({ username: 'chelpis', password: 'chelpis' });
let getrawtx = async (id : string) : Promise<transaction> => btclient.getRawTransaction(id).then(x => {
  let tx : any = { raw: x, txid: revend(sha256(sha256(x))) };
  [tx.version,                   x] = parsefixint(x,4);
  [tx.flag,                      x] = parseflag(x);
  let vincnt : number; [vincnt,  x] = parsevarint(x);
  tx.vin = [];
  for (let i = 0 ; i < vincnt ; i += 1) {
    tx.vin[i] = {}; tx.vin[i].scriptSig = {};
    [tx.vin[i].txid,             x] = parsefixlen(x,32,revend);
    [tx.vin[i].vout,             x] = parsefixint(x,4);
    let len : number; [len,      x] = parsevarint(x);
    [tx.vin[i].scriptSig.hex,    x] = parsefixlen(x,len);
    tx.vin[i].scriptSig.asm         = parsescript(tx.vin[i].scriptSig.hex);
    [tx.vin[i].sequence,         x] = parsefixint(x,4);
  }
  let voutcnt : number; [voutcnt,x] = parsevarint(x);
  tx.vout = [];
  for (let i = 0 ; i < voutcnt ; i += 1) {
    tx.vout[i] = {}; tx.vout[i].scriptPubKey = {};
    [tx.vout[i].value,           x] = parsefixint(x,8); tx.vout[i].value /= 100000000;
    let len : number; [len,      x] = parsevarint(x);
    [tx.vout[i].scriptPubKey.hex,x] = parsefixlen(x,len);
    tx.vout[i].scriptPubKey.asm     = parsescript(tx.vout[i].scriptPubKey.hex);
  }
  if (tx.flag) throw new Error("unsupported flag");
  [tx.locktime,                  x] = parsefixint(x,4);
  return Promise.resolve(tx);
});
let serialize = (tx : transaction, vin : number, script : string) : string => {
  let raw = '';
  raw += fixint(tx.version,4);
  raw += varint(tx.vin.length);
  for (let i = 0 ; i < tx.vin.length ; i += 1) {
    raw += revend(tx.vin[i].txid);
    raw += fixint(tx.vin[i].vout,4);
    raw += (i === vin) ? script : varint(0);
    raw += fixint(tx.vin[i].sequence,4);
  }
  raw += varint(tx.vout.length);
  for (let vout of tx.vout) {
    raw += fixint(vout.value*100000000,8);
    raw += varint(vout.scriptPubKey.hex.length/2);
    raw +=        vout.scriptPubKey.hex;
  }
  raw += fixint(tx.locktime,4);
  return raw;
};

let secp256k1 = new elliptic.ec('secp256k1');
let runscript = (inputscript : any[], filter : (string) => boolean, buildtx : (string) => string, debug = false) : boolean => {
  let flag = true;
  let script = JSON.parse(JSON.stringify(inputscript));
  let subscr = JSON.parse(JSON.stringify(inputscript));
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
      case 'OP_RIPEMD160': stack.push(       ripemd(stack.pop()));  break;
      case 'OP_SHA256':    stack.push(       sha256(stack.pop()));  break;
      case 'OP_HASH160':   stack.push(ripemd(sha256(stack.pop()))); break;
      case 'OP_HASH256':   stack.push(sha256(sha256(stack.pop()))); break;
      case 'OP_CODESEPARATOR': subscr = JSON.parse(JSON.stringify(script)); break;
      case 'OP_CHECKSIG':
        let pk = secp256k1.keyFromPublic(stack.pop(),'hex');
        let sig = stack.pop().replace('[ALL]','');
        let scr = asmscript(subscr.filter(filter));
        if (debug) console.log('OP_CHECKSIG:', parsescript(scr).split(' '));
        stack.push(pk.verify(sha256(sha256(buildtx(varint(scr.length/2) + scr) + '01000000')),sig));
        break;
      case 'OP_CHECKSIGVERIFY': script.unshift('OP_VERIFY'); script.unshift('OP_CHECKSIG'); break;
      default: throw new Error("unsupported opcode"); break;
    }
    if (debug) console.log(flag,script,stack);
  }
  return flag && stack.pop();
};
let verifytx = async (id : string) => {
  let tx = await getrawtx(id);
  for (let i = 0 ; i < tx.vin.length ; i += 1) {
    let from = await getrawtx(tx.vin[i].txid);
    let script = tx.vin[i].scriptSig.asm.split(' ').concat(from.vout[tx.vin[i].vout].scriptPubKey.asm.split(' '));
    if (!runscript(script,op => op !== 'OP_CODESEPARATOR' && op.substr(0,2) !== '30',scr => serialize(tx,i,scr)) && !runscript(script,op => op !== 'OP_CODESEPARATOR' && op.substr(0,2) === 'OP',scr => serialize(tx,i,scr))) {
      console.log(tx,i);
      runscript(script,_ => true,scr => serialize(tx,i,scr),true);
      throw new Error("transaction verification failed");
    }
  }
};

let main = async () => {
  let block = await btclient.getBlock(await btclient.getBlockHash(1));
  for (let i = 1 ; i < 1000 ; i += 1) {
    for (let j = 1 ; j < block.tx.length ; j += 1) await verifytx(block.tx[j]);
    block = await btclient.getBlock(block.nextblockhash);
  }
};

main();

