/*
 * Bitcoin transaction verification
 */

import {createHash} from 'crypto';
import {ec}         from 'elliptic';
import fetch        from 'node-fetch';
import {sprintf}    from 'sprintf-js';

let revend = (s : string) : string => {
  let r = '';
  for (let i = 0 ; i < s.length ; i += 2) {
    r = s.substr(i,2) + r;
  }
  return r;
};
let fixint = (x : number, n : number) : string => revend(sprintf(sprintf('%%0%dx',2*n),x));
let varint = (x : number) : string => (x < 253) ? fixint(x,1) : (x < 65535) ? 'fd' + fixint(x,2) : (x < 4294967295) ? 'fe' + fixint(x,4) : 'ff' + fixint(x,8);

interface transaction {
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
    scriptPubKey : { hex : string; };
  }[];
  locktime : number;
  raw      : string;
  sig      : string;
  pk       : string;
}

let fetchtx = async (id : string) : Promise<transaction> => fetch('https://blockexplorer.com/api/tx/' + id).then(x => x.text()).then(JSON.parse);

let serialize = (tx : transaction, from? : transaction) : transaction => {
  tx.raw = '';
  tx.raw += fixint(tx.version,4);
  tx.raw += varint(tx.vin.length);
  for (let vin of tx.vin) {
    tx.raw += revend(vin.txid);
    tx.raw += fixint(vin.vout,4);
    if (from && from.txid === vin.txid) {
      let asm = vin.scriptSig.asm.split(' ');
      tx.sig = asm[0].replace('[ALL]','');
      tx.pk  = asm[1];
      let scr = from.vout[vin.vout].scriptPubKey.hex;
      tx.raw += varint(scr.length/2);
      tx.raw += scr;
    }
    else if (from) {
      tx.raw += varint(0);
    }
    else {
      tx.raw += varint(vin.scriptSig.hex.length/2);
      tx.raw +=        vin.scriptSig.hex;
    }
    tx.raw += fixint(vin.sequence,4);
  }
  tx.raw += varint(tx.vout.length);
  for (let vout of tx.vout) {
    tx.raw += fixint(vout.value*100000000,8);
    tx.raw += varint(vout.scriptPubKey.hex.length/2);
    tx.raw +=        vout.scriptPubKey.hex;
  }
  tx.raw += fixint(tx.locktime,4);
  return tx;
};

let secp256k1 = new ec('secp256k1');
let H = (msg : string, enc? : string) : string => {
  let sha256 = createHash('sha256');
  sha256.update(Buffer.from(msg,enc));
  return sha256.digest('hex');
};

let main = async () => {
  let x = await fetchtx('7cf527db3771159589ecbcd16e8ec4ab13cbc97fb6db1b288496328a553c4cbb');
  let y = await fetchtx(x.vin[0].txid);
  let z = serialize(x,y);
  let pk = secp256k1.keyFromPublic(z.pk,'hex');
  console.log(x,y,pk.verify(H(H(z.raw + '01000000','hex'),'hex'),z.sig));
};

main();

