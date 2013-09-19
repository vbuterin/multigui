// BitcoinJS lacks a deserialize, and its numToVarInt is somehow broken

var numToBytes = function(num,bytes) {
    if (bytes == 0) return [];
    else return [num % 256].concat(numToBytes(Math.floor(num / 256),bytes-1));
}
Bitcoin.Util.numToVarInt = function(num) {
    if (num < 253) return [num];
    else if (num < 65536) return [253].concat(numToBytes(num,2));
    else if (num < 4294967296) return [254].concat(numToBytes(num,4));
    else return [253].concat(numToBytes(num,8));
}

Bitcoin.Transaction.deserialize = function(buffer) {
    var pos = 0;
    var readAsInt = function(bytes) {
        if (bytes == 0) return 0;
        pos++;
        return buffer[pos-1] + readAsInt(bytes-1) * 256;
    }
    var readVarInt = function() {
        pos++;
        if (buffer[pos-1] < 253) {
            return buffer[pos-1];
        }
        return readAsInt(buffer[pos-1] - 251);
    }
    var readBytes = function(bytes) {
        pos += bytes;
        return buffer.slice(pos - bytes, pos);
    }
    var readVarString = function() {
        var size = readVarInt();
        return readBytes(size);
    }
    var obj = {
        ins: [],
        outs: []
    }
    obj.version = readAsInt(4);
    var ins = readVarInt();
    for (var i = 0; i < ins; i++) {
        obj.ins.push({
            outpoint: {
                hash: Bitcoin.Util.bytesToBase64(readBytes(32)),
                index: readAsInt(4)
            },
            script: new Bitcoin.Script(readVarString()),
            sequence: readAsInt(4)
        });
    }
    var outs = readVarInt();
    for (var i = 0; i < outs; i++) {
        obj.outs.push({
            value: readBytes(8),
            script: new Bitcoin.Script(readVarString())
        });
    }
    obj.locktime = readAsInt(4);
    return new Bitcoin.Transaction(obj);
}

var sha256 = Crypto.SHA256;

var slowsha = function(x) {
    var old_pass = x, new_pass;
    for (var i = 0; i < 1000; i++) {
        new_pass = Crypto.util.hexToBytes(sha256(old_pass));
        old_pass = new_pass + x;
    }
    return Crypto.util.bytesToHex(new_pass);
}

var base58checkEncode = function(x,vbyte) {
    vbyte = vbyte || 0;
    var front = [vbyte].concat(Crypto.util.hexToBytes(x));
    var checksum = Crypto.SHA256(Crypto.SHA256(front, {asBytes: true}), {asBytes: true})
                        .slice(0,4);
    return Bitcoin.Base58.encode(front.concat(checksum));
}

var base58checkDecode = function(x) {
    var bytes = Bitcoin.Base58.decode(x),
        front = bytes.slice(0,bytes.length-4),
        back = bytes.slice(bytes.length-4);
    var checksum = Crypto.SHA256(Crypto.SHA256(front,{asBytes: true}), {asBytes: true})
                        .slice(0,4);
    if (""+checksum != ""+back) {
        throw "Checksum failed";
    }
    return Crypto.util.bytesToHex(front.slice(1));
}

var importpk = function(x) {
    if (x.length == 64) x = base58checkEncode(x);
    return new Bitcoin.ECKey(x);
}

var privtopub = function(x) {
    if (x.length == 64) x = base58checkEncode(x,128);
    return Crypto.util.bytesToHex(importpk(x).getPub());
}

var pubkey_to_address = function(x,v) {
    var hash160 = Bitcoin.Util.sha256ripe160(Crypto.util.hexToBytes(x))
    return base58checkEncode(Crypto.util.bytesToHex(hash160),v);
}
var script_to_address = function(x) { return pubkey_to_address(x,5) };

// Signs a standard input

var sign = function(tx,i,pk) {
    console.log('signing',tx,i,pk);
    var btx = Bitcoin.Transaction.deserialize(Crypto.util.hexToBytes(tx)),
        ipk = importpk(pk),
        ipub = ipk.getPub(),
        hash160 = Bitcoin.Util.sha256ripe160(ipub),
        script = Bitcoin.Script.createOutputScript(new Bitcoin.Address(hash160)),
        hash = btx.hashTransactionForSignature( script, i, 1),
        sig = ipk.sign(hash).concat([1]);
    btx.ins[i].script = Bitcoin.Script.createInputScript(sig,ipub);
    return Crypto.util.bytesToHex(btx.serialize());
}

// Signs a multisig input

var multisign = function(tx,i,script,pk) {
    console.log('signing',tx,i,script,pk);
    var scriptBytes = Crypto.util.hexToBytes(script),
        scriptObj = new Bitcoin.Script(scriptBytes),
        txObj = Bitcoin.Transaction.deserialize(Crypto.util.hexToBytes(tx)),
        hash = txObj.hashTransactionForSignature(scriptObj, i, 1),
        pkObj = importpk(pk),
        sig = Crypto.util.bytesToHex(pkObj.sign(hash)) + '01';
    return sig;
}

// Validates a signature for a transaction input

var validate_input = function(tx,i,script,sig,pub) {
    var txObj = Bitcoin.Transaction.deserialize(Crypto.util.hexToBytes(tx)),
        scriptBytes = Crypto.util.hexToBytes(script),
        scriptObj = new Bitcoin.Script(scriptBytes),
        hash = txObj.hashTransactionForSignature(scriptObj,i,1);
    return Bitcoin.ECDSA.verify(hash, Crypto.util.hexToBytes(sig),
                                      Crypto.util.hexToBytes(pub));
}

// Makes a transaction given inputs as
// ["319ba90f1645eed46a8fd48e9754ca979c3371f59099d32634a8b56549ce02aa:0", ...]
// and outputs as
// ["13BekWh2nU1s25PdJdw6aXCWrMXBCVKFnz:50000", ...]

var mktx = function(inputs,outputs,cb) {
    var tx = new Bitcoin.Transaction();
    inputs.map(function(i) {
        tx.addInput(i.substring(0,64),parseInt(i.substring(65)));
    });
    outputs.map(function(o) {
        var pos = o.indexOf(':');
        tx.addOutput(o.substring(0,pos),parseInt(o.substring(pos+1)));
    });
    return cb ? cb(tx) : tx;
}

// Given a UTXO set as inputs, create a transaction sending the money to a 
// given destination address. Includes a change address parameter

var make_sending_transaction = function(utxo,to,value,change,cb) {
    var sum = utxo.map(function(x) { return x.value; })
        .reduce(function(a,b) { return a+b; },0);
    var outputs = [{
        address: to,   
        value: value
    }]
    if (value < 5430) { return cb("Amount below dust threshold!"); }
    if (sum < value) { return cb("Not enough money!"); }
    if (sum-value < 10000) { return cb("Not enough to pay 0.0001 BTC fee!"); }

    // Split change in half by default so that the wallet has multiple UTXO at all times
    if (typeof change == "string") change = [change, change];

    var changelen = Math.min(change.length,Math.floor((sum-value-10000) / 5430));

    for (var i = 0; i < changelen; i++) {
        outputs.push({ 
            address: change[i],
            value: Math.floor((sum-value-10000)/changelen) 
        });
    }
    m.mktx(utxo,outputs,cb);
}

// Get sufficient unspent transaction outputs from a history set to
// spend a given amount of money

var get_enough_utxo_from_history = function(h,amount,cb) {
    var utxo = h.filter(function(x) { return !x.spend });
    var valuecompare = function(a,b) { return a.value > b.value; }
    var high = utxo.filter(function(o) { return o.value >= amount; }).sort(valuecompare);
    if (high.length > 0) return [high[0]];
    utxo.sort(valuecompare);
    var totalval = 0;
    for (var i = 0; i < utxo.length; i++) {
        totalval += utxo[i].value;
        if (totalval >= amount) return utxo.slice(0,i+1);
    }
    throw ("Not enough money. Have: "+totalval+", needed: "+amount);
}

// Converts a hex script into a specialized form that can be used for
// searching for pubkeys, grabbing k and n values, etc

var opcodes = _.invert(Bitcoin.Opcode.map)

var showscript = function(scr) {
    var chunks = new Bitcoin.Script(Crypto.util.hexToBytes(scr)).chunks;
    return chunks.map(function(x) {
        if (typeof x == "number") return opcodes[x] ? opcodes[x].substring(3) : x;
        return Crypto.util.bytesToHex(x);
    });
}

// Gets all pubkeys used in a multisig script

var pubkeys_from_script = function(scr) {
    if (scr.length == 66 || scr.length == 130) return scr;
    return showscript(scr).filter(function(x) {
        return typeof x == "string" && (x.length == 66 || x.length == 130)
    });
}

// Converts internal script array representation into hex script

var rawscript = function(scr) {
    var chunks = scr.map(function(x) {
        if (Bitcoin.Opcode.map['OP_'+x]) return Bitcoin.Opcode.map['OP_'+x];
        return Crypto.util.hexToBytes(x);
    });
    return Crypto.util.bytesToHex(
        chunks.reduce(function(script,x) {
            if (typeof x == "number") script.writeOp(x);
            else if (typeof x == "object") script.writeBytes(x);
            return script;
        },new Bitcoin.Script()).buffer
    );
}

// Checks the transaction for multisig inputs with sufficient signatures
// and applies them

var apply_multisignatures = function(tx,i,script,sigs) {
    var shown = showscript(script),
        k = shown[0],
        n = shown[shown.length-2];
    if (sigs.length < k) {
        throw "Not enough signatures"   
    }
    var script = new Bitcoin.Script();
    _.range(sigs.length,k).map(function() { script.writeOp(0); });
    sigs.map(function(sig) { script.writeBytes(Crypto.util.hexToBytes(sig)); });
    script.writeBytes(Crypto.util.hexToBytes(script));
    var txObj = Bitcoin.Transaction.deserialize(tx);
    txObj.ins[i].script = script;
    return txObj.serialize();
}

var process_multisignatures = function(eto) {
    var eto = _.clone(eto);
    for (var i = 0; i < eto.inputscripts.length; i++) {
        var script = eto.inputscripts[i];
        if (script.length == 66 || script.length == 130) {
            continue;
        }
        if (eto.sigs[i] === true) {
            continue;
        }
        var shown = showscript(script),
            k = shown[0],
            n = shown[shown.length-2],
            pubs = shown.filter(function(x) {
                return (""+x).length == 66 || (""+x).length == 130
            }),
            sigs = eto.sigs[i].filter(function(x) { return x; });
        if (sigs.length < k) {
            continue;
        }
        var zeroes = [].concat(_.range(sigs.length,n).map(function() { return 0 })),
            script2 = [].concat.apply(zeroes,sigs.map(function(sig) { return [sig] }))
                .concat([script]),
            raw = rawscript(script2),
            txObj = Bitcoin.Transaction.deserialize(Crypto.util.hexToBytes(eto.tx));
        txObj.ins[i].script = new Bitcoin.Script(Crypto.util.hexToBytes(raw));
        eto.tx = Crypto.util.bytesToHex(txObj.serialize());
        eto.sigs[i] = true;
    }
    return eto;
}

var sign_eto = function(eto,pk) {
    var eto = _.clone(eto);
    for (var i = 0; i < eto.inputscripts.length; i++) {
        var script = eto.inputscripts[i];
        if (script.length == 66 || script.length == 130) {
            eto.tx = sign(eto.tx,i,pk);
            eto.sigs[i] = true;
        }
        else {
            var pubs = pubkeys_from_script(script),
                pub = privtopub(pk),
                j = pubs.indexOf(pub);
            if (j == -1) continue;
            eto.sigs[i] = eto.sigs[i] || [];
            if (eto.sigs[i] === true) { continue; }
            eto.sigs[i][j] = multisign(eto.tx,i,eto.inputscripts[i],pk);
        }
    }
    return process_multisignatures(eto);
}

//Given an ETO, get all signatures, including partial signatures and
//full signatures extracted from the transaction itself

var get_sigs = function(eto) {
    var sigs = [],
        txobj = Bitcoin.Transaction.deserialize(Crypto.util.hexToBytes(eto.tx));
    for (var i = 0; i < eto.inputscripts.length; i++) {
        if (eto.sigs[i] && eto.sigs[i] !== true) {
            sigs = sigs.concat(eto.sigs[i].filter(function(x) { return x }));
        }
        else {
            if (!txobj.ins[i].script) continue;
            var script = showscript(Crypto.util.bytesToHex(txobj.ins[i].script.buffer));
            sigs = sigs.concat(script.filter(function(x) {
                return (""+x).substring(0,3) == "304" && (""+x).length > 130;
            }));
        }
    }
    return sigs;
}

//Apply a singature to an extended transaction object. Works by attempting
//to validate the transaction against every possible index/pubkey pair, and
//substituting it in where it works. Offers synchronous and asynchronous
//functionality

var apply_sig_to_eto = function(eto,sig,cb,err) {
    var eto = _.clone(eto);
    var state = "NOSIG",
        txObj = eto.tx;

    var process_input = function(i) {
        if (i >= eto.inputscripts.length) {
            return end();
        }
        var script = eto.inputscripts[i];
        if (script.length == 66 || script.length == 130) {
            var v = validate_input(eto.tx,i,script,sig)
            if (v) {
                if (eto.sigs[i] === true) { 
                    if (state == "NOSIG") state = "EXISTSIG";
                }
                else {
                    state = "SUCCESS";
                    eto.sigs[i] = true;
                }
                var ipub = Crypto.util.hexToBytes(eto.inputscripts[i]);
                txObj.ins[i].script = Bitcoin.Script.createInputScript(sig,ipub);
            }
        }
        else {
            var pubs = pubkeys_from_script(script);
            for (var j = 0; j < pubs.length; j++) {
                eto.sigs[i] = eto.sigs[i] || [];
                var v = validate_input(eto.tx,i,script,sig,pubs[j]);
                if (v) {
                    if (eto.sigs[i] === true || eto.sigs[i] && eto.sigs[i][j]) {
                        if (state == "NOSIG") state = "EXISTSIG";
                    }
                    else state = "SUCCESS";
                    eto.sigs[i][j] = sig;
                }
            }
        }
        if (cb) setTimeout(_.partial(process_input,i+1),25);
        else process_input(i+1);
    }

    process_input(0);

    var end = function() {
        if (state == "NOSIG") {
            if (cb && err) return err("Signature invalid");
            else throw "Signature invalid" 
        }
        else if (state == "EXISTSIG") {
            if (cb && err) return err("Signature already applied");
            else throw "Signature already applied" 
        }
        if (cb) cb(process_multisignatures(eto));
        else return process_multisignatures(eto);
    }
}
