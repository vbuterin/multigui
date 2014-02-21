var sx              = require('node-sx'),
    eto             = sx.eto,
    express         = require('express'),
    crypto          = require('crypto'),
    cp              = require('child_process'),
    async           = require('async'),
    _               = require('underscore'),
    sha256          = function(x) { return crypto.createHash('sha256').update(x).digest('hex') },
    eh              = sx.eh;

var entropy;

crypto.randomBytes(100,function(err,buf) {
    if (err) { throw err; }
    entropy = buf.toString('hex');
});

var pybtctool = function(command, argz) {                                                 
    var cb = arguments[arguments.length - 1]                                              
        args = Array.prototype.slice.call(arguments,1,arguments.length-1)                 
                    .map(function(x) {                                                    
                        return (''+x).replace('\\','\\\\').replace(' ','\\ ')             
                     })                                                                   
    cp.exec('pybtctool '+command+' '+args.join(' '),cb);                                  
}

var random = function(modulus) {
    var alphabet = '0123456789abcdef';
    return sha256(entropy+new Date().getTime()+Math.random()).split('')
           .reduce(function(tot,x) {
                return (tot * 16 + alphabet.indexOf(x)) % modulus;
           },0);
}

var app = express();

app.configure(function(){                                                                 
    app.set('views',__dirname + '/views');                                                  
    app.set('view engine', 'jade'); app.set('view options', { layout: false });             
    app.use(express.bodyParser());                                                          
    app.use(express.methodOverride());                                                      
    app.use(app.router);                                                                    
    app.use(express.static(__dirname + '/public'));                                         
});

var active_wallets = {};

var update_int = setInterval(function() {
    for (var v in active_wallets) {
        var w = active_wallets[v];
        w.update_history(function() {
            //console.log("Saving wallet...");
            Wallet.update({name: w.name},w,function(){});
        });
    }
},10000);

var mkrespcb = function(res,code,success) {
    return eh(function(e) { res.json(e,code); },success);
}

var smartParse = function(x) {
    return (typeof x == "string") ? JSON.parse(x) : x;
}

app.use('/addr',function(req,res) {
    hard_retrieve(req,mkrespcb(res,400,function(w) {
        w.getaddress(mkrespcb(res,400,function(address) {
            return res.json(address);
        }));
    }));
});

var getreqpubs = function(req) {
    var pubs = [];
    req.query = _.extend(req.query,req.body)
    for (var v in req.query) {
        if (v.substring(0,3) == "pub") {
            if (req.query[v].length == 66 || req.query[v].length == 130) {
                pubs.push(req.query[v]); 
            }
            else if (req.query[v]) {
                return { error: "Bad pubkey: "+req.query[v] }
            }
        }
    }
    return pubs;
}

app.use('/msigaddr',function(req,res) {
    req.query = _.extend(req.query,req.body)
    var pubs = getreqpubs(req);
    if (pubs.error) {
        return res.json(pubs.error,400);
    }
    var k = parseInt(req.param("k"));
    if (isNaN(k)) {
        return res.json("Invalid k: "+k,400); 
    }
    console.log("Generating multisig address from "+k+" of: ",pubs)
    sx.gen_multisig_addr_data(pubs,k,mkrespcb(res,400,function(d) {
        res.json(d);
    }));
});

app.use('/showtx',function(req,res) {
    sx.showtx(req.param('tx'),mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/privtopub',function(req,res) {
    sx.pubkey(req.param('pk'),mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/addrtopub',function(req,res) {
    sx.addr_to_pubkey(req.param('address'),mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/sigs',function(req,res) {
    var inp = req.param('tx') ||  smartParse(req.param('eto'));
    eto.extract_signatures(inp,mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/toaddress',function(req,res) {
    var inp = req.param('pub') || req.param('pk') || req.param('script');
    sx.toaddress(inp,mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/mkmultitx',function(req,res) {
    var from   = req.param('from'),
        to     = req.param('to'),
        script = req.param('script'),
        value  = Math.ceil(parseFloat(req.param('value')) * 100000000);
        console.log(1);
    async.waterfall([function(cb2) {
        if (from.length > 34) {
            sx.blke_fetch_transaction(utxoid.substring(0,64),eh(cb2,function(tx) {
                sx.showtx(tx,eh(cb2,function(shown) {
                    console.log(2);
                    return cb2(null,[shown.outputs[parseInt(utxoid.substring(65))]]);
                }));
            }));
        }
        else if (from) {
            console.log(1.5);
            sx.get_utxo(from,value+10000,cb2);
        }
        else { return cb2("Need from or utxo"); }
    }, function(utxo,cb2) {
        console.log("Making transaction sending "+value+" satoshis to "+to);
        console.log("UTXO:",utxo);
        sx.make_sending_transaction(utxo,to,value,utxo[0].address,eh(cb2,function(tx) {
            cb2(null,tx,utxo);
        }));
    }, function(tx,utxo,cb2) {
        var scriptmap = {};
        scriptmap[utxo[0].address] = script;
        eto.mketo(tx,scriptmap,utxo,cb2);
    }],mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/mketo',function(req,res) {
    var tx = req.param('tx'),
        sm = {};
    req.query = _.extend(req.query,req.body)
    for (var p in req.query) {
        if (27 <= p.length && p.length <= 34) { sm[p] = req.query[p]; }
    }
    eto.mketo(tx,sm,null,mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/signeto',function(req,res) {
    try {
        var eto_object = smartParse(req.param('eto')),
            pk = req.param('privkey') || req.param('pk');
    }
    catch(e) { 
        return res.json("Failed to JSON parse: "+req.param("eto"),400); 
    }
    console.log('s1',pk,eto_object);
    eto.signeto(eto_object,pk,mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/applysigtoeto',function(req,res) {
    try {
        var eto_object = smartParse(req.param('eto')),
            sig = req.param('sig'),
            sigs = smartParse(req.param('sigs'));
    }
    catch(e) { 
        return res.json("Failed to JSON parse: "+req.param("eto"),400); 
    }
    if (sig) { 
        eto.apply_sig_to_eto(eto_object,sig,mkrespcb(res,400,_.bind(res.json,res)));
    }
    else if (sigs) {
        sx.foldr(sigs,eto_object,eto.apply_sig_to_eto,mkrespcb(res,400,_.bind(res.json,res)));
    }
    else res.json(eto_object);
});

app.use('/pusheto',function(req,res) {
    try { var eto_object = smartParse(req.param('eto')); }
    catch(e) { return res.json("Failed to JSON parse: "+req.param("eto"),400); }
    eto.publish_eto(eto_object,mkrespcb(res,400,_.bind(res.json,res)));
});

app.use('/eligius_pusheto',function(req,res) {
    try { var eto_object = smartParse(req.param('eto')); }
    catch(e) { return res.json("Failed to JSON parse: "+req.param("eto"),400); }
    pybtctool('eligius_pushtx',eto_object.tx,mkrespcb(res,400,_.bind(res.json,res)))
});

app.use('/history',function(req,res) {
    console.log('grabbing',req.param('address'));
    sx.bci_history(req.param('address'),mkrespcb(res,400,function(h) {
        console.log('grabbed');
        if (req.param('unspent')) {
            h = h.filter(function(x) { return !x.spend });
        }
        if (req.param('confirmations')) {
            h = h.filter(function(x) { return x.confirmations >= parseInt(req.param('confirmations')) });
        }
        return res.json(h);
    }));
});

app.use('/addr_to_pubkey_or_script',function(req,res) {
    sx.addr_to_pubkey(req.param('address'),mkrespcb(res,400,function(result) {
        return res.json(result);
    }));
});

app.use('/',function(req,res) {                                                           
    res.render('multigui.jade',{});                                                           
});

app.listen(80);

return app;

