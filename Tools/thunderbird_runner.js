const dns = require("dns");
const exit = require('process').exit;

const thunderbird_dkimverifier_location = "/Users/karl/Documents/GitHub/dkim_verifier/"

async function read(stream) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8');
}

async function main() {
    const { default: Verifier } = await import(thunderbird_dkimverifier_location + '/modules/dkim/verifier.mjs.js');
    const { default: prefs } = await import(thunderbird_dkimverifier_location + "/modules/preferences.mjs.js");
    const { default: MsgParser } = await import(thunderbird_dkimverifier_location + "/modules/msgParser.mjs.js");
    const { default: KeyStore } = await import(thunderbird_dkimverifier_location + '/modules/dkim/keyStore.mjs.js');
    const { default: Logging } = await import(thunderbird_dkimverifier_location + "/modules/logging.mjs.js");

    Logging.setLogLevel(Logging.Level.Error);

    prefs._valueGetter = (name) => { return prefs._prefs[name]; };
    prefs._valueSetter = (name, value) => { prefs._prefs[name] = value; return Promise.resolve(); };
    prefs.init = () => { return Promise.resolve(); };
    prefs.clear = () => { prefs._prefs = {}; return Promise.resolve(); };

    globalThis.browser = {
        runtime: {},
    };

    const rawMessage = await read(process.stdin);

    const msgParsed = MsgParser.parseMsg(rawMessage);
    const fromHeader = msgParsed.headers.get("from");

    if (!fromHeader) {
        throw new Error("message does not contain a from header");
    }
    let from;
    try {
        from = MsgParser.parseFromHeader(fromHeader[0]);
    } catch (error) {
        log.error("Parsing of from header failed", error);
        exit()
    }

    const msg = {
        headerFields: msgParsed.headers,
        bodyPlain: msgParsed.body,
        from: from,
    };

    function queryDnsTxt(name) {
        return dns.promises.resolveTxt(name).then((res) => {
            return {
                data: [res[0].join("")],
                rcode: 0,
                secure: false,
                bogus: false,
            }
        }).catch((res) => {
            return {
                data: undefined,
                rcode: 2,
                secure: false,
                bogus: false,
            }
        });
    }


    const result = await new Verifier(new KeyStore(queryDnsTxt)).verify(msg);
    for (const signature of result.signatures) {
        if (signature.result == "SUCCESS") {
            console.log("SUCCESS", signature.warnings)
            exit();
        }
    }

    if (result.signatures[0]) {
        console.log("FAIL", result.signatures[0].result + " " + result.signatures[0].errorType)
        exit();
    }

    console.log("FAIL")
}

main()