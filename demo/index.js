import { Ecc } from "cybex-ecc";
import {
  TransactionBuilder,
  FetchChain,
  ChainStore,
  ops,
  Signature,
  PrivateKey,
  Aes,
  PublicKey
} from "cybexjs";
import { Apis } from "cybexjs-ws";

const connectNode = async (nodeAddress = "wss://hangzhou.51nebula.com") => {
  let instanceRes = await Apis.instance(nodeAddress, true).init_promise;
  console.log("Connected to:", nodeAddress);
  await ChainStore.init();
  return Apis;
};

const showResult = (...args) => {
  args.forEach(str => {
    document.getElementById("result").prepend(
      (function() {
        let p = document.createElement("p");
        p.textContent = str;
        return p;
      })()
    );
  });
};

document.getElementById("connect").addEventListener("click", async e => {
  let connection = await connectNode();
  showResult("Connect Done");
});

const broadcast = tr => {
  return new Promise((resolve, reject) => {
    var tr_object = ops.signed_transaction.toObject(tr);
    Apis.instance()
      .network_api()
      .exec("broadcast_transaction_with_callback", [
        function(res) {
          return resolve(res);
        },
        tr_object
      ])
      .then(function() {
        //console.log('... broadcast success, waiting for callback')
        if (was_broadcast_callback) was_broadcast_callback();
        return;
      })
      .catch(error => {
        // console.log may be redundant for network errors, other errors could occur
        console.log(error);
        var message = error.message;
        if (!message) {
          message = "";
        }
        reject(
          new Error(message + "Broadcast Error: " + JSON.stringify(tr_object))
        );
        return;
      });
    return;
  });
};

let seed = "ldw-formatactiveqwer1234qwer1234";
// let seed = "create-testactiveqwer1234qwer1234";
let ecc = Ecc.from_seed(seed);
console.debug("ECC: ", ecc);
console.debug("Public: ", ecc.to_public_str());
document.getElementById("transfer").addEventListener("click", async e => {
  let tr = new TransactionBuilder();
  let priv = PrivateKey.fromSeed(seed);
  let value = document.getElementById("amount").value || 1;
  let op = tr.get_type_operation("transfer", {
    fee: { amount: 1000, asset_id: "1.3.0" },
    from: "1.2.139",
    to: "1.2.18",
    amount: { amount: value * 100000, asset_id: "1.3.0" }
  });
  await tr.update_head_block();
  tr.add_operation(op);
  await tr.set_required_fees();
  await tr.update_head_block();
  let chain_id = Apis.instance().chain_id;
  await tr.finalize();
  showResult("TR Buffer", tr.tr_buffer);
  let buf = Buffer.concat([new Buffer(chain_id, "hex"), tr.tr_buffer]);
  showResult("Buffer", buf);
  let startD = new Date();
  console.debug("Start: ", startD);
  for (let i = 0; i < 5000; i++) {
    ecc.sign_buffer(buf);
  }
  let perTimeOfRs = (new Date() - startD) / 5000;
  console.debug("Rust End x5000", (new Date() - startD) / 1000);
  // startD = new Date();
  // for (let i = 0; i < 50; i++) {
    // let signer = Signature.signBuffer(buf, priv);
  // }
  // let perTimeOfJs = (new Date() - startD) / 50;
  // console.debug("JS End x50", (new Date() - startD) / 1000);
  // console.debug(
  //   `RS: ${perTimeOfRs}, JS: ${perTimeOfJs}, Times: ${perTimeOfJs /
  //     perTimeOfRs}`
  // );
  tr.signatures.push(ecc.sign_buffer_to_hex(buf));
  // tr.signatures.push(ecc.sign_hex(buf.toString("hex")));
  // tr.signatures.push(signer.toHex());
  let toBroadcase = ops.signed_transaction.toObject(tr);
  tr.signer_private_keys.push("");
  tr.signed = true;
  showResult("TR: ", JSON.stringify(toBroadcase));
  let res = await tr.broadcast();
  showResult("TR Result: ", JSON.stringify(res));
});
document.getElementById("testmemo").addEventListener("click", async e => {
  let tr = new TransactionBuilder();
  let priv = PrivateKey.fromSeed(seed);
  let startD = new Date();
  console.debug("Start: ", startD);
  for (let i = 0; i < 500; i++) {
    let memo = ecc.decode_memo(
      "7bAJvGEX9xbEEuE4ho8zaac1vppbGYVxhaP4Lebu3DKuo2FTmb",
      "395460150602219",
      "dbc904d761774ffe3d5acaed8a50a3fa4cc82a29f5330a02e75e2b71a284a275939d3eea4de1a5adb03041af026e1848db85e663b495a74814b55053baf0d1ed"
    );
    // console.log("MEMO: ", memo);
  }
  let perTimeOfRs = (new Date() - startD) / 5000;
  console.debug("Rust End x5000: ", perTimeOfRs, (new Date() - startD) / 1000);
  startD = new Date();
  for (let i = 0; i < 50; i++) {
    let memo = Aes.decrypt_with_checksum(
      priv,
      PublicKey.fromPublicKeyString(
        "CYB7bAJvGEX9xbEEuE4ho8zaac1vppbGYVxhaP4Lebu3DKuo2FTmb"
      ),
      "395460150602219",
      "dbc904d761774ffe3d5acaed8a50a3fa4cc82a29f5330a02e75e2b71a284a275939d3eea4de1a5adb03041af026e1848db85e663b495a74814b55053baf0d1ed"
    );
  }
  let perTimeOfJs = (new Date() - startD) / 50;
  console.debug("JS End x50", (new Date() - startD) / 1000);
  console.debug(
    `RS: ${perTimeOfRs}, JS: ${perTimeOfJs}, Times: ${perTimeOfJs /
      perTimeOfRs}`
  );
});

document.getElementById("verify").addEventListener("click", async e => {
  function getRandomStr() {
    let len = 12 + Math.floor(Math.random() * 200);
    return new Array(len)
      .fill(1)
      .map(seed => parseInt(seed, 26))
      .join("");
  }
  let buffer = new Buffer("hereisatestbuffer");
  let priv = PrivateKey.fromSeed("create-test20");
  let ec = Ecc.from_seed("create-test20");
  for (let i = 0; i < 5; i++) {
    let buf = Buffer.from(getRandomStr());
    let sign = ec.sign_buffer_to_hex(buf);
    console.log("SignerHex: ", sign);
    let signRaw = Signature.sign(buf, priv);
    console.log("SignerHexRaw: ", signRaw.toHex());
    console.log(Signature.fromHex(sign).verifyBuffer(buf, priv.toPublicKey()));
  }
  console.log("Done");
});
