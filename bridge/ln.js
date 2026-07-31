// Lightning backend for the swap bridge: pay a bolt11 and report the
// preimage. Deliberately tiny — the bridge only ever needs to *send* over
// Lightning (an ark->LN swap), because an ASP's LN *receive* is already free.
//
// Two adapters, both CLN, both using named parameters:
//   'socket' — lightning-rpc unix socket (production: mount the socket)
//   'docker' — `docker exec <container> lightning-cli` (regtest convenience)

import { execFile } from 'node:child_process';
import { createConnection } from 'node:net';

const run = (cmd, args) => new Promise((resolve, reject) => {
  execFile(cmd, args, { maxBuffer: 8 << 20 }, (err, stdout, stderr) => {
    if (err) return reject(new Error((stderr || err.message).trim().slice(0, 400)));
    resolve(stdout);
  });
});

// CLN prints progress lines before the JSON body on some commands.
const parseJson = (s) => {
  const i = s.indexOf('{');
  if (i < 0) throw new Error('no JSON in CLN response: ' + s.slice(0, 200));
  return JSON.parse(s.slice(i));
};

function dockerAdapter({ container, network }) {
  return {
    async call(method, params = {}) {
      const args = ['exec', container, 'lightning-cli', `--${network}`, method,
        ...Object.entries(params).map(([k, v]) => `${k}=${v}`)];
      return parseJson(await run('docker', args));
    },
  };
}

function socketAdapter({ path }) {
  let id = 0;
  return {
    call(method, params = {}) {
      return new Promise((resolve, reject) => {
        const sock = createConnection(path);
        let buf = '';
        sock.on('error', reject);
        sock.on('connect', () => sock.write(JSON.stringify({
          jsonrpc: '2.0', id: ++id, method, params,
        }) + '\n'));
        sock.on('data', (d) => {
          buf += d;
          let nl;
          while ((nl = buf.indexOf('\n')) >= 0) {
            const line = buf.slice(0, nl).trim();
            buf = buf.slice(nl + 1);
            if (!line) continue;
            let msg;
            try { msg = JSON.parse(line); } catch { continue; }
            sock.end();
            if (msg.error) return reject(new Error(JSON.stringify(msg.error).slice(0, 400)));
            return resolve(msg.result);
          }
        });
      });
    },
  };
}

export function lnBackend(cfg) {
  const rpc = cfg.kind === 'docker' ? dockerAdapter(cfg) : socketAdapter(cfg);

  return {
    async info() {
      const r = await rpc.call('getinfo');
      return { id: r.id, alias: r.alias, blockheight: r.blockheight, network: r.network };
    },

    // Spendable outbound capacity, so the bridge can refuse a swap it can't
    // route rather than taking an HTLC it will only have to refund.
    async outboundSat() {
      const r = await rpc.call('listpeerchannels');
      return (r.channels || [])
        .filter((c) => c.state === 'CHANNELD_NORMAL' && c.peer_connected)
        .reduce((n, c) => n + Math.floor((c.spendable_msat ?? 0) / 1000), 0);
    },

    // Pay a bolt11. Resolves { preimage, feeSat }; throws otherwise.
    // maxfee caps routing spend so a swap can't cost more than we charged.
    async pay(bolt11, { maxfeeSat, retryFor = 60 } = {}) {
      const params = { bolt11, retry_for: retryFor };
      if (maxfeeSat != null) params.maxfee = `${Math.max(0, Math.floor(maxfeeSat))}sat`;
      const r = await rpc.call('pay', params);
      if (r.status && r.status !== 'complete') throw new Error(`payment not complete: ${r.status}`);
      if (!r.payment_preimage) throw new Error('payment returned no preimage');
      return {
        preimage: r.payment_preimage,
        feeSat: Math.ceil((((r.amount_sent_msat ?? 0) - (r.amount_msat ?? 0)) || 0) / 1000),
      };
    },

    // Has this payment hash already been paid by us? Checked before paying so
    // a crashed-and-resumed bridge never double-pays.
    async paidPreimage(paymentHash) {
      const r = await rpc.call('listpays', { payment_hash: paymentHash }).catch(() => null);
      const done = (r?.pays || []).find((p) => p.status === 'complete');
      return done?.preimage || null;
    },

    // Is a payment still in flight? A pending pay must not be retried and
    // must not be refunded — its preimage may still arrive.
    async isPending(paymentHash) {
      const r = await rpc.call('listpays', { payment_hash: paymentHash }).catch(() => null);
      return (r?.pays || []).some((p) => p.status === 'pending');
    },
  };
}
