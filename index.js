const dns = require('dns2');
const acme = require('acme-client');
const memoizeFs = require('memoize-fs')
const https = require('https');
const { networkInterfaces } = require('os')

const memoizer = memoizeFs({ cachePath: './cache' })

if(!process.env['BASE_DOMAIN']) throw new Error('BASE_DOMAIN env var must be set')
if(!process.env['DNS_EMAIL']) throw new Error('DNS_EMAIL env var must be set')

const firstExternalV4Ip = Object.values(networkInterfaces()).flat(2).filter(addr => addr.family === 'IPv4' && !addr.internal)[0].address

const BASE_DOMAIN = process.env['BASE_DOMAIN'];
const EXTERNAL_IP = process.env['EXTERNAL_IP'] || firstExternalV4Ip;
const TOKEN = process.env['TOKEN'] || 'secret';
const DNS_EMAIL = process.env['DNS_EMAIL'];
const PRODUCTION_LE = ['1', 'true', 't', 'TRUE'].includes(process.env['PRODUCTION_LE'])

const dnsServer = dns.createUDPServer((request, send, rinfo) => {
  const response = dns.Packet.createResponseFromRequest(request);
  request.questions.forEach(question => {
    switch (question.type) {
      case dns.Packet.TYPE.NS: {
        if (question.name.toLowerCase() === BASE_DOMAIN) {
          response.answers.push({
            name: question.name,
            type: dns.Packet.TYPE.NS,
            class: dns.Packet.CLASS.IN,
            ttl: 300,
            ns: BASE_DOMAIN
          });

        }
        break;
      }
      case dns.Packet.TYPE.TXT: {
        console.log(question.name.toLowerCase(), acme_txt_secret)
        if (question.name.toLowerCase().includes('_acme-challenge.') && acme_txt_secret) {
          response.answers.push({
            name: question.name,
            type: dns.Packet.TYPE.TXT,
            class: dns.Packet.CLASS.IN,
            ttl: 1,
            data: acme_txt_secret
          });
        }
        break;
      }
      case dns.Packet.TYPE.A: {
        if (question.name.toLowerCase() === BASE_DOMAIN || question.name.toLowerCase() === 'key.' + BASE_DOMAIN) {
          response.answers.push({
            name: question.name,
            type: dns.Packet.TYPE.A,
            class: dns.Packet.CLASS.IN,
            ttl: 300,
            address: EXTERNAL_IP
          });
          break;
        }

        const ipSubStr = question.name.toLowerCase().match(/(?<b1>\d{1,3})-(?<b2>\d{1,3})-(?<b3>\d{1,3})-(?<b4>\d{1,3})/);
        if (ipSubStr !== null && ipSubStr.groups !== null) {
          const { b1, b2, b3, b4 } = ipSubStr.groups;

          if (parseInt(b1) > 255 || parseInt(b2) > 255 || parseInt(b3) > 255 || parseInt(b4) > 255) {
            break;
          }
          response.answers.push({
            name: question.name,
            type: dns.Packet.TYPE.A,
            class: dns.Packet.CLASS.IN,
            ttl: 300,
            address: `${b1}.${b2}.${b3}.${b4}`
          });
        }
        break;
      }
    }
  });


  send(response);
});

dnsServer.on('request', (request, response, rinfo) => {
  function typeFromId(id) {
    return Object.keys(dns.Packet.TYPE).find(key => dns.Packet.TYPE[key] === id);
  }

  function classFromId(id) {
    return Object.keys(dns.Packet.CLASS).find(key => dns.Packet.CLASS[key] === id);
  }
  const [question] = request.questions;
  console.log(request.header.id, typeFromId(question.type), classFromId(question.class), question.name)
});

dnsServer.listen(53);
dnsServer.on('error', console.error);

let acme_txt_secret = undefined;

(async () => {

  const deserialize = (ser) => {
    const { data } = JSON.parse(ser, (k, v) => {
      if (
        v !== null &&
        typeof v === 'object' &&
        'type' in v &&
        v.type === 'Buffer' &&
        'data' in v &&
        Array.isArray(v.data)) {
        return Buffer.from(v.data);
      }
      return v;
    });
    return data
  }

  const getAccountKey = await memoizer.fn(async () => {
    console.log('Generating account private key')
    return acme.forge.createPrivateKey()
  }, { deserialize });

  const getCsr = await memoizer.fn(async () => {
    console.log('Generating CSR')
    return acme.forge.createCsr({
      commonName: '*.' + BASE_DOMAIN
    });
  }, { maxAge: 1000 * 60 * 60 * 24 * 10, deserialize });


  const getCerts = await memoizer.fn(async () => {
    const [key, csr] = await getCsr();
    console.log('Reqesting certs')
    const client = new acme.Client({
      directoryUrl: PRODUCTION_LE ? acme.directory.letsencrypt.production : acme.directory.letsencrypt.staging,
      accountKey: await getAccountKey(),
    });
    const certs = await client.auto({
      csr,
      email: DNS_EMAIL,
      termsOfServiceAgreed: true,
      challengePriority: ['dns-01'],
      challengeCreateFn: (authz, challenge, keyAuthorization) => { acme_txt_secret = keyAuthorization },
      challengeRemoveFn: (authz, challenge, keyAuthorization) => { acme_txt_secret = undefined }
    });
    console.log('Certs renewed')
    return [key, csr, certs]
  }, { maxAge: 1000 * 60 * 60 * 24 * 10, deserialize });

  const [key, csr, certs] = await getCerts()

  const options = {
    key: `-----BEGIN RSA PRIVATE KEY-----\n${acme.forge.getPemBody(key)}\n-----END RSA PRIVATE KEY-----`,
    cert: certs
  };

  https.createServer(options, function (req, res) {
    const searchParams = new URLSearchParams(req.url.slice(1))
    if (searchParams.get('token') !== TOKEN) {
      res.writeHead(403);
      res.end("Not authorized\n");
      return
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(options));

  }).listen(443);
})();

