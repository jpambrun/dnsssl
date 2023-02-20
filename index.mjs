import dns from 'dns2'
import acme from 'acme-client';
import { promises as fsp } from 'fs';
import crypto from "crypto"
import { publicIpv4 } from 'public-ip';
import * as http from 'http'

if (!process.env['BASE_DOMAIN']) throw new Error('BASE_DOMAIN env var must be set')
if (!process.env['DNS_EMAIL']) throw new Error('DNS_EMAIL env var must be set')


const BASE_DOMAIN = process.env['BASE_DOMAIN'];
const EXTERNAL_IP = process.env['EXTERNAL_IP'] || await publicIpv4();
const DNS_EMAIL = process.env['DNS_EMAIL'];
const PRODUCTION_LE = ['1', 'true', 't', 'TRUE'].includes(process.env['PRODUCTION_LE'])
const TOKEN = process.env['TOKEN'] || 'secret';

let acme_txt_secret = undefined;

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
        const ipSubStr = question.name.toLowerCase().match(/(?<b1>\d{1,3})-(?<b2>\d{1,3})-(?<b3>\d{1,3})-(?<b4>\d{1,3})/);
        if (ipSubStr !== null && ipSubStr.groups !== null) {
          const { b1, b2, b3, b4 } = ipSubStr.groups;

          if (parseInt(b1) >= 255 && parseInt(b2) >= 255 && parseInt(b3) >= 255 && parseInt(b4) >= 255) {
            response.answers.push({
              name: question.name,
              type: dns.Packet.TYPE.A,
              class: dns.Packet.CLASS.IN,
              ttl: 300,
              address: `${b1}.${b2}.${b3}.${b4}`
            });
            break;
          }
        }

        {
          response.answers.push({
            name: question.name,
            type: dns.Packet.TYPE.A,
            class: dns.Packet.CLASS.IN,
            ttl: 300,
            address: EXTERNAL_IP
          });
          break;
        }

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
  console.log(request.header.id, typeFromId(question?.type), classFromId(question?.class), question?.name)
});

const getAccountKey = () => {
  console.log('Generating account private key')
  return acme.crypto.createPrivateKey()
};

const generateCsr = async () => {
  console.log('Generating CSR')
  return acme.crypto.createCsr({
    commonName: '*.' + BASE_DOMAIN
  });
};

const areCertsValid = async () => {
  const key = await fsp.readFile(`./secret/${BASE_DOMAIN}.key`).catch(() => undefined)
  const certs = await fsp.readFile(`./secret/${BASE_DOMAIN}.crt`).catch(() => undefined)
  if (key === undefined || certs === undefined) return false;

  const parsedCert = new crypto.X509Certificate(certs);
  const validTo = new Date(parsedCert.validTo);
  if (validTo - Date.now() < 30 * 24 * 60 * 60 * 1000) return false;
  return true
}


const generateCerts = async () => {
  const [key, csr] = await generateCsr();
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
  await fsp.writeFile(`./secret/${BASE_DOMAIN}.key`, key)
  await fsp.writeFile(`./secret/${BASE_DOMAIN}.crt`, certs)
  return [key, certs]
};

const validateOrGenerateCerts = async () => {
  if (await areCertsValid()) {
    console.log('certs are still valid')
  } else {
    console.log('certs are need to be renewed')
    generateCerts()

  }
}

http.createServer( async function (req, res) {
  const searchParams = new URLSearchParams(req.url.slice(1))
  if (searchParams.get('token') !== TOKEN) {
    res.writeHead(403);
    res.end("Not authorized\n");
    return
  }
  const key = await fsp.readFile(`./secret/${BASE_DOMAIN}.key`).catch(() => undefined)
  const certs = await fsp.readFile(`./secret/${BASE_DOMAIN}.crt`).catch(() => undefined)
  const options = {
    key: `-----BEGIN RSA PRIVATE KEY-----\n${acme.forge.getPemBody(key)}\n-----END RSA PRIVATE KEY-----`,
    cert: certs
  };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(options));

}).listen(8080);


dnsServer.listen(53);
dnsServer.on('error', console.error);


validateOrGenerateCerts()
setInterval(validateOrGenerateCerts, 12 * 60 * 60 * 1000)
