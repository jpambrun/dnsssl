import dns from "dns2";
import acme from "acme-client";
import { promises as fsp } from "fs";
import fs from "fs";
import crypto from "crypto";
import { publicIpv4 } from "public-ip";
import * as http from "http";
import { Socket } from "net";

if (!process.env["BASE_DOMAIN"]) throw new Error("BASE_DOMAIN env var must be set");
if (!process.env["DNS_EMAIL"]) throw new Error("DNS_EMAIL env var must be set");

const BASE_DOMAIN = process.env["BASE_DOMAIN"];
const EXTERNAL_IP = process.env["EXTERNAL_IP"] || (await publicIpv4());
const DNS_EMAIL = process.env["DNS_EMAIL"];
const PRODUCTION_LE = ["1", "true", "t", "TRUE"].includes(process.env["PRODUCTION_LE"]);
const TOKEN = process.env["TOKEN"] || "secret";

let acme_txt_secret = undefined;

function typeFromId(id) {
  return Object.keys(dns.Packet.TYPE).find((key) => dns.Packet.TYPE[key] === id);
}

function classFromId(id) {
  return Object.keys(dns.Packet.CLASS).find((key) => dns.Packet.CLASS[key] === id);
}

const dnsServer = dns.createServer({
  udp: true,
  tcp: true,
});

dnsServer.on("request", (request, send, rinfo) => {
  const response = dns.Packet.createResponseFromRequest(request);
  for (const question of request.questions) {
    console.log(request.header.id, typeFromId(question?.type), classFromId(question?.class), question?.name);

    switch (question.type) {
      case dns.Packet.TYPE.NS: {
        if (question.name.toLowerCase().includes(BASE_DOMAIN)) {
          response.answers.push({
            name: question.name,
            type: dns.Packet.TYPE.NS,
            class: dns.Packet.CLASS.IN,
            ttl: 300,
            ns: question.name.toLowerCase(),
          });
        }
        break;
      }
      case dns.Packet.TYPE.CAA: {
        response.answers.push({
          name: question.name,
          type: dns.Packet.TYPE.CAA,
          class: dns.Packet.CLASS.IN,
          ttl: 300,
          flag: 0,
          tag: "issuewild",
          value: "letsencrypt.org",
        });
        break;
      }
      case dns.Packet.TYPE.TXT: {
        if (question.name.toLowerCase().includes("_acme-challenge.") && acme_txt_secret) {
          console.log(question.name.toLowerCase(), acme_txt_secret);
          response.answers.push({
            name: question.name,
            type: dns.Packet.TYPE.TXT,
            class: dns.Packet.CLASS.IN,
            ttl: 10,
            data: acme_txt_secret,
          });
        }

        if (question.name.toLowerCase().includes("_secret.")) {
          const subdomain = "";
          const key = fs.readFileSync(`./secret/${(subdomain || "") + BASE_DOMAIN}.key`, { encoding: "utf8" });
          const certs = fs.readFileSync(`./secret/${(subdomain || "") + BASE_DOMAIN}.crt`, { encoding: "utf8" });

          const isTCP = rinfo instanceof Socket;

          let chunks = [];
          if (question.name.toLowerCase().includes("key")) {
            chunks = key.split("\n");
          } else if (question.name.toLowerCase().includes("crt")) {
            chunks = certs.split("\n");
          }

          response.header.tc = isTCP ? 0 : 1;

          response.answers.push({
            name: question.name,
            type: dns.Packet.TYPE.TXT,
            class: dns.Packet.CLASS.IN,
            ttl: 10,
            data: isTCP ? chunks : chunks.slice(0, 2),
          });
        }
        break;
      }
      case dns.Packet.TYPE.A: {
        const ipSubStr = question.name.toLowerCase().match(/(?<b1>\d{1,3})-(?<b2>\d{1,3})-(?<b3>\d{1,3})-(?<b4>\d{1,3})/);
        if (ipSubStr !== null && ipSubStr.groups !== null) {
          const { b1, b2, b3, b4 } = ipSubStr.groups;

          if (parseInt(b1) <= 255 && parseInt(b2) <= 255 && parseInt(b3) <= 255 && parseInt(b4) <= 255) {
            response.answers.push({
              name: question.name,
              type: dns.Packet.TYPE.A,
              class: dns.Packet.CLASS.IN,
              ttl: 300,
              address: `${b1}.${b2}.${b3}.${b4}`,
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
            address: EXTERNAL_IP,
          });
          break;
        }
      }
    }
  }

  send(response);
});

const getAccountKey = () => {
  console.log("Generating account private key");
  return acme.crypto.createPrivateKey();
};

const generateCsr = async (subdomain) => {
  console.log("Generating CSR");
  return acme.crypto.createCsr({
    commonName: "*." + (subdomain ? `${subdomain}.` : "") + BASE_DOMAIN,
  });
};

const areCertsValid = async (subdomain = "") => {
  const key = await fsp.readFile(`./secret/${subdomain + BASE_DOMAIN}.key`, { encoding: "utf8" }).catch(() => undefined);
  const certs = await fsp.readFile(`./secret/${subdomain + BASE_DOMAIN}.crt`, { encoding: "utf8" }).catch(() => undefined);
  if (key === undefined || certs === undefined) return false;

  const parsedCert = new crypto.X509Certificate(certs);
  const validTo = new Date(parsedCert.validTo);
  if (validTo - Date.now() < 30 * 24 * 60 * 60 * 1000) return false;
  return true;
};

const generateCerts = async (subdomain = "") => {
  const [key, csr] = await generateCsr(subdomain);
  console.log(`Reqesting certs for *.${subdomain + BASE_DOMAIN}`);
  const client = new acme.Client({
    directoryUrl: PRODUCTION_LE ? acme.directory.letsencrypt.production : acme.directory.letsencrypt.staging,
    accountKey: await getAccountKey(),
  });
  const certs = await client.auto({
    csr,
    email: DNS_EMAIL,
    termsOfServiceAgreed: true,
    challengePriority: ["dns-01"],
    challengeCreateFn: (authz, challenge, keyAuthorization) => {
      acme_txt_secret = keyAuthorization;
    },
    challengeRemoveFn: (authz, challenge, keyAuthorization) => {
      acme_txt_secret = undefined;
    },
  });
  console.log("Certs renewed");
  await fsp.writeFile(`./secret/${subdomain + BASE_DOMAIN}.key`, key);
  await fsp.writeFile(`./secret/${subdomain + BASE_DOMAIN}.crt`, certs);
  return [key, certs];
};

const validateOrGenerateCerts = async () => {
  await fsp.mkdir("./secret").catch(() => {});
  async function processSubdomain(subdomain) {
    if (!(await areCertsValid(subdomain))) {
      console.log(`Certificates for *.${subdomain} need to be renewed`);
      await generateCerts(subdomain);
    } else {
      console.log(`Certificates for *.${subdomain} are valid`);
    }
  }

  // sequential since the secret var is global..
  for (const subdomain of ["", "127-0-0-1"]) {
    await processSubdomain(subdomain);
  }

  console.log("Certs generated, please will shutdown, please resart the server");
  process.exit(0);


  // await Promise.all([processSubdomain(""), processSubdomain("127-0-0-1")]).catch((err) => {
  //   console.error("Error generating certs", err);
  //   process.exit(1);
  // });
};

dnsServer.on("error", console.error);

validateOrGenerateCerts();
setInterval(validateOrGenerateCerts, 1 * 60 * 60 * 1000);

process.on("SIGINT", () => process.exit());

await dnsServer.listen({
  udp: { port: 53, address: "0.0.0.0" },
  tcp: { port: 53, address: "0.0.0.0" },
});

console.log("DNS Listening.");
console.log(dnsServer.addresses());

const cert = Bun.file("secret/ip.dev.health.crt");
const key = Bun.file("secret/ip.dev.health.key");

if ((await cert.exists()) && (await key.exists())) {
  console.log("Certs exist, starting https server");
  Bun.serve({
    port: 443,
    tls: {
      cert,
      key,
    },
    fetch: (req) => {
      const requestUrl = new URL(req.url);
      if (requestUrl.pathname === "/health") {
        return new Response("ok");
      }

      if (requestUrl.searchParams.get("token") === TOKEN) {
        if (requestUrl.pathname === "/crt") {
          return new Response(cert);
        }
        if (requestUrl.pathname === "/key") {
          return new Response(key);
        }
      } else {
        return new Response("Invalid token", { status: 403 });
      }
      return new Response("Not found", { status: 404 });
    },
  });
}
