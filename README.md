# Tiny dynamic DNS server with let's encrypt wildcard cert

This is a little DNS server inspired by nip.io and sslip.io that resolves any `prefix-ww.xx.yy.zz-suffix.dns.example.com`
to the ww.xx.yy.zz ipv4 address. In addition, it requests a `*.dns.example.com` wildcard certificate and
makes it available from `https://key.example.com/?token=secret`.

The only requirement is to create a DNS A record for `dns` pointing to this server along with a NS record `DNS` pointing to `dns.example.com`.

It caches certs, accounts and keys under `./cache`.

## installation & configuration


``` bash
npm install
sudo setcap 'cap_net_bind_service=+ep' `which node`
DNS_EMAIL=your.email@example.com BASE_DOMAIN=dns.example.com npm start
PRODUCTION_LE=true DNS_EMAIL=your.email@example.com BASE_DOMAIN=dns.example.com npm start
```

The following environnement variable  are available 

```
BASE_DOMAIN   : (required) Your domain with associated A and NS records.
DNS_EMAIL     : (required) Your email for Let's Encrypt cert requests.
EXTERNAL_IP   : (optional) External IP, the one associated with the A record. Will pick the first external IPv4 is omitted.
TOKEN         : (optional) Secret to "protect" the key, defaults to "secret".
PRODUCTION_LE : (optional) Wether to use staging or production LE endpoints, defaults to staging.
```


