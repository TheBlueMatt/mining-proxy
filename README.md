Mining Server Proxy
=====================================
A simple proxy which supports serving work via the Stratum and the [BetterHash](https://github.com/TheBlueMatt/bips/blob/master/bip-XXXX.mediawiki) mining protocols.

Work is obtained using the BetterHash work protocol via a request to bitcoind in conjunction with the [2018-02-miningserver](https://github.com/TheBlueMatt/bitcoin/commits/2018-02-miningserver) patchset. Payout information is obtained using the BetterHash pool protocol via a request to the pool daemon included in this repo.