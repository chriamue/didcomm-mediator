# didcomm-mediator
DIDComm v2 Mediator

## Spec

[DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/#roles)

## Resolver

Supported did methods:

* did:key
* did:iota

## quickstart

```sh
cargo build
cargo run
```

## Protocols

| Protocol                   | Not started | In Development | In Review | Done | Notes                                                                |
| :------------------------- | :---------: | :------: | :---------------: | :-:  | :-------------------------------------------------------------------- |
| [basic message](https://didcomm.org/basicmessage/2.0/) | :large_orange_diamond: | | | | |
| [did exchange](https://github.com/hyperledger/aries-rfcs/blob/main/features/0023-did-exchange/README.md) | | :large_orange_diamond: | | | |
| [discover features](https://identity.foundation/didcomm-messaging/spec/#discover-features-protocol-20) | |  :large_orange_diamond: | | | |
| [forward](https://identity.foundation/didcomm-messaging/spec/#messages) | |  :large_orange_diamond: | | | |
| [message pickup](https://github.com/hyperledger/aries-rfcs/tree/main/features/0212-pickup) | |  :large_orange_diamond: | | | |
| [trust ping](https://identity.foundation/didcomm-messaging/spec/#trust-ping-protocol-20) | | | | :heavy_check_mark: | Finished implementation. |
