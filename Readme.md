# js-sdk-examples

## Setup

1. Download the zk circuits into `./circuits` by running `dl_circuits.sh`. This will download the latest files from `https://opid-circuits.s3.amazonaws.com/latest.zip`

   ```bash
   ./dl_circuits.sh
   ```

2. Copy over the `.env.sample` into `.env`  
   You'll need to fill in `RPC_URL` and `WALLET_KEY` with your own endpoint and key respectively. The default env vars assume you will be using the Optimism sepolia network.

   ```bash
   cp .env.example .env
   ```

   `example.env`

   ```bash
   # rpc url
   RPC_URL="https://sepolia.optimism.io"
   # rhs chain id
   CHAIN_ID="11155420"
   # state v2 contract address in the sepolia network
   CONTRACT_ADDRESS="0x9a1A258702050BcFB938Ad8Ec0996503473216d1"
   # path to the circuits folder
   CIRCUITS_PATH="./circuits"
   # key in hex format with eth balance
   WALLET_KEY=""
   # MongoDB connection string, uses in memory Mongo server if not specified
   MONGO_DB_CONNECTION=""
   # third part yurl to optimism sepolia network rpc node
   THIRD_PARTY_RPC_URL=""
   # third party contract address in the linea test network
   THIRD_PARTY_CONTRACT_ADDRESS=""
   # third party key in hex format with matic balance
   THIRD_PARTY_WALLET_KEY=""
   # reverse hash service url or contract address if onchain rhs
   RHS_URL=""
   # 'ERC20Verifier' or 'SelectiveDisclosureVerifier' or 'UniversalVerifier'
   ERC20_VERIFIER="ERC20Verifier"
   # Universal Verifier (0x102eB31F9f2797e8A84a79c01FFd9aF7D1d9e556) or ERC20 Verifier (0xca6bfa62791d3c7c7ed1a5b320018c1C1dAC89Ee)  or SelectiveDisclosureVerifier (0x9001f41Fbe63fF09635Fe8Dfc532035BA34348B9)
   ERC20_VERIFIER_ADDRESS='0xca6bfa62791d3c7c7ed1a5b320018c1C1dAC89Ee'
   # ERC20 Embedded (0xca6bfa62791d3c7c7ed1a5b320018c1C1dAC89Ee) or ERC20 Universally linked (0x76A9d02221f4142bbb5C07E50643cCbe0Ed6406C) or ERC20 Selective disclosure (0x9001f41Fbe63fF09635Fe8Dfc532035BA34348B9)
   ERC20_ZK_AIRDROP_ADDRESS='0xca6bfa62791d3c7c7ed1a5b320018c1C1dAC89Ee'
   ```

3. Install dependencies

   ```bash
   npm i
   ```

## Run

You can run each example function independently:

```bash
npm run start -- [function]
```

The [function] should be replaced with one of the following options:

- identityCreation
- issueCredential
- transitState
- transitStateThirdPartyDID
- generateProofs
- handleAuthRequest
- handleAuthRequestWithProfiles
- handleAuthRequestNoIssuerStateTransition
- submitSigV2ZkResponse
- submitMtpV2ZkResponse
- submitV3ZkResponse
- submitV3SelectiveDisclosureZkResponse

To run all examples

```bash
npm run start
```

## License

js-sdk-examples is part of the 0xPolygonID project copyright 2024 ZKID Labs AG

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.
