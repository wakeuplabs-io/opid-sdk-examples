import {
  buildVerifierId,
  core,
  CredentialStatusType,
  IdentityCreationOptions,
} from "@wakeuplabs/opid-sdk";
import "dotenv/config";

export const OPID_METHOD = "opid";
export const OPID_BLOCKCHAIN = "optimism";
export const OPID_NETWORK_SEPOLIA = "sepolia";
export const OPID_SEPOLIA_CHAIN_ID = 11155420;

export const RPC_URL = process.env.RPC_URL as string;
export const CHAIN_ID = Number(process.env.CHAIN_ID ?? OPID_SEPOLIA_CHAIN_ID);
export const RHS_URL = process.env.RHS_URL as string;
export const RHS_ADDRESS = process.env.RHS_ADDRESS as string;
export const STATE_CONTRACT_ADDRESS = process.env
  .STATE_CONTRACT_ADDRESS as string;
export const WALLET_KEY = process.env.WALLET_KEY as string;
export const THIRD_PARTY_WALLET_KEY = process.env
  .THIRD_PARTY_WALLET_KEY as string;
export const VERIFIER_DID = process.env.VERIFIER_DID as string;

export const TRANSFER_REQUEST_ID_SIG_VALIDATOR = 1;
export const TRANSFER_REQUEST_ID_MTP_VALIDATOR = 2;
export const TRANSFER_REQUEST_ID_V3 = 3;

export enum VerifierType {
  Universal = "UniversalVerifier",
  ERC20 = "ERC20Verifier",
  SelectiveDisclosure = "SelectiveDisclosureVerifier",
}

export const ERC20_VERIFIER: VerifierType = process.env
  .ERC20_VERIFIER as VerifierType;

// opt-sepolia example deployment
export const ERC20_VERIFIER_ADDRESS = process.env
  .ERC20_VERIFIER_ADDRESS as string;
export const ERC20_ZK_AIRDROP_ADDRESS = process.env
  .ERC20_ZK_AIRDROP_ADDRESS as string;

export const ERC20_VERIFIER_ID = buildVerifierId(ERC20_VERIFIER_ADDRESS, {
  blockchain: OPID_BLOCKCHAIN,
  networkId: OPID_NETWORK_SEPOLIA,
  method: OPID_METHOD,
});

export const ERC20_VERIFIER_DID = core.DID.parseFromId(ERC20_VERIFIER_ID);

export const DEFAULT_NETWORK_CONNECTION = {
  rpcUrl: RPC_URL,
  contractAddress: STATE_CONTRACT_ADDRESS,
};

export const DEFAULT_IDENTITY_CREATION_OPTIONS: IdentityCreationOptions = {
  method: OPID_METHOD,
  blockchain: OPID_BLOCKCHAIN,
  networkId: OPID_NETWORK_SEPOLIA,
  revocationOpts: {
    type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    id: RHS_URL,
  },
};

export const CIRCUITS_FOLDER = process.env.CIRCUITS_PATH as string;
export const MONGO_DB_CONNECTION = process.env.MONGO_DB_CONNECTION as string;
export const MONGO_DB_TABLE_NAME = process.env.MONGO_DB_TABLE_NAME as string;

export const ONCHAIN_RHS_CONFIG: {
  credentialType: CredentialStatusType;
  identityCreationOptions: IdentityCreationOptions;
} = {
  credentialType: CredentialStatusType.Iden3OnchainSparseMerkleTreeProof2023,
  identityCreationOptions: {
    method: OPID_METHOD,
    blockchain: OPID_BLOCKCHAIN,
    networkId: OPID_NETWORK_SEPOLIA,
    revocationOpts: {
      type: CredentialStatusType.Iden3OnchainSparseMerkleTreeProof2023,
      id: RHS_ADDRESS,
    },
  },
};

export const OFFCHAIN_RHS_CONFIG: {
  credentialType: CredentialStatusType;
  identityCreationOptions: IdentityCreationOptions;
} = {
  credentialType: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
  identityCreationOptions: {
    method: OPID_METHOD,
    blockchain: OPID_BLOCKCHAIN,
    networkId: OPID_NETWORK_SEPOLIA,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: RHS_URL,
    },
  },
};
