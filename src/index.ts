import "dotenv/config";
import {
  EthStateStorage,
  CredentialRequest,
  CircuitId,
  ZeroKnowledgeProofRequest,
  AuthorizationRequestMessage,
  PROTOCOL_CONSTANTS,
  AuthHandler,
  core,
  CredentialStatusType,
  ProofType,
  AuthorizationRequestMessageBody,
  byteEncoder,
} from "@wakeuplabs/opid-sdk";
import {
  initInMemoryDataStorageAndWallets,
  initCircuitStorage,
  initProofService,
  initPackageManager,
  initMongoDataStorageAndWallets,
} from "./utils/walletSetup";
import { ethers, Wallet, getBytes, hexlify } from "ethers";
import { generateRequestData } from "./utils/request";
import { Erc20AirdropAbi } from "./abis/airdrop";
import { Erc20VerifierAbi } from './abis/verifier';
import {
  DEFAULT_IDENTITY_CREATION_OPTIONS,
  ERC20_VERIFIER,
  ERC20_VERIFIER_ADDRESS,
  ERC20_ZK_AIRDROP_ADDRESS,
  ERC20_VERIFIER_DID,
  RHS_URL,
  TRANSFER_REQUEST_ID_MTP_VALIDATOR,
  TRANSFER_REQUEST_ID_SIG_VALIDATOR,
  TRANSFER_REQUEST_ID_V3,
  WALLET_KEY,
  VerifierType,
  THIRD_PARTY_WALLET_KEY,
  VERIFIER_DID,
} from "./config";
import { OFFCHAIN_RHS_CONFIG } from "./config";

// change currentConfig to alter every function
// on-chainRhsConfig not working on credentialAtomicMTPV2
const currentConfig = OFFCHAIN_RHS_CONFIG;

function createKYCAgeCredential(did: core.DID) {
  const credentialRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: did.string(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 12345678888,
    revocationOpts: currentConfig.identityCreationOptions.revocationOpts,
  };
  return credentialRequest;
}

function createKYCAgeCredentialRequest(
  circuitId: CircuitId,
  credentialRequest: CredentialRequest
): ZeroKnowledgeProofRequest {
  const proofReqSig: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQuerySigV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        documentType: {
          $eq: 99,
        },
      },
    },
  };

  const proofReqMtp: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQueryMTPV2,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        birthday: {
          $lt: 20020101,
        },
      },
    },
  };

  switch (circuitId) {
    case CircuitId.AtomicQuerySigV2:
      return proofReqSig;
    case CircuitId.AtomicQueryMTPV2:
      return proofReqMtp;
    default:
      return proofReqSig;
  }
}

function prepareProofInputs(json: { proof: any; pub_signals: string[] }): {
  inputs: string[];
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
} {
  const { proof, pub_signals } = json;
  const { pi_a, pi_b, pi_c } = proof;
  const [[p1, p2], [p3, p4]] = pi_b;
  const preparedProof = {
    pi_a: pi_a.slice(0, 2),
    pi_b: [
      [p2, p1],
      [p4, p3],
    ],
    pi_c: pi_c.slice(0, 2),
  };

  return { inputs: pub_signals, ...preparedProof };
}

function generateChallenge(address: string): bigint {
  function padRightToUint256(bytes: Uint8Array) {
    const paddedBytes = new Uint8Array(32);
    paddedBytes.set(bytes, 0);
    return BigInt(hexlify(paddedBytes));
  }

  function reverseUint256(input: bigint) {
    // mask to restrict to 256 bits
    const MASK_256 = BigInt(
      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    );
    let v = BigInt(input);

    // Swap bytes
    v =
      ((v &
        BigInt(
          "0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00"
        )) >>
        8n) |
      ((v &
        BigInt(
          "0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF"
        )) <<
        8n);
    v &= MASK_256;

    // Swap 2-byte long pairs
    v =
      ((v &
        BigInt(
          "0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000"
        )) >>
        16n) |
      ((v &
        BigInt(
          "0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF"
        )) <<
        16n);
    v &= MASK_256;

    // Swap 4-byte long pairs
    v =
      ((v &
        BigInt(
          "0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000"
        )) >>
        32n) |
      ((v &
        BigInt(
          "0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF"
        )) <<
        32n);
    v &= MASK_256;

    // Swap 8-byte long pairs
    v =
      ((v &
        BigInt(
          "0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000"
        )) >>
        64n) |
      ((v &
        BigInt(
          "0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF"
        )) <<
        64n);
    v &= MASK_256;

    // Swap 16-byte long pairs
    v = ((v >> 128n) | (v << 128n)) & MASK_256;

    return v;
  }

  return reverseUint256(padRightToUint256(getBytes(address)));
}

async function identityCreation() {
  console.log("=============== key creation ===============");

  const { identityWallet } = await initInMemoryDataStorageAndWallets();
  const { did, credential } = await identityWallet.createIdentity({
    ...currentConfig.identityCreationOptions,
  });

  console.log("=============== did ===============");
  console.log(did.string());

  console.log("=============== Auth BJJ credential ===============");
  console.log(JSON.stringify(credential));
}

async function issueCredential() {
  console.log("=============== issue credential ===============");

  const { dataStorage, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== issuer did ===============");
  console.log(issuerDID.string());
  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  console.log("===============  credential ===============");
  console.log(JSON.stringify(credential));

  await dataStorage.credential.saveCredential(credential);
}

async function transitState() {
  console.log("=============== transit state ===============");

  const { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== issuerDID did ===============");
  console.log(issuerDID.string());

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishRevocationInfoByCredentialStatusType(
    issuerDID,
    currentConfig.credentialType,
    {
      rhsUrl: currentConfig.identityCreationOptions.revocationOpts.id,
    }
  );

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    WALLET_KEY,
    dataStorage.states.getRpcProvider()
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);
}

async function transitStateThirdPartyDID() {
  console.log(
    "=============== THIRD PARTY DID: transit state  ==============="
  );
  core.registerDidMethodNetwork({
    method: "thirdparty",
    methodByte: 0b1000_0001,
    blockchain: "linea",
    network: "test",
    networkFlag: 0b01000001 | 0b00000001,
    chainId: 11155112,
  });

  core.registerDidMethodNetwork({
    method: "iden3",
    blockchain: "linea",
    network: "test",
    networkFlag: 0b11000001 | 0b00000011,
  });

  const { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const method = core.DidMethod.thirdparty;
  const blockchain = core.Blockchain.linea;
  const networkId = core.NetworkId.test;
  const { did: userDID } = await identityWallet.createIdentity({
    method,
    blockchain,
    networkId,
    revocationOpts: currentConfig.identityCreationOptions.revocationOpts,
  });

  console.log("=============== third party: user did ===============");
  console.log(userDID.string());

  const { did: issuerDID } = await identityWallet.createIdentity({
    method: core.DidMethod.Iden3,
    blockchain: core.Blockchain.linea,
    networkId: core.NetworkId.test,
    revocationOpts: currentConfig.identityCreationOptions.revocationOpts,
  });
  console.log("=============== third party: issuer did ===============");
  console.log(issuerDID.string());

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= third party: generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log(
    "================= third party: push states to rhs ==================="
  );

  await identityWallet.publishRevocationInfoByCredentialStatusType(
    issuerDID,
    currentConfig.credentialType,
    {
      rhsUrl: currentConfig.identityCreationOptions.revocationOpts.id,
    }
  );

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    THIRD_PARTY_WALLET_KEY,
    (dataStorage.states as EthStateStorage).getRpcProvider()
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);
}

async function generateProofs(useMongoStore = false) {
  console.log("=============== generate proofs ===============");

  let dataStorage, credentialWallet, identityWallet;
  if (useMongoStore) {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initMongoDataStorageAndWallets());
  } else {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initInMemoryDataStorageAndWallets());
  }

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishRevocationInfoByCredentialStatusType(
    issuerDID,
    currentConfig.credentialType,
    {
      rhsUrl: RHS_URL,
    }
  );

  console.log("================= publish to blockchain ===================");

  const ethSigner = new Wallet(WALLET_KEY, dataStorage.states.getRpcProvider());
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  const { proof, pub_signals } = await proofService.generateProof(
    proofReqSig,
    userDID,
    {
      credential: credential,
      skipRevocation: false,
    }
  );

  const sigProofOk = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQuerySigV2
  );
  console.log("valid: ", sigProofOk);

  console.log(
    "================= generate credentialAtomicMTPV2 ==================="
  );

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

  console.log(credsWithIden3MTPProof);
  await credentialWallet.saveAll(credsWithIden3MTPProof);

  const proofReqMtp: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQueryMTPV2,
    credentialRequest
  );

  const { proof: proofMTP, pub_signals: pub_signalsMTP } =
    await proofService.generateProof(proofReqMtp, userDID);

  console.log(JSON.stringify(proofMTP));
  const mtpProofOk = await proofService.verifyProof(
    { proof: proofMTP, pub_signals: pub_signalsMTP },
    CircuitId.AtomicQueryMTPV2
  );
  console.log("valid: ", mtpProofOk);

  const { proof: proof2, pub_signals: pub_signals2 } =
    await proofService.generateProof(proofReqSig, userDID);

  const sigProof2Ok = await proofService.verifyProof(
    { proof: proof2, pub_signals: pub_signals2 },
    CircuitId.AtomicQuerySigV2
  );
  console.log("valid: ", sigProof2Ok);
}

async function handleAuthRequest(useMongoStore = false) {
  console.log("=============== handle auth request ===============");

  let dataStorage, credentialWallet, identityWallet;
  if (useMongoStore) {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initMongoDataStorageAndWallets());
  } else {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initInMemoryDataStorageAndWallets());
  }

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishRevocationInfoByCredentialStatusType(
    issuerDID,
    currentConfig.credentialType,
    {
      rhsUrl: currentConfig.identityCreationOptions.revocationOpts.id,
    }
  );

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    WALLET_KEY,
    (dataStorage.states as EthStateStorage).getRpcProvider()
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log("=================  credential auth request ===================");

  const authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.string(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify age",
    },
  };
  console.log(JSON.stringify(authRequest));

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

  console.log(credsWithIden3MTPProof);
  await credentialWallet.saveAll(credsWithIden3MTPProof);

  const authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);
  const authHandlerRequest = await authHandler.handleAuthorizationRequest(
    userDID,
    authRawRequest
  );
  console.log(JSON.stringify(authHandlerRequest, null, 2));
}

async function handleAuthRequestWithProfiles() {
  console.log(
    "=============== handle auth request with profiles ==============="
  );

  const { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  // credential is issued on the profile!
  const profileDID = await identityWallet.createProfile(
    userDID,
    50,
    issuerDID.string()
  );

  const credentialRequest = createKYCAgeCredential(profileDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log("=================  credential auth request ===================");

  const authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: VERIFIER_DID,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify age",
    },
  };
  console.log(JSON.stringify(authRequest));

  const authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);

  const authProfile = await identityWallet.getProfileByVerifier(
    authRequest.from
  );

  // let's check that we didn't create profile for verifier
  const authProfileDID = authProfile
    ? core.DID.parse(authProfile.id)
    : await identityWallet.createProfile(userDID, 100, authRequest.from);

  const resp = await authHandler.handleAuthorizationRequest(
    authProfileDID,
    authRawRequest
  );

  console.log(resp);
}

async function handleAuthRequestWithProfilesV3CircuitBeta() {
  console.log(
    "=============== handle auth request with profiles v3 circuits beta ==============="
  );

  const { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  // credential is issued on the profile!
  const profileDID = await identityWallet.createProfile(
    userDID,
    50,
    issuerDID.string()
  );

  const credentialRequest = createKYCAgeCredential(profileDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate credentialAtomicV3 ==================="
  );

  const proofReq: ZeroKnowledgeProofRequest = {
    id: 19,
    circuitId: CircuitId.AtomicQueryV3OnChain,
    params: {
      nullifierSessionId: "123443290439234342342423423423423",
    },
    query: {
      groupId: 1,
      allowedIssuers: ["*"],
      proofType: ProofType.BJJSignature,
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        documentType: {},
      },
    },
  };

  const linkedProof: ZeroKnowledgeProofRequest = {
    id: 20,
    circuitId: CircuitId.LinkedMultiQuery10,
    optional: false,
    query: {
      groupId: 1,
      proofType: ProofType.BJJSignature,
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        birthday: {
          $lt: 20010101,
        },
      },
    },
  };

  console.log("=================  credential auth request ===================");

  const authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: VERIFIER_DID,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "v3 beta",
      scope: [proofReq, linkedProof],
      reason: "selective disclosure of document type,",
    },
  };
  console.log(JSON.stringify(authRequest));

  const authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);

  const authProfile = await identityWallet.getProfileByVerifier(
    authRequest.from
  );

  // let's check that we didn't create profile for verifier
  const authProfileDID = authProfile
    ? core.DID.parse(authProfile.id)
    : await identityWallet.createProfile(userDID, 100, authRequest.from);

  const resp = await authHandler.handleAuthorizationRequest(
    authProfileDID,
    authRawRequest,
    {
      mediaType: PROTOCOL_CONSTANTS.MediaType.SignedMessage,
    }
  );

  console.log(resp);
}

async function handleAuthRequestNoIssuerStateTransition() {
  console.log(
    "=============== handle auth request no issuer state transition ==============="
  );

  const { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate credentialAtomicSigV2 ==================="
  );

  const proofReqSig: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
    CircuitId.AtomicQuerySigV2,
    credentialRequest
  );

  console.log("=================  credential auth request ===================");

  const authRequest: AuthorizationRequestMessage = {
    id: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    thid: "fe6354fe-3db2-48c2-a779-e39c2dda8d90",
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    from: issuerDID.string(),
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      callbackUrl: "http://testcallback.com",
      message: "message to sign",
      scope: [proofReqSig],
      reason: "verify age",
    },
  };
  console.log(JSON.stringify(authRequest));

  const authRawRequest = new TextEncoder().encode(JSON.stringify(authRequest));

  // * on the user side */

  console.log("============== handle auth request ==============");
  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);
  const authHandlerRequest = await authHandler.handleAuthorizationRequest(
    userDID,
    authRawRequest
  );
  console.log(JSON.stringify(authHandlerRequest, null, 2));
}

async function handleAuthRequestV3CircuitsBetaStateTransition() {
  console.log(
    "=============== handle auth request no issuer state transition V3 ==============="
  );

  const { dataStorage, credentialWallet, identityWallet } =
    await initInMemoryDataStorageAndWallets();

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const authV2Data = await circuitStorage.loadCircuitData(CircuitId.AuthV2);
  const pm = await initPackageManager(
    authV2Data,
    proofService.generateAuthV2Inputs.bind(proofService),
    proofService.verifyState.bind(proofService)
  );

  const authHandler = new AuthHandler(pm, proofService);

  const { did: issuerDID, credential: issuerAuthBJJCredential } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== user did ===============", issuerDID.string());

  const { did: userDID, credential: authBJJCredentialUser } =
    await identityWallet.createIdentity({
      ...currentConfig.identityCreationOptions,
    });

  console.log("=============== user did ===============", userDID.string());

  const profileDID = await identityWallet.createProfile(
    userDID,
    777,
    issuerDID.string()
  );

  const claimReq: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/kyc-nonmerklized.json",
    type: "KYCAgeCredential",
    credentialSubject: {
      id: userDID.string(),
      birthday: 19960424,
      documentType: 99,
    },
    expiration: 2793526400,
    revocationOpts: currentConfig.identityCreationOptions.revocationOpts,
  };
  const issuedCred = await identityWallet.issueCredential(issuerDID, claimReq);
  await credentialWallet.save(issuedCred);
  console.log("=============== issued birthday credential ===============");

  const res = await identityWallet.addCredentialsToMerkleTree(
    [issuedCred],
    issuerDID
  );
  console.log("=============== added to merkle tree ===============");

  await identityWallet.publishRevocationInfoByCredentialStatusType(
    issuerDID,
    currentConfig.credentialType,
    {
      rhsUrl: currentConfig.identityCreationOptions.revocationOpts.id,
    }
  );
  console.log("=============== published to rhs ===============");

  const ethSigner = new ethers.Wallet(
    WALLET_KEY,
    (dataStorage.states as EthStateStorage).getRpcProvider()
  );

  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );

  console.log("=============== state transition ===============", txId);

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

  await credentialWallet.saveAll(credsWithIden3MTPProof);

  console.log(
    "=============== saved credentials with mtp proof ==============="
  );

  const employeeCredRequest: CredentialRequest = {
    credentialSchema:
      "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCEmployee-v101.json",
    type: "KYCEmployee",
    credentialSubject: {
      id: profileDID.string(),
      ZKPexperiance: true,
      hireDate: "2023-12-11",
      position: "boss",
      salary: 200,
      documentType: 1,
    },
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: RHS_URL,
    },
  };
  const employeeCred = await identityWallet.issueCredential(
    issuerDID,
    employeeCredRequest
  );

  await credentialWallet.save(employeeCred);

  console.log("=============== issued employee credential ===============");

  console.log(
    "=============== generate ZeroKnowledgeProofRequest MTP + SIG + with Linked proof ==================="
  );

  const proofReqs: ZeroKnowledgeProofRequest[] = [
    {
      id: 1,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      query: {
        allowedIssuers: ["*"],
        type: claimReq.type,
        proofType: ProofType.Iden3SparseMerkleTreeProof,
        context:
          "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld",
        credentialSubject: {
          documentType: {
            $eq: 99,
          },
        },
      },
    },
    {
      id: 2,
      circuitId: CircuitId.AtomicQueryV3,
      optional: false,
      params: {
        nullifierSessionId: 12345,
      },
      query: {
        groupId: 1,
        proofType: ProofType.BJJSignature,
        allowedIssuers: ["*"],
        type: "KYCEmployee",
        context:
          "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
        skipClaimRevocationCheck: true,
        credentialSubject: {
          salary: {
            $eq: 200,
          },
        },
      },
    },
    {
      id: 3,
      circuitId: CircuitId.LinkedMultiQuery10,
      optional: false,
      query: {
        groupId: 1,
        proofType: ProofType.Iden3SparseMerkleTreeProof,
        allowedIssuers: ["*"],
        type: "KYCEmployee",
        skipClaimRevocationCheck: true,
        context:
          "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
        credentialSubject: {
          salary: {
            $ne: 300,
          },
        },
      },
    },
  ];

  const authReqBody: AuthorizationRequestMessageBody = {
    callbackUrl: "http://localhost:8080/callback?id=1234442-123123-123123",
    reason: "reason",
    message: "mesage",
    did_doc: {},
    scope: proofReqs,
  };

  const id = globalThis.crypto.randomUUID();
  const authReq: AuthorizationRequestMessage = {
    id,
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE
      .AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    thid: id,
    body: authReqBody,
    from: issuerDID.string(),
  };

  const msgBytes = byteEncoder.encode(JSON.stringify(authReq));
  console.log("=============== auth request ===============");

  const authHandlerRequest = await authHandler.handleAuthorizationRequest(
    userDID,
    msgBytes,
    {
      mediaType: PROTOCOL_CONSTANTS.MediaType.SignedMessage,
    }
  );
  console.log(JSON.stringify(authHandlerRequest, null, 2));
}

async function submitSigV2ZkResponse(useMongoStore = false) {
  let dataStorage, credentialWallet, identityWallet;
  if (useMongoStore) {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initMongoDataStorageAndWallets());
  } else {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initInMemoryDataStorageAndWallets());
  }

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID } = await identityWallet.createIdentity({
    ...DEFAULT_IDENTITY_CREATION_OPTIONS,
  });
  await identityWallet.createIdentity({
    ...currentConfig.identityCreationOptions,
  });
  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID } = await identityWallet.createIdentity({
    ...DEFAULT_IDENTITY_CREATION_OPTIONS,
  });

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate credentialAtomicSigV2OnChain ==================="
  );

  const ethSigner = new ethers.Wallet(
    WALLET_KEY,
    dataStorage.states.getRpcProvider()
  );
  const { proof, pub_signals } = await proofService.generateProof(
    {
      id: TRANSFER_REQUEST_ID_SIG_VALIDATOR,
      circuitId: CircuitId.AtomicQuerySigV2OnChain,
      optional: false,
      query: {
        allowedIssuers: ["*"],
        context:
          "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
        credentialSubject: { birthday: { $lt: 20020101 } },
        type: "KYCAgeCredential",
      },
    },
    userDID,
    {
      challenge: generateChallenge(await ethSigner.getAddress()),
      skipRevocation: false,
    }
  );

  const valid = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQuerySigV2OnChain
  );
  console.log("Proof ok: ", valid);

  console.log("================= Get request status ===============");

  const erc20Verifier = new ethers.Contract(
    ERC20_VERIFIER_ADDRESS,
    Erc20VerifierAbi,
    ethSigner
  );

  console.log(
    "ZKPRequest",
    await erc20Verifier.getZKPRequest(TRANSFER_REQUEST_ID_SIG_VALIDATOR)
  );

  const status = await erc20Verifier.getProofStatus(
    ethSigner.getAddress(),
    TRANSFER_REQUEST_ID_SIG_VALIDATOR
  );
  console.log("Proof status", status.isVerified);
  if (status.isVerified) {
    return console.log("Proof already verified");
  }

  console.log("=============== Airdrop balance ===============");

  const erc20Airdrop = new ethers.Contract(
    ERC20_ZK_AIRDROP_ADDRESS,
    Erc20AirdropAbi,
    ethSigner
  );
  console.log(
    "Balance before:",
    await erc20Airdrop.balanceOf(await ethSigner.getAddress())
  );

  console.log("================= Submit proof ===============");

  const { inputs, pi_a, pi_b, pi_c } = prepareProofInputs({
    proof,
    pub_signals,
  });
  const submitZkpResponseTx = await erc20Verifier.submitZKPResponse(
    TRANSFER_REQUEST_ID_SIG_VALIDATOR,
    inputs,
    pi_a,
    pi_b,
    pi_c
  );
  await submitZkpResponseTx.wait();
  console.log("Submit ZKPResponse tx hash", submitZkpResponseTx.hash);

  console.log("================= Get request status ===============");

  console.log(
    "Proof status",
    await erc20Verifier.getProofStatus(
      ethSigner.getAddress(),
      TRANSFER_REQUEST_ID_SIG_VALIDATOR
    )
  );

  if (ERC20_VERIFIER === VerifierType.Universal) {
    console.log("================= Mint erc20 airdrop ===============");

    const mintTx = await erc20Airdrop.mint(await ethSigner.getAddress());
    await mintTx.wait();
    console.log("MintTx hash", mintTx.hash);
  }

  console.log("=============== Airdrop balance ===============");
  console.log(
    "Balance after",
    await erc20Airdrop.balanceOf(await ethSigner.getAddress())
  );
}

async function submitMtpV2ZkResponse(useMongoStore = false) {
  let dataStorage, credentialWallet, identityWallet;
  if (useMongoStore) {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initMongoDataStorageAndWallets());
  } else {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initInMemoryDataStorageAndWallets());
  }

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID } = await identityWallet.createIdentity({
    ...DEFAULT_IDENTITY_CREATION_OPTIONS,
  });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID } = await identityWallet.createIdentity({
    ...DEFAULT_IDENTITY_CREATION_OPTIONS,
  });

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishRevocationInfoByCredentialStatusType(
    issuerDID,
    CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    { rhsUrl: RHS_URL }
  );

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    WALLET_KEY,
    dataStorage.states.getRpcProvider()
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  const credsWithIden3MTPProof =
    await identityWallet.generateIden3SparseMerkleTreeProof(
      issuerDID,
      res.credentials,
      txId
    );

  await dataStorage.credential.saveAllCredentials(credsWithIden3MTPProof);

  console.log(
    "================= generate credentialAtomicQueryMTPV2OnChain ==================="
  );

  const { proof, pub_signals } = await proofService.generateProof(
    {
      id: TRANSFER_REQUEST_ID_MTP_VALIDATOR,
      circuitId: CircuitId.AtomicQueryMTPV2OnChain,
      optional: false,
      query: {
        allowedIssuers: ["*"],
        context:
          "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
        credentialSubject: { birthday: { $lt: 20020101 } },
        type: "KYCAgeCredential",
      },
    },
    userDID,
    {
      challenge: generateChallenge(await ethSigner.getAddress()),
      skipRevocation: false,
    }
  );

  const valid = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQueryMTPV2OnChain
  );
  console.log("Proof ok: ", valid);

  console.log("================= Get request status ===============");

  const erc20Verifier = new ethers.Contract(
    ERC20_VERIFIER_ADDRESS,
    Erc20VerifierAbi,
    ethSigner
  );

  console.log(
    "ZKPRequest",
    TRANSFER_REQUEST_ID_MTP_VALIDATOR,
    await erc20Verifier.getZKPRequest(TRANSFER_REQUEST_ID_MTP_VALIDATOR)
  );

  const status = await erc20Verifier.getProofStatus(
    ethSigner.getAddress(),
    TRANSFER_REQUEST_ID_MTP_VALIDATOR
  );
  console.log("Proof status", status.isVerified);

  if (status.isVerified) {
    return console.log("Proof already verified");
  }

  console.log("=============== Airdrop balance ===============");

  const erc20Airdrop = new ethers.Contract(
    ERC20_ZK_AIRDROP_ADDRESS,
    Erc20AirdropAbi,
    ethSigner
  );
  console.log(
    "Balance before:",
    await erc20Airdrop.balanceOf(await ethSigner.getAddress())
  );

  console.log("================= Submit proof ===============");

  const { inputs, pi_a, pi_b, pi_c } = prepareProofInputs({
    proof,
    pub_signals,
  });

  const submitZkpResponseTx = await erc20Verifier.submitZKPResponse(
    TRANSFER_REQUEST_ID_MTP_VALIDATOR,
    inputs,
    pi_a,
    pi_b,
    pi_c
  );
  await submitZkpResponseTx.wait();
  console.log("Submit ZKPResponse tx hash", submitZkpResponseTx.hash);

  console.log("================= Get request status ===============");

  console.log(
    "Proof status",
    await erc20Verifier.getProofStatus(
      ethSigner.getAddress(),
      TRANSFER_REQUEST_ID_MTP_VALIDATOR
    )
  );

  if (ERC20_VERIFIER === VerifierType.Universal) {
    console.log("================= Mint erc20 airdrop ===============");

    const mintTx = await erc20Airdrop.mint(await ethSigner.getAddress());
    await mintTx.wait();
    console.log("MintTx hash", mintTx.hash);
  }

  console.log("=============== Airdrop balance ===============");

  console.log(
    "Balance after:",
    await erc20Airdrop.balanceOf(await ethSigner.getAddress())
  );
}

async function submitV3ZkResponse(useMongoStore = false) {
  console.warn(
    "By default provided ERC20 contract examples don't support V3, only selective disclosure."
  );

  let dataStorage, credentialWallet, identityWallet;
  if (useMongoStore) {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initMongoDataStorageAndWallets());
  } else {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initInMemoryDataStorageAndWallets());
  }

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID } = await identityWallet.createIdentity({
    ...DEFAULT_IDENTITY_CREATION_OPTIONS,
  });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID } = await identityWallet.createIdentity({
    ...DEFAULT_IDENTITY_CREATION_OPTIONS,
  });

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishRevocationInfoByCredentialStatusType(
    issuerDID,
    CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    { rhsUrl: RHS_URL }
  );

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    WALLET_KEY,
    dataStorage.states.getRpcProvider()
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log(
    "================= generate credentialAtomicQueryMTPV2OnChain ==================="
  );

  const { proof, pub_signals } = await proofService.generateProof(
    {
      id: TRANSFER_REQUEST_ID_V3,
      circuitId: CircuitId.AtomicQueryV3OnChain,
      optional: false,
      query: {
        allowedIssuers: ["*"],
        context:
          "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
        credentialSubject: { birthday: { $lt: 20020101 } },
        type: "KYCAgeCredential",
        proofType: 0,
        skipClaimRevocationCheck: false,
      },
      params: {
        nullifierSessionId: 0,
      },
    },
    userDID,
    {
      verifierDid: ERC20_VERIFIER_DID,
      challenge: generateChallenge(await ethSigner.getAddress()),
      skipRevocation: false,
    }
  );

  const valid = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQueryV3OnChain
  );
  console.log("Proof ok: ", valid);

  console.log("================= Get request status ===============");

  const erc20Verifier = new ethers.Contract(
    ERC20_VERIFIER_ADDRESS,
    Erc20VerifierAbi,
    ethSigner
  );

  console.log(
    "ZKPRequest",
    await erc20Verifier.getZKPRequest(TRANSFER_REQUEST_ID_V3)
  );

  const status = await erc20Verifier.getProofStatus(
    ethSigner.getAddress(),
    TRANSFER_REQUEST_ID_V3
  );
  console.log("Proof status", status.isVerified);

  if (status.isVerified) {
    return console.log("Proof already verified");
  }

  console.log("=============== Airdrop balance ===============");

  const erc20Airdrop = new ethers.Contract(
    ERC20_ZK_AIRDROP_ADDRESS,
    Erc20AirdropAbi,
    ethSigner
  );
  console.log(
    "Balance before:",
    await erc20Airdrop.balanceOf(await ethSigner.getAddress())
  );

  console.log("================= Submit proof ===============");

  const { inputs, pi_a, pi_b, pi_c } = prepareProofInputs({
    proof,
    pub_signals,
  });

  const submitZkpResponseTx = await erc20Verifier.submitZKPResponse(
    TRANSFER_REQUEST_ID_V3,
    inputs,
    pi_a,
    pi_b,
    pi_c
  );
  await submitZkpResponseTx.wait();

  console.log("Submit ZKPResponse tx hash", submitZkpResponseTx.hash);

  console.log("================= Get request status ===============");

  console.log(
    "Proof status",
    await erc20Verifier.getProofStatus(
      ethSigner.getAddress(),
      TRANSFER_REQUEST_ID_V3
    )
  );

  if (ERC20_VERIFIER === VerifierType.Universal) {
    console.log("================= Mint erc20 airdrop ===============");

    const mintTx = await erc20Airdrop.mint(await ethSigner.getAddress());
    await mintTx.wait();
    console.log("MintTx hash", mintTx.hash);
  }

  console.log("=============== Airdrop balance ===============");

  console.log(
    "Balance after",
    await erc20Airdrop.balanceOf(await ethSigner.getAddress())
  );
}

async function submitV3SelectiveDisclosureZkResponse(useMongoStore = false) {
  if (ERC20_VERIFIER !== VerifierType.SelectiveDisclosure) {
    throw new Error("Verifier is not SelectiveDisclosure");
  }

  let dataStorage, credentialWallet, identityWallet;
  if (useMongoStore) {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initMongoDataStorageAndWallets());
  } else {
    ({ dataStorage, credentialWallet, identityWallet } =
      await initInMemoryDataStorageAndWallets());
  }

  const circuitStorage = await initCircuitStorage();
  const proofService = await initProofService(
    identityWallet,
    credentialWallet,
    dataStorage.states,
    circuitStorage
  );

  const { did: userDID } = await identityWallet.createIdentity({
    ...DEFAULT_IDENTITY_CREATION_OPTIONS,
  });

  console.log("=============== user did ===============");
  console.log(userDID.string());

  const { did: issuerDID } = await identityWallet.createIdentity({
    ...DEFAULT_IDENTITY_CREATION_OPTIONS,
  });

  const credentialRequest = createKYCAgeCredential(userDID);
  const credential = await identityWallet.issueCredential(
    issuerDID,
    credentialRequest
  );

  await dataStorage.credential.saveCredential(credential);

  console.log(
    "================= generate Iden3SparseMerkleTreeProof ======================="
  );

  const res = await identityWallet.addCredentialsToMerkleTree(
    [credential],
    issuerDID
  );

  console.log("================= push states to rhs ===================");

  await identityWallet.publishRevocationInfoByCredentialStatusType(
    issuerDID,
    CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    { rhsUrl: RHS_URL }
  );

  console.log("================= publish to blockchain ===================");

  const ethSigner = new ethers.Wallet(
    WALLET_KEY,
    dataStorage.states.getRpcProvider()
  );
  const txId = await proofService.transitState(
    issuerDID,
    res.oldTreeState,
    true,
    dataStorage.states,
    ethSigner
  );
  console.log(txId);

  console.log(
    "================= generate credentialAtomicQueryMTPV2OnChain ==================="
  );

  const { proof, pub_signals } = await proofService.generateProof(
    {
      id: TRANSFER_REQUEST_ID_V3,
      circuitId: CircuitId.AtomicQueryV3OnChain,
      optional: false,
      query: {
        allowedIssuers: ["*"],
        context:
          "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
        credentialSubject: { birthday: {} },
        type: "KYCAgeCredential",
        proofType: 1,
        skipClaimRevocationCheck: false,
      },
      params: {
        nullifierSessionId: 0,
      },
    },
    userDID,
    {
      verifierDid: ERC20_VERIFIER_DID,
      challenge: generateChallenge(await ethSigner.getAddress()),
      skipRevocation: false,
    }
  );

  const valid = await proofService.verifyProof(
    { proof, pub_signals },
    CircuitId.AtomicQueryV3OnChain
  );
  console.log("Proof ok: ", valid);

  console.log("================= Get request status ===============");

  const erc20Verifier = new ethers.Contract(
    ERC20_VERIFIER_ADDRESS,
    Erc20VerifierAbi,
    ethSigner
  );

  console.log(
    "ZKPRequest",
    await erc20Verifier.getZKPRequest(TRANSFER_REQUEST_ID_V3)
  );

  const status = await erc20Verifier.getProofStatus(
    ethSigner.getAddress(),
    TRANSFER_REQUEST_ID_V3
  );
  console.log("Proof status", status.isVerified);

  if (status.isVerified) {
    return console.log("Proof already verified");
  }

  console.log("=============== Airdrop balance ===============");

  const erc20Airdrop = new ethers.Contract(
    ERC20_ZK_AIRDROP_ADDRESS,
    Erc20AirdropAbi,
    ethSigner
  );
  console.log(
    "Balance before:",
    await erc20Airdrop.balanceOf(await ethSigner.getAddress())
  );

  console.log("================= Submit proof ===============");

  const { inputs, pi_a, pi_b, pi_c } = prepareProofInputs({
    proof,
    pub_signals,
  });

  const submitZkpResponseTx = await erc20Verifier.submitZKPResponse(
    TRANSFER_REQUEST_ID_V3,
    inputs,
    pi_a,
    pi_b,
    pi_c
  );
  await submitZkpResponseTx.wait();

  console.log("Submit ZKPResponse tx hash", submitZkpResponseTx.hash);

  console.log("================= Get request status ===============");

  console.log(
    "Proof status",
    await erc20Verifier.getProofStatus(
      ethSigner.getAddress(),
      TRANSFER_REQUEST_ID_V3
    )
  );

  console.log("=============== Airdrop balance ===============");

  console.log(
    "Balance after:",
    await erc20Airdrop.balanceOf(await ethSigner.getAddress())
  );
}

async function main(choice: string) {
  switch (choice) {
    case "identityCreation":
      await identityCreation();
      break;
    case "issueCredential":
      await issueCredential();
      break;
    case "transitState":
      await transitState();
      break;
    case "generateProofs":
      await generateProofs();
      break;
    case "handleAuthRequest":
      await handleAuthRequest();
      break;
    case "handleAuthRequestWithProfiles":
      await handleAuthRequestWithProfiles();
      break;
    case "handleAuthRequestWithProfilesV3CircuitBeta":
      await handleAuthRequestWithProfilesV3CircuitBeta();
      break;
    case "handleAuthRequestNoIssuerStateTransition":
      await handleAuthRequestNoIssuerStateTransition();
      break;
    case "generateRequestData":
      await generateRequestData();
      break;
    case "transitStateThirdPartyDID":
      await transitStateThirdPartyDID();
      break;
    case "handleAuthRequestV3CircuitsBetaStateTransition":
      await handleAuthRequestV3CircuitsBetaStateTransition();
      break;
    case "submitSigV2ZkResponse":
      await submitSigV2ZkResponse();
      break;
    case "submitMtpV2ZkResponse":
      await submitMtpV2ZkResponse();
      break;
    case "submitV3ZkResponse":
      await submitV3ZkResponse();
      break;
    case "submitV3SelectiveDisclosureZkResponse":
      await submitV3SelectiveDisclosureZkResponse();
      break;

    default:
      // default run all
      await identityCreation();
      await issueCredential();
      await transitState();
      await generateProofs();
      await handleAuthRequest();
      await handleAuthRequestWithProfiles();
      await handleAuthRequestWithProfilesV3CircuitBeta();
      await handleAuthRequestNoIssuerStateTransition();
      await generateRequestData();
      await handleAuthRequestV3CircuitsBetaStateTransition();
  }
}

(async function () {
  const args = process.argv.slice(2);
  await main(args[0]);
})();
