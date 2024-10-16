import { proving } from "@iden3/js-jwz";
import {
  BjjProvider,
  CredentialStorage,
  CredentialWallet,
  defaultEthConnectionConfig,
  EthStateStorage,
  ICredentialWallet,
  IDataStorage,
  Identity,
  IdentityStorage,
  IdentityWallet,
  IIdentityWallet,
  InMemoryDataSource,
  InMemoryMerkleTreeStorage,
  InMemoryPrivateKeyStore,
  KMS,
  KmsKeyType,
  Profile,
  W3CCredential,
  EthConnectionConfig,
  CircuitData,
  IStateStorage,
  ProofService,
  ICircuitStorage,
  CredentialStatusType,
  CredentialStatusResolverRegistry,
  IssuerResolver,
  RHSResolver,
  OnChainResolver,
  AuthDataPrepareFunc,
  StateVerificationFunc,
  DataPrepareHandlerFunc,
  VerificationHandlerFunc,
  IPackageManager,
  VerificationParams,
  ProvingParams,
  ZKPPacker,
  PlainPacker,
  PackageManager,
  AgentResolver,
  FSCircuitStorage,
  AbstractPrivateKeyStore,
  CredentialStatusPublisherRegistry,
  Iden3SmtRhsCredentialStatusPublisher,
  Iden3OnchainSmtCredentialStatusPublisher,
  OnChainRevocationStorage,
} from "@wakeuplabs/opid-sdk";
import path from "path";
import {
  MongoDataSourceFactory,
  MerkleTreeMongodDBStorage,
} from "@0xpolygonid/mongo-storage";
import { MongoMemoryServer } from "mongodb-memory-server";
import { MongoClient, Db } from "mongodb";
import { ethers } from "ethers";
import {
  CIRCUITS_FOLDER,
  MONGO_DB_CONNECTION,
  RPC_URL,
  STATE_CONTRACT_ADDRESS,
  MONGO_DB_TABLE_NAME,
  WALLET_KEY,
  RHS_ADDRESS,
  CHAIN_ID,
} from "../config";

const conf: EthConnectionConfig = {
  ...defaultEthConnectionConfig,
  contractAddress: STATE_CONTRACT_ADDRESS,
  url: RPC_URL,
  chainId: CHAIN_ID,
};

export function initInMemoryDataStorage(): IDataStorage {
  // change here priority fees in case transaction is stuck or processing too long
  // conf.maxPriorityFeePerGas = '250000000000' - 250 gwei
  // conf.maxFeePerGas = '250000000000' - 250 gwei

  const dataStorage = {
    credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
    identity: new IdentityStorage(
      new InMemoryDataSource<Identity>(),
      new InMemoryDataSource<Profile>()
    ),
    mt: new InMemoryMerkleTreeStorage(40),

    states: new EthStateStorage(conf),
  };

  return dataStorage;
}

export async function initMongoDataStorage(): Promise<IDataStorage> {
  let url = MONGO_DB_CONNECTION;
  if (!url) {
    const mongodb = await MongoMemoryServer.create();
    url = mongodb.getUri();
  }
  const client = new MongoClient(url);
  await client.connect();
  const db: Db = client.db(MONGO_DB_TABLE_NAME);

  const dataStorage = {
    credential: new CredentialStorage(
      await MongoDataSourceFactory<W3CCredential>(db, "credentials")
    ),
    identity: new IdentityStorage(
      await MongoDataSourceFactory<Identity>(db, "identity"),
      await MongoDataSourceFactory<Profile>(db, "profile")
    ),
    mt: await MerkleTreeMongodDBStorage.setup(db, 40),
    states: new EthStateStorage(conf),
  };

  return dataStorage as unknown as IDataStorage;
}

export async function initIdentityWallet(
  dataStorage: IDataStorage,
  credentialWallet: ICredentialWallet,
  keyStore: AbstractPrivateKeyStore
): Promise<IIdentityWallet> {
  const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, keyStore);
  const kms = new KMS();
  kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

  const credentialStatusPublisherRegistry =
    new CredentialStatusPublisherRegistry();
  credentialStatusPublisherRegistry.register(
    CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    new Iden3SmtRhsCredentialStatusPublisher()
  );
  if (!WALLET_KEY) throw new Error("wallet key not configured");
  const ethSigner = new ethers.Wallet(
    WALLET_KEY,
    dataStorage.states.getRpcProvider()
  );
  if (RHS_ADDRESS)
    credentialStatusPublisherRegistry.register(
      CredentialStatusType.Iden3OnchainSparseMerkleTreeProof2023,
      new Iden3OnchainSmtCredentialStatusPublisher(
        new OnChainRevocationStorage(conf, RHS_ADDRESS, ethSigner)
      )
    );

  return new IdentityWallet(kms, dataStorage, credentialWallet, {
    credentialStatusPublisherRegistry,
  });
}

export async function initInMemoryDataStorageAndWallets() {
  const dataStorage = initInMemoryDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const memoryKeyStore = new InMemoryPrivateKeyStore();

  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet,
    memoryKeyStore
  );

  return {
    dataStorage,
    credentialWallet,
    identityWallet,
  };
}

export async function initMongoDataStorageAndWallets() {
  const dataStorage = await initMongoDataStorage();
  const credentialWallet = await initCredentialWallet(dataStorage);
  const memoryKeyStore = new InMemoryPrivateKeyStore();

  const identityWallet = await initIdentityWallet(
    dataStorage,
    credentialWallet,
    memoryKeyStore
  );

  return {
    dataStorage,
    credentialWallet,
    identityWallet,
  };
}

export async function initCredentialWallet(
  dataStorage: IDataStorage
): Promise<CredentialWallet> {
  const resolvers = new CredentialStatusResolverRegistry();
  resolvers.register(
    CredentialStatusType.SparseMerkleTreeProof,
    new IssuerResolver()
  );
  resolvers.register(
    CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
    new RHSResolver(dataStorage.states)
  );
  resolvers.register(
    CredentialStatusType.Iden3OnchainSparseMerkleTreeProof2023,
    new OnChainResolver([conf])
  );
  resolvers.register(
    CredentialStatusType.Iden3commRevocationStatusV1,
    new AgentResolver()
  );

  return new CredentialWallet(dataStorage, resolvers);
}

export async function initCircuitStorage(): Promise<ICircuitStorage> {
  return new FSCircuitStorage({
    dirname: path.join(__dirname, "../../circuits"),
  });
}
export async function initProofService(
  identityWallet: IIdentityWallet,
  credentialWallet: ICredentialWallet,
  stateStorage: IStateStorage,
  circuitStorage: ICircuitStorage
): Promise<ProofService> {
  return new ProofService(
    identityWallet,
    credentialWallet,
    circuitStorage,
    stateStorage,
    {
      ipfsGatewayURL: "https://ipfs.io",
    }
  );
}

export async function initPackageManager(
  circuitData: CircuitData,
  prepareFn: AuthDataPrepareFunc,
  stateVerificationFn: StateVerificationFunc
): Promise<IPackageManager> {
  const authInputsHandler = new DataPrepareHandlerFunc(prepareFn);

  const verificationFn = new VerificationHandlerFunc(stateVerificationFn);
  const mapKey =
    proving.provingMethodGroth16AuthV2Instance.methodAlg.toString();
  const verificationParamMap: Map<string, VerificationParams> = new Map([
    [
      mapKey,
      {
        key: circuitData.verificationKey!,
        verificationFn,
      },
    ],
  ]);

  const provingParamMap: Map<string, ProvingParams> = new Map();
  provingParamMap.set(mapKey, {
    dataPreparer: authInputsHandler,
    provingKey: circuitData.provingKey!,
    wasm: circuitData.wasm!,
  });

  const mgr: IPackageManager = new PackageManager();
  const packer = new ZKPPacker(provingParamMap, verificationParamMap);
  const plainPacker = new PlainPacker();
  mgr.registerPackers([packer, plainPacker]);

  return mgr;
}
