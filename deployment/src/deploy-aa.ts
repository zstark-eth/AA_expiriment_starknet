import "dotenv/config";

import { readFileSync } from "node:fs";

import {
  Account,
  RpcProvider,
  CallData,
  ec,
  hash,
} from "starknet";

import { MultiSigDeploySigner } from "./multisig-deploy-signer.js";

function required(name: string): string {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }

  return value;
}

async function main() {
  const rpcUrl = required("RPC_URL");
  const funderAddress = required("FUNDER_ADDRESS");
  const funderPrivateKey = required("FUNDER_PRIVATE_KEY");
  const feeTokenAddress = required("FEE_TOKEN_ADDRESS");

  const ownerPrivateKeys = required("OWNER_PRIVATE_KEYS")
    .split(",")
    .map((key) => key.trim())
    .filter(Boolean);

  const threshold = Number(required("THRESHOLD"));
  const addressSalt = required("ACCOUNT_SALT");

  if (
    !Number.isInteger(threshold) ||
    threshold < 1 ||
    threshold > ownerPrivateKeys.length
  ) {
    throw new Error("Invalid multisig threshold");
  }

  const provider = new RpcProvider({
    nodeUrl: rpcUrl,
  });

  const network = required("NETWORK");

const actualChainId = await provider.getChainId();

const expectedChainIds: Record<string, string> = {
  devnet: "0x534e5f5345504f4c4941",
  sepolia: "0x534e5f5345504f4c4941",
  mainnet: "0x534e5f4d41494e",
};

if (!(network in expectedChainIds)) {
  throw new Error("Unsupported network");
}

if (
  BigInt(actualChainId) !== BigInt(expectedChainIds[network])
) {
  throw new Error(`Wrong chain ID for ${network}`);
}

const rpcHost = new URL(rpcUrl).hostname;
const isLocal = ["127.0.0.1", "localhost", "::1"].includes(rpcHost);

if ((network === "devnet") !== isLocal) {
  throw new Error("RPC endpoint does not match selected network");
}

if (network !== "devnet" && new URL(rpcUrl).protocol !== "https:") {
  throw new Error("Remote networks require HTTPS RPC");
}

if (
  network === "mainnet" &&
  process.env.MAINNET_CONFIRMATION !== "I_UNDERSTAND"
) {
  throw new Error("Mainnet deployment requires explicit confirmation");
}

console.log(`Network: ${network}`);
console.log(`Chain ID: ${actualChainId}`);

  // The funder is an already deployed account.
  const funder = new Account({
    provider,
    address: funderAddress,
    signer: funderPrivateKey,
  });

  // Load Sierra and CASM artifacts produced by Scarb.
  const contract = JSON.parse(
    readFileSync(
      "../target/dev/aa_experiment_AA.contract_class.json",
      "utf8"
    )
  );

  const casm = JSON.parse(
    readFileSync(
      "../target/dev/aa_experiment_AA.compiled_contract_class.json",
      "utf8"
    )
  );

  // Declare the AA class once per network.
  const declaration = await funder.declareIfNot({
    contract,
    casm,
  });

  if (declaration.transaction_hash !== "") {
    console.log("Declare transaction:", declaration.transaction_hash);

    await provider.waitForTransaction(
      declaration.transaction_hash
    );
  }

  const classHash = declaration.class_hash;

  // Derive public keys from the owner private keys.
  const ownerPublicKeys = ownerPrivateKeys.map((privateKey) =>
    ec.starkCurve.getStarkKey(privateKey)
  );

  if (new Set(ownerPublicKeys.map((key) => BigInt(key).toString())).size
      !== ownerPublicKeys.length) {
    throw new Error("Duplicate owner keys are not allowed");
  }

  // Cairo Array<felt252> serialization:
  // [array_length, owner_1, owner_2, ..., threshold]
  const constructorCalldata = CallData.compile([
    ownerPublicKeys.length.toString(),
    ...ownerPublicKeys,
    threshold.toString(),
  ]);

  // Calculate the future account address before deployment.
  const futureAddress = hash.calculateContractAddressFromHash(
    addressSalt,
    classHash,
    constructorCalldata,
    0
  );

  console.log("Class hash:", classHash);
  console.log("Future AA address:", futureAddress);
  console.log("Owners:", ownerPublicKeys);
  console.log("Threshold:", threshold);

  // Prefund the future account to pay its DeployAccount fee.
  const fundingAmount = BigInt(
    required("PREFUND_AMOUNT_BASE_UNITS")
  );

  if (fundingAmount <= 0n) {
    throw new Error("Prefunding amount must be positive");
  }

  const mask128 = (1n << 128n) - 1n;
  const low = fundingAmount & mask128;
  const high = fundingAmount >> 128n;

  const fundingTx = await funder.execute({
    contractAddress: feeTokenAddress,
    entrypoint: "transfer",
    calldata: [
      futureAddress,
      low.toString(),
      high.toString(),
    ],
  });

  console.log("Funding transaction:", fundingTx.transaction_hash);

  await provider.waitForTransaction(
    fundingTx.transaction_hash
  );

  // Use the future address as the Account address.
  // Starknet.js will call our custom signer for DeployAccount.
  const multisigSigner = new MultiSigDeploySigner(
    ownerPrivateKeys
  );

  const counterfactualAccount = new Account({
    provider,
    address: futureAddress,
    signer: multisigSigner,
  });

  // This sends a real DEPLOY_ACCOUNT transaction.
  // Resource bounds are estimated by Starknet.js if omitted.
  const deployment = await counterfactualAccount.deployAccount({
    classHash,
    addressSalt,
    constructorCalldata,
  }, {
    version: "0x3",
  });

  console.log("DeployAccount transaction:", deployment.transaction_hash);

  await provider.waitForTransaction(
    deployment.transaction_hash
  );

  // Confirm that the contract is now deployed at the predicted address.
  const deployedClassHash = await provider.getClassHashAt(
    futureAddress
  );

  if (BigInt(deployedClassHash) !== BigInt(classHash)) {
    throw new Error("Unexpected class hash at deployed address");
  }

  // Read threshold and owners from the deployed AA.
  const thresholdResult = await provider.callContract({
    contractAddress: futureAddress,
    entrypoint: "get_threshold",
    calldata: [],
  });

  const ownersResult = await provider.callContract({
    contractAddress: futureAddress,
    entrypoint: "get_public_keys_arr",
    calldata: [],
  });

  const deployedThreshold = BigInt(thresholdResult[0]);

  const ownerCount = Number(BigInt(ownersResult[0]));
  const deployedOwners = ownersResult.slice(1, 1 + ownerCount);

  console.log("Deployment successful!");
  console.log("Address:", futureAddress);
  console.log("Deployed threshold:", deployedThreshold.toString());
  console.log("Deployed owners:", deployedOwners);
}

main().catch((error) => {
  console.error("Deployment failed:", error);
  process.exitCode = 1;
});
