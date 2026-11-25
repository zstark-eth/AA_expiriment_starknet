
import "dotenv/config";

import { Account, RpcProvider } from "starknet";
import { MultiSigDeploySigner } from "./multisig-deploy-signer.js";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

async function getBalance(
  provider: RpcProvider,
  token: string,
  address: string
): Promise<bigint> {
  const result = await provider.callContract({
    contractAddress: token,
    entrypoint: "balanceOf",
    calldata: [address],
  });

  return BigInt(result[0]) + (BigInt(result[1]) << 128n);
}

async function main() {
  if (required("NETWORK") !== "devnet") {
    throw new Error("Devnet only");
  }

  const provider = new RpcProvider({
    nodeUrl: required("RPC_URL"),
  });

  const accountAddress = required("AA_ADDRESS");
  const recipient = required("RECIPIENT_ADDRESS");
  const token = required("FEE_TOKEN_ADDRESS");

  const ownerKeys = required("OWNER_PRIVATE_KEYS")
    .split(",")
    .map((key) => key.trim());

  if (ownerKeys.length < 2) {
    throw new Error("Two owner keys are required");
  }

  // Intentionally use only ONE owner.
  const account = new Account({
    provider,
    address: accountAddress,
    signer: new MultiSigDeploySigner([ownerKeys[0]]),
  });

  const amount = BigInt(required("TRANSFER_AMOUNT_BASE_UNITS"));

  const balanceBefore = await getBalance(
    provider, token, recipient
  );

  const nonceBefore = BigInt(await account.getNonce());

  console.log("Testing with only one owner signature...");
  console.log("Threshold: 2");
  console.log("Provided signatures: 1");

  const mask128 = (1n << 128n) - 1n;

  let transactionHash: string | undefined;
  let rejection = "";

  try {
    const tx = await account.execute(
      {
        contractAddress: token,
        entrypoint: "transfer",
        calldata: [
          recipient,
          (amount & mask128).toString(),
          (amount >> 128n).toString(),
        ],
      },
      {
        version: "0x3",
        skipValidate: false,
      }
    );

    transactionHash = tx.transaction_hash;
  } catch (error) {
    rejection = error instanceof Error
      ? `${error.name}: ${error.message}`
      : String(error);

    console.log("Transaction rejected by RPC:");
    console.log(rejection);
  }

  if (transactionHash) {
    throw new Error(
      `SECURITY FAILURE: transaction was accepted: ${transactionHash}`
    );
  }

  if (!rejection) {
    throw new Error("No rejection was received");
  }

  const balanceAfter = await getBalance(
    provider, token, recipient
  );

  const nonceAfter = BigInt(await account.getNonce());

  if (balanceAfter !== balanceBefore) {
    throw new Error("SECURITY FAILURE: recipient received tokens");
  }

  if (nonceAfter !== nonceBefore) {
    throw new Error("Unexpected nonce change after rejected transaction");
  }

  console.log("SUCCESS: insufficient multisig was rejected.");
  console.log("Recipient balance unchanged.");
  console.log("Account nonce unchanged.");
}

main().catch((error) => {
  console.error("Test failed:", error);
  process.exitCode = 1;
});
