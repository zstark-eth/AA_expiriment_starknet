
import "dotenv/config";

import { Account, RpcProvider } from "starknet";
import { MultiSigDeploySigner } from "./multisig-deploy-signer.js";

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

async function getStrkBalance(
  provider: RpcProvider,
  token: string,
  address: string
): Promise<bigint> {
  const result = await provider.callContract({
    contractAddress: token,
    entrypoint: "balanceOf",
    calldata: [address],
  });

  if (result.length < 2) {
    throw new Error("Invalid ERC20 balance response");
  }

  const low = BigInt(result[0]);
  const high = BigInt(result[1]);

  return low + (high << 128n);
}

async function main() {
  const network = required("NETWORK");

  // First interaction test is local Devnet only.
  if (network !== "devnet") {
    throw new Error("This interaction test is Devnet-only for now");
  }

  const rpcUrl = required("RPC_URL");
  const provider = new RpcProvider({ nodeUrl: rpcUrl });

  const host = new URL(rpcUrl).hostname;
  if (!["127.0.0.1", "localhost", "::1"].includes(host)) {
    throw new Error("Expected local Devnet RPC");
  }

  const chainId = await provider.getChainId();

  if (BigInt(chainId) !== BigInt("0x534e5f5345504f4c4941")) {
    throw new Error("Wrong chain ID");
  }

  const accountAddress = required("AA_ADDRESS");
  const recipient = required("RECIPIENT_ADDRESS");
  const token = required("FEE_TOKEN_ADDRESS");

  if (BigInt(accountAddress) === BigInt(recipient)) {
    throw new Error("Recipient must differ from AA");
  }

  const ownerPrivateKeys = required("OWNER_PRIVATE_KEYS")
    .split(",")
    .map((key) => key.trim());

  const account = new Account({
    provider,
    address: accountAddress,
    signer: new MultiSigDeploySigner(ownerPrivateKeys),
  });

  const amount = BigInt(required("TRANSFER_AMOUNT_BASE_UNITS"));

  if (amount <= 0n) {
    throw new Error("Transfer amount must be positive");
  }

  const senderBefore = await getStrkBalance(
    provider, token, accountAddress
  );

  const recipientBefore = await getStrkBalance(
    provider, token, recipient
  );

  const feeReserve = 10n ** 18n; // Keep at least 1 STRK for fees.

  if (senderBefore < amount + feeReserve) {
    throw new Error("Insufficient STRK balance for transfer and fee reserve");
  }

  console.log("AA STRK balance before:", senderBefore.toString());
  console.log("Recipient balance before:", recipientBefore.toString());
  console.log("Transfer amount:", amount.toString());

  const mask128 = (1n << 128n) - 1n;
  const low = amount & mask128;
  const high = amount >> 128n;

  // Starknet.js constructs and signs an Invoke V3 transaction.
  const tx = await account.execute(
    {
      contractAddress: token,
      entrypoint: "transfer",
      calldata: [
        recipient,
        low.toString(),
        high.toString(),
      ],
    },
    {
      version: "0x3",
      skipValidate: false,
    }
  );

  console.log("Invoke transaction:", tx.transaction_hash);

  await provider.waitForTransaction(tx.transaction_hash);

  const senderAfter = await getStrkBalance(
    provider, token, accountAddress
  );

  const recipientAfter = await getStrkBalance(
    provider, token, recipient
  );

  if (recipientAfter !== recipientBefore + amount) {
    throw new Error("Recipient balance does not match expected transfer");
  }

  if (senderAfter >= senderBefore) {
    throw new Error("AA balance did not decrease");
  }

  console.log("Transfer successful!");
  console.log("AA balance after:", senderAfter.toString());
  console.log("Recipient balance after:", recipientAfter.toString());
}

main().catch((error) => {
  console.error("Interaction failed:", error);
  process.exitCode = 1;
});
