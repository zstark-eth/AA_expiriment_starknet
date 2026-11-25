import { Signer, CallData, ec, hash, stark, transaction } from "starknet";

import type {
  Call,
  DeployAccountSignerDetails,
  InvocationsSignerDetails,
  Signature,
} from "starknet";


export class MultiSigDeploySigner extends Signer {
  private readonly ownerPrivateKeys: string[];

  constructor(ownerPrivateKeys: string[]) {
    if (ownerPrivateKeys.length === 0) {
      throw new Error("At least one owner key is required");
    }

    super(ownerPrivateKeys[0]);

    this.ownerPrivateKeys = [...ownerPrivateKeys];
  }

  override async signDeployAccountTransaction(
    details: DeployAccountSignerDetails
  ): Promise<Signature> {
    // This signer currently supports DeployAccount V3 only.
    if (BigInt(details.version) !== 3n) {
      throw new Error("Only DeployAccount V3 is supported");
    }

    const compiledConstructorCalldata = CallData.compile(
      details.constructorCalldata
    );

    // Use the exact transaction hash algorithm from Starknet.js.
    const transactionHash =
      hash.calculateDeployAccountTransactionHash({
        ...details,
        salt: details.addressSalt,
        compiledConstructorCalldata,
        version: details.version,
        nonceDataAvailabilityMode: stark.intDAM(
          details.nonceDataAvailabilityMode
        ),
        feeDataAvailabilityMode: stark.intDAM(
          details.feeDataAvailabilityMode
        ),
      });

    // Cairo AA expects [public_key, r, s, ...].
    return this.ownerPrivateKeys.flatMap((privateKey) => {
      const publicKey = ec.starkCurve.getStarkKey(privateKey);

      const { r, s } = ec.starkCurve.sign(
        transactionHash,
        privateKey
      );

      return [
        publicKey,
        r.toString(),
        s.toString(),
      ];
    });
  }

  // Regular Invoke signing will be implemented separately.
  override async signTransaction(
  transactions: Call[],
  details: InvocationsSignerDetails
 ): Promise<Signature> {
  if (BigInt(details.version) !== 3n) {
    throw new Error("Only Invoke V3 is supported");
  }

  const compiledCalldata = transaction.getExecuteCalldata(
    transactions,
    details.cairoVersion
  );

  const transactionHash = hash.calculateInvokeTransactionHash({
    ...details,
    senderAddress: details.walletAddress,
    compiledCalldata,
    version: details.version,
    nonceDataAvailabilityMode: stark.intDAM(
      details.nonceDataAvailabilityMode
    ),
    feeDataAvailabilityMode: stark.intDAM(
      details.feeDataAvailabilityMode
    ),
  });

  return this.ownerPrivateKeys.flatMap((privateKey) => {
    const publicKey = ec.starkCurve.getStarkKey(privateKey);

    const { r, s } = ec.starkCurve.sign(
      transactionHash,
      privateKey
    );

    return [publicKey, r.toString(), s.toString()];
  });
 }
}
