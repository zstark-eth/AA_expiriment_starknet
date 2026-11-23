
import { typedData } from "starknet";

const accountAddress =
  "0x3d9c0006cfcb13af4fe34b0fdca7a5e1001acd3b51ce4251920b3a9d9012e3d";

const data = {
  types: {
    StarknetDomain: [
      { name: "name", type: "shortstring" },
      { name: "version", type: "shortstring" },
      { name: "chainId", type: "shortstring" },
      { name: "revision", type: "shortstring" }
    ],

    OutsideExecution: [
      { name: "Caller", type: "ContractAddress" },
      { name: "Nonce", type: "felt" },
      { name: "Execute After", type: "u128" },
      { name: "Execute Before", type: "u128" },
      { name: "Calls", type: "Call*" }
    ],

    Call: [
      { name: "To", type: "ContractAddress" },
      { name: "Selector", type: "selector" },
      { name: "Calldata", type: "felt*" }
    ]
  },

  primaryType: "OutsideExecution",

  domain: {
    name: "Account.execute_from_outside",
    version: 2,
    chainId: "SN_SEPOLIA",
    revision: 1
  },

  message: {
    Caller: "0x777",
    Nonce: "0x12345",
    "Execute After": 1000,
    "Execute Before": 2000,

    Calls: [
      {
        To: "0x111",
        Selector: "transfer",
        Calldata: ["0x222", "100000000", "0"]
      },
      {
        To: "0x333",
        Selector: "approve",
        Calldata: ["0x444", "0x5678", "200000000"]
      }
    ]
  }
};

const hash = typedData.getMessageHash(data, accountAddress);

console.log("STARKNET.JS HASH:", hash);
