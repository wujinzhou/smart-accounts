/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Signer, utils } from "ethers";
import type { Provider } from "@ethersproject/providers";
import type {
  ISecp256r1,
  ISecp256r1Interface,
} from "../../../../contracts/validators/p256/ISecp256r1";

const _abi = [
  {
    inputs: [
      {
        internalType: "bytes32",
        name: "message",
        type: "bytes32",
      },
      {
        internalType: "bytes",
        name: "signature",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "publicKey",
        type: "bytes",
      },
    ],
    name: "validateSignature",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

export class ISecp256r1__factory {
  static readonly abi = _abi;
  static createInterface(): ISecp256r1Interface {
    return new utils.Interface(_abi) as ISecp256r1Interface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): ISecp256r1 {
    return new Contract(address, _abi, signerOrProvider) as ISecp256r1;
  }
}
