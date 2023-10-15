/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type {
  SmartAccount,
  SmartAccountInterface,
} from "../../contracts/SmartAccount";

const _abi = [
  {
    inputs: [
      {
        internalType: "contract IEntryPoint",
        name: "_EntryPoint",
        type: "address",
      },
    ],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [],
    name: "AddressCannotBeZero",
    type: "error",
  },
  {
    inputs: [],
    name: "CallerNotEntryPoint",
    type: "error",
  },
  {
    inputs: [],
    name: "CallerNotSelf",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "ErrorRecoveror",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "ErrorValidator",
    type: "error",
  },
  {
    inputs: [],
    name: "InvalidHook",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "validator",
        type: "address",
      },
    ],
    name: "ValidatorAlreadyEnabled",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "expectedValidator",
        type: "address",
      },
      {
        internalType: "address",
        name: "returnedValidator",
        type: "address",
      },
      {
        internalType: "address",
        name: "prevValidator",
        type: "address",
      },
    ],
    name: "ValidatorAndPrevValidatorMismatch",
    type: "error",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "validator",
        type: "address",
      },
    ],
    name: "ValidatorCannotBeZeroOrSentinel",
    type: "error",
  },
  {
    inputs: [],
    name: "WrongArrayLength",
    type: "error",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "recoveror",
        type: "address",
      },
    ],
    name: "AddedRecoveror",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "previousHandler",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "handler",
        type: "address",
      },
    ],
    name: "ChangedFallbackHandler",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "validator",
        type: "address",
      },
    ],
    name: "DisabledValidator",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "validator",
        type: "address",
      },
    ],
    name: "EnabledValidator",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "uint8",
        name: "version",
        type: "uint8",
      },
    ],
    name: "Initialized",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "hook",
        type: "address",
      },
    ],
    name: "InstalledHook",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "address",
        name: "recoveror",
        type: "address",
      },
    ],
    name: "RemovedRecoveror",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "hook",
        type: "address",
      },
    ],
    name: "UninstalledHook",
    type: "event",
  },
  {
    stateMutability: "nonpayable",
    type: "fallback",
  },
  {
    inputs: [],
    name: "addDeposit",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "hook",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "addHook",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "recoveror",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "addRecoveror",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "prevValidator",
        type: "address",
      },
      {
        internalType: "address",
        name: "validator",
        type: "address",
      },
    ],
    name: "disableValidator",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "validator",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "enableValidator",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "entryPoint",
    outputs: [
      {
        internalType: "contract IEntryPoint",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "dest",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
      {
        internalType: "bytes",
        name: "func",
        type: "bytes",
      },
    ],
    name: "execute",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address[]",
        name: "dest",
        type: "address[]",
      },
      {
        internalType: "uint256[]",
        name: "value",
        type: "uint256[]",
      },
      {
        internalType: "bytes[]",
        name: "func",
        type: "bytes[]",
      },
    ],
    name: "executeBatch",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "getDeposit",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getFallbackHandler",
    outputs: [
      {
        internalType: "address",
        name: "_handler",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getNonce",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "start",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "pageSize",
        type: "uint256",
      },
    ],
    name: "getRecoverorsPaginated",
    outputs: [
      {
        internalType: "address[]",
        name: "array",
        type: "address[]",
      },
      {
        internalType: "address",
        name: "next",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "start",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "pageSize",
        type: "uint256",
      },
    ],
    name: "getValidatorsPaginated",
    outputs: [
      {
        internalType: "address[]",
        name: "array",
        type: "address[]",
      },
      {
        internalType: "address",
        name: "next",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "defalutCallbackHandler",
        type: "address",
      },
      {
        internalType: "address[]",
        name: "validators",
        type: "address[]",
      },
      {
        internalType: "bytes[]",
        name: "data",
        type: "bytes[]",
      },
    ],
    name: "initialize",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "recoveror",
        type: "address",
      },
    ],
    name: "isRecoverorEnabled",
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
  {
    inputs: [
      {
        internalType: "address",
        name: "validator",
        type: "address",
      },
    ],
    name: "isValidatorEnabled",
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
  {
    inputs: [
      {
        internalType: "address",
        name: "validator",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "recovery",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "prevBeforeHook",
        type: "address",
      },
      {
        internalType: "address",
        name: "prevAfterHook",
        type: "address",
      },
      {
        internalType: "address",
        name: "hook",
        type: "address",
      },
    ],
    name: "removeHook",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "prevRecoveror",
        type: "address",
      },
      {
        internalType: "address",
        name: "recoveror",
        type: "address",
      },
    ],
    name: "removeRecoveror",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "handler",
        type: "address",
      },
    ],
    name: "setFallbackHandler",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "dest",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "value",
        type: "uint256",
      },
      {
        internalType: "bytes",
        name: "func",
        type: "bytes",
      },
    ],
    name: "sudo",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        components: [
          {
            internalType: "address",
            name: "sender",
            type: "address",
          },
          {
            internalType: "uint256",
            name: "nonce",
            type: "uint256",
          },
          {
            internalType: "bytes",
            name: "initCode",
            type: "bytes",
          },
          {
            internalType: "bytes",
            name: "callData",
            type: "bytes",
          },
          {
            internalType: "uint256",
            name: "callGasLimit",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "verificationGasLimit",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "preVerificationGas",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "maxFeePerGas",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "maxPriorityFeePerGas",
            type: "uint256",
          },
          {
            internalType: "bytes",
            name: "paymasterAndData",
            type: "bytes",
          },
          {
            internalType: "bytes",
            name: "signature",
            type: "bytes",
          },
        ],
        internalType: "struct UserOperation",
        name: "userOp",
        type: "tuple",
      },
      {
        internalType: "bytes32",
        name: "userOpHash",
        type: "bytes32",
      },
      {
        internalType: "uint256",
        name: "missingAccountFunds",
        type: "uint256",
      },
    ],
    name: "validateUserOp",
    outputs: [
      {
        internalType: "uint256",
        name: "validationData",
        type: "uint256",
      },
    ],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address payable",
        name: "withdrawAddress",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "amount",
        type: "uint256",
      },
    ],
    name: "withdrawDepositTo",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x60a06040523480156200001157600080fd5b50604051620023a4380380620023a4833981016040819052620000349162000113565b6001600160a01b0381166080526200004b62000052565b5062000145565b600054610100900460ff1615620000bf5760405162461bcd60e51b815260206004820152602760248201527f496e697469616c697a61626c653a20636f6e747261637420697320696e697469604482015266616c697a696e6760c81b606482015260840160405180910390fd5b60005460ff9081161462000111576000805460ff191660ff9081179091556040519081527f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb38474024989060200160405180910390a15b565b6000602082840312156200012657600080fd5b81516001600160a01b03811681146200013e57600080fd5b9392505050565b60805161220b62000199600039600081816103d801528181610567015281816106fc0152818161079c0152818161091001528181610c0c01528181610d6501528181610e0501526113d2015261220b6000f3fe6080604052600436106101805760003560e01c8063a28b34c4116100d6578063cf777df91161007f578063d561e48911610059578063d561e489146104a6578063f08a0323146104c6578063fa849015146104e657610180565b8063cf777df914610451578063d087d28814610471578063d2b0e7791461048657610180565b8063b61d27f6116100b0578063b61d27f6146103fc578063bb6aa2b41461041c578063c399ec881461043c57610180565b8063a28b34c414610389578063ad05234a146103a9578063b0d691fe146103c957610180565b80635a4389701161013857806375f251671161011257806375f25167146102f1578063856dfd99146103215780639229e1201461036957610180565b80635a438970146102835780635faac46b146102a35780636dd3bf74146102d157610180565b806347e1da2a1161016957806347e1da2a1461023b5780634a58db191461025b5780634d44560d1461026357610180565b80633a871cdd146101e65780633d6767f814610219575b34801561018c57600080fd5b507f6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d48054806101b757005b36600080373360601b365260008060143601600080855af190503d6000803e806101e0573d6000fd5b503d6000f35b3480156101f257600080fd5b50610206610201366004611b83565b610506565b6040519081526020015b60405180910390f35b34801561022557600080fd5b50610239610234366004611c2e565b61052c565b005b34801561024757600080fd5b50610239610256366004611cc8565b61055c565b6102396106fa565b34801561026f57600080fd5b5061023961027e366004611d62565b61077a565b34801561028f57600080fd5b5061023961029e366004611c2e565b61081b565b3480156102af57600080fd5b506102c36102be366004611d62565b6108e9565b604051610210929190611d8e565b3480156102dd57600080fd5b506102396102ec366004611deb565b610905565b3480156102fd57600080fd5b5061031161030c366004611e47565b610995565b6040519015158152602001610210565b34801561032d57600080fd5b507f6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d4545b6040516001600160a01b039091168152602001610210565b34801561037557600080fd5b50610239610384366004611e64565b6109a8565b34801561039557600080fd5b506102396103a4366004611e9d565b610a15565b3480156103b557600080fd5b506102c36103c4366004611d62565b610bec565b3480156103d557600080fd5b507f0000000000000000000000000000000000000000000000000000000000000000610351565b34801561040857600080fd5b50610239610417366004611deb565b610c01565b34801561042857600080fd5b50610239610437366004611c2e565b610c8b565b34801561044857600080fd5b50610206610d45565b34801561045d57600080fd5b5061031161046c366004611e47565b610dd1565b34801561047d57600080fd5b50610206610dde565b34801561049257600080fd5b506102396104a1366004611e64565b610e34565b3480156104b257600080fd5b506102396104c1366004611ee8565b610e99565b3480156104d257600080fd5b506102396104e1366004611e47565b6110cb565b3480156104f257600080fd5b50610239610501366004611c2e565b61115a565b60006105106113c7565b61051a8484611441565b905061052582611507565b9392505050565b33301461054c5760405163d97d09c160e01b815260040160405180910390fd5b610557838383611554565b505050565b336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146105a55760405163cb10477360e01b815260040160405180910390fd5b84811415806105be575082158015906105be5750828114155b156105dc5760405163150072e360e11b815260040160405180910390fd5b60008390036106885760005b858110156106825761067a87878381811061060557610605611f6b565b905060200201602081019061061a9190611e47565b600085858581811061062e5761062e611f6b565b90506020028101906106409190611f81565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506115f992505050565b6001016105e8565b506106f2565b60005b858110156106f0576106e88787838181106106a8576106a8611f6b565b90506020020160208101906106bd9190611e47565b8686848181106106cf576106cf611f6b565b9050602002013585858581811061062e5761062e611f6b565b60010161068b565b505b505050505050565b7f000000000000000000000000000000000000000000000000000000000000000060405163b760faf960e01b81523060048201526001600160a01b03919091169063b760faf99034906024016000604051808303818588803b15801561075f57600080fd5b505af1158015610773573d6000803e3d6000fd5b5050505050565b33301461079a5760405163d97d09c160e01b815260040160405180910390fd5b7f000000000000000000000000000000000000000000000000000000000000000060405163040b850f60e31b81526001600160a01b03848116600483015260248201849052919091169063205c287890604401600060405180830381600087803b15801561080757600080fd5b505af11580156106f2573d6000803e3d6000fd5b33301461083b5760405163d97d09c160e01b815260040160405180910390fd5b610846600484611799565b604051633cbcc2b960e21b81526001600160a01b0384169063f2f30ae4906108749085908590600401611fc8565b600060405180830381600087803b15801561088e57600080fd5b505af11580156108a2573d6000803e3d6000fd5b50506040516001600160a01b03861681527fcc87bd27eafb647c2f20f074fcdd0fe8d9c2171b9876dacd94c4a62149d4fe03925060200190505b60405180910390a1505050565b606060006108f960038585611875565b915091505b9250929050565b336001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161461094e5760405163cb10477360e01b815260040160405180910390fd5b61098f848484848080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061196f92505050565b50505050565b60006109a26003836119df565b92915050565b3330146109c85760405163d97d09c160e01b815260040160405180910390fd5b6109d460038383611a19565b6040516001600160a01b03821681527fae2356b2cb822c142448e45b195255df334895b014113d50bb822c311cddc855906020015b60405180910390a15050565b333014610a355760405163d97d09c160e01b815260040160405180910390fd5b806000816001600160a01b031663e445e7dd6040518163ffffffff1660e01b8152600401602060405180830381865afa158015610a76573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610a9a919061200d565b6002811115610aab57610aab611ff7565b03610ac157610abc60018584611a19565b610b5f565b6001816001600160a01b031663e445e7dd6040518163ffffffff1660e01b8152600401602060405180830381865afa158015610b01573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b25919061200d565b6002811115610b3657610b36611ff7565b03610b4757610abc60028484611a19565b610b5360018584611a19565b610b5f60028484611a19565b806001600160a01b0316630d638f306040518163ffffffff1660e01b8152600401600060405180830381600087803b158015610b9a57600080fd5b505af1158015610bae573d6000803e3d6000fd5b50506040516001600160a01b03851692507fa20b2dba0769450542a688d94941808255eb735da2fa53df12ff98fc529ffd4e9150600090a250505050565b606060006108f960048585611875565b905090565b336001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614610c4a5760405163cb10477360e01b815260040160405180910390fd5b61098f848484848080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506115f992505050565b610c9433610dd1565b610cb85760405163a841d6f560e01b81523360048201526024015b60405180910390fd5b610cc183610995565b610ce95760405163304106bf60e11b81526001600160a01b0384166004820152602401610caf565b60405163064acaab60e11b81526001600160a01b03841690630c95955690610d179085908590600401611fc8565b600060405180830381600087803b158015610d3157600080fd5b505af11580156106f0573d6000803e3d6000fd5b6040516370a0823160e01b81523060048201526000906001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016906370a08231906024015b602060405180830381865afa158015610dad573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610bfc919061202e565b60006109a26004836119df565b604051631aab3f0d60e11b8152306004820152600060248201819052906001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016906335567e1a90604401610d90565b333014610e545760405163d97d09c160e01b815260040160405180910390fd5b610e6060048383611a19565b6040516001600160a01b03821681527f779fb1c42fad72db3b3d13498dce770027f44544e8a1a5a9e06e530db8cd689290602001610a09565b600054610100900460ff1615808015610eb95750600054600160ff909116105b80610ed35750303b158015610ed3575060005460ff166001145b610f455760405162461bcd60e51b815260206004820152602e60248201527f496e697469616c697a61626c653a20636f6e747261637420697320616c72656160448201527f647920696e697469616c697a65640000000000000000000000000000000000006064820152608401610caf565b6000805460ff191660011790558015610f68576000805461ff0019166101001790555b838214610f885760405163150072e360e11b815260040160405180910390fd5b610f9186611b38565b610fd46001600081905260036020527fa15bc60c955c405d20d9149c709e2460f1c2d9a497496a7f46004d1772c3054c80546001600160a01b0319169091179055565b6110176001600081905260046020527fabd6e7cb50984ff9c2f3e18a2660c3353dadf4e3291deeb275dae2cd1e44fe0580546001600160a01b0319169091179055565b60005b8481101561107d5761107586868381811061103757611037611f6b565b905060200201602081019061104c9190611e47565b85858481811061105e5761105e611f6b565b90506020028101906110709190611f81565b611554565b60010161101a565b5080156106f2576000805461ff0019169055604051600181527f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb38474024989060200160405180910390a1505050505050565b3330146110eb5760405163d97d09c160e01b815260040160405180910390fd5b7f6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d45461111682611b38565b816001600160a01b0316816001600160a01b03167f06be9a1bea257286cf2afa8205ed494ca9d6a4b41aa58d04238deebada20fb0c60405160405180910390a35050565b33301461117a5760405163d97d09c160e01b815260040160405180910390fd5b6040516301ffc9a760e01b81526329c791d960e01b600482015283906001600160a01b038216906301ffc9a790602401602060405180830381865afa1580156111c7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906111eb9190612047565b61120857604051639c9d882360e01b815260040160405180910390fd5b6000816001600160a01b031663e445e7dd6040518163ffffffff1660e01b8152600401602060405180830381865afa158015611248573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061126c919061200d565b600281111561127d5761127d611ff7565b036112925761128d600185611799565b61132d565b6001816001600160a01b031663e445e7dd6040518163ffffffff1660e01b8152600401602060405180830381865afa1580156112d2573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906112f6919061200d565b600281111561130757611307611ff7565b036113175761128d600285611799565b611322600185611799565b61132d600285611799565b6040516313861fb560e01b81526001600160a01b038216906313861fb59061135b9086908690600401611fc8565b600060405180830381600087803b15801561137557600080fd5b505af1158015611389573d6000803e3d6000fd5b50506040516001600160a01b03871692507fe9fdf38cc72369bf1f90f6adc9835796c285cba93070412e0e48413e63c5b9089150600090a250505050565b336001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161461143f5760405162461bcd60e51b815260206004820152601c60248201527f6163636f756e743a206e6f742066726f6d20456e747279506f696e74000000006044820152606401610caf565b565b60008080611453610140860186611f81565b810190611460919061207f565b9150915061146d82610995565b61147c576001925050506109a2565b6001600160a01b03821663971604c66114986020880188611e47565b86846040518463ffffffff1660e01b81526004016114b893929190612193565b6020604051808303816000875af11580156114d7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906114fb919061202e565b95945050505050565b50565b801561150457604051600090339060001990849084818181858888f193505050503d8060008114610773576040519150601f19603f3d011682016040523d82523d6000602084013e610773565b61155f600384611799565b60405163064acaab60e11b81526001600160a01b03841690630c9595569061158d9085908590600401611fc8565b600060405180830381600087803b1580156115a757600080fd5b505af11580156115bb573d6000803e3d6000fd5b50506040516001600160a01b03861681527f702ed4645b59645b8a8b7dd88e069cb684a1170094eca847038827e03c1107a4925060200190506108dc565b600160008190526020527fcc69885fda6bcc1a4ace058b4a62bf5e179ea78fd58a1ccd71c22cc9b688792f546001600160a01b03165b60016001600160a01b03821611156116c357604051632b668a3760e21b81526001600160a01b0382169063ad9a28dc9061167190879087908790600401612193565b600060405180830381600087803b15801561168b57600080fd5b505af115801561169f573d6000803e3d6000fd5b505050506001600160a01b039081166000908152600160205260409020541661162f565b6116ce84848461196f565b50600160005260026020527fe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0546001600160a01b03165b60016001600160a01b038216111561098f57604051632b668a3760e21b81526001600160a01b0382169063ad9a28dc9061174790879087908790600401612193565b600060405180830381600087803b15801561176157600080fd5b505af1158015611775573d6000803e3d6000fd5b505050506001600160a01b0390811660009081526002602052604090205416611705565b6001600160a01b038116158015906117bb57506001600160a01b038116600114155b6118075760405162461bcd60e51b815260206004820152601e60248201527f6974656d2063616e2774206265207a65726f206f722073656e74696e656c00006044820152606401610caf565b6001600160a01b03818116600090815260208490526040902054161561182b575050565b60016000818152602093909352604080842080546001600160a01b039485168087529286208054959091166001600160a01b03199586161790559190935280549091169091179055565b606060008267ffffffffffffffff81111561189257611892612069565b6040519080825280602002602001820160405280156118bb578160200160208202803683370190505b506001600160a01b0380861660009081526020889052604081205492945091165b6001600160a01b038116158015906118fe57506001600160a01b038116600114155b801561190957508482105b15611960578084838151811061192157611921611f6b565b6001600160a01b039283166020918202929092018101919091529181166000908152918890526040909120541681611958816121bb565b9250506118dc565b90835291959194509092505050565b600080846001600160a01b0316848460405161198b91906121e2565b60006040518083038185875af1925050503d80600081146119c8576040519150601f19603f3d011682016040523d82523d6000602084013e6119cd565b606091505b50915091508161077357805160208201fd5b600060016001600160a01b038316148015906105255750506001600160a01b03908116600090815260209290925260409091205416151590565b6001600160a01b03811615801590611a3b57506001600160a01b038116600114155b611a875760405162461bcd60e51b815260206004820152601e60248201527f6974656d2063616e2774206265207a65726f206f722073656e74696e656c00006044820152606401610caf565b6001600160a01b03828116600090815260208590526040902054811690821614611af35760405162461bcd60e51b815260206004820152601960248201527f6974656d20616e64207072656974656d206d69736d61746368000000000000006044820152606401610caf565b6001600160a01b0390811660008181526020949094526040808520805494841686529085208054949093166001600160a01b0319948516179092559092528154169055565b6001600160a01b038116611b5f576040516303988b8160e61b815260040160405180910390fd5b7f6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d455565b600080600060608486031215611b9857600080fd5b833567ffffffffffffffff811115611baf57600080fd5b84016101608187031215611bc257600080fd5b95602085013595506040909401359392505050565b6001600160a01b038116811461150457600080fd5b60008083601f840112611bfe57600080fd5b50813567ffffffffffffffff811115611c1657600080fd5b6020830191508360208285010111156108fe57600080fd5b600080600060408486031215611c4357600080fd5b8335611c4e81611bd7565b9250602084013567ffffffffffffffff811115611c6a57600080fd5b611c7686828701611bec565b9497909650939450505050565b60008083601f840112611c9557600080fd5b50813567ffffffffffffffff811115611cad57600080fd5b6020830191508360208260051b85010111156108fe57600080fd5b60008060008060008060608789031215611ce157600080fd5b863567ffffffffffffffff80821115611cf957600080fd5b611d058a838b01611c83565b90985096506020890135915080821115611d1e57600080fd5b611d2a8a838b01611c83565b90965094506040890135915080821115611d4357600080fd5b50611d5089828a01611c83565b979a9699509497509295939492505050565b60008060408385031215611d7557600080fd5b8235611d8081611bd7565b946020939093013593505050565b604080825283519082018190526000906020906060840190828701845b82811015611dd05781516001600160a01b031684529284019290840190600101611dab565b5050506001600160a01b039490941692019190915250919050565b60008060008060608587031215611e0157600080fd5b8435611e0c81611bd7565b935060208501359250604085013567ffffffffffffffff811115611e2f57600080fd5b611e3b87828801611bec565b95989497509550505050565b600060208284031215611e5957600080fd5b813561052581611bd7565b60008060408385031215611e7757600080fd5b8235611e8281611bd7565b91506020830135611e9281611bd7565b809150509250929050565b600080600060608486031215611eb257600080fd5b8335611ebd81611bd7565b92506020840135611ecd81611bd7565b91506040840135611edd81611bd7565b809150509250925092565b600080600080600060608688031215611f0057600080fd5b8535611f0b81611bd7565b9450602086013567ffffffffffffffff80821115611f2857600080fd5b611f3489838a01611c83565b90965094506040880135915080821115611f4d57600080fd5b50611f5a88828901611c83565b969995985093965092949392505050565b634e487b7160e01b600052603260045260246000fd5b6000808335601e19843603018112611f9857600080fd5b83018035915067ffffffffffffffff821115611fb357600080fd5b6020019150368190038213156108fe57600080fd5b60208152816020820152818360408301376000818301604090810191909152601f909201601f19160101919050565b634e487b7160e01b600052602160045260246000fd5b60006020828403121561201f57600080fd5b81516003811061052557600080fd5b60006020828403121561204057600080fd5b5051919050565b60006020828403121561205957600080fd5b8151801515811461052557600080fd5b634e487b7160e01b600052604160045260246000fd5b6000806040838503121561209257600080fd5b823561209d81611bd7565b9150602083013567ffffffffffffffff808211156120ba57600080fd5b818501915085601f8301126120ce57600080fd5b8135818111156120e0576120e0612069565b604051601f8201601f19908116603f0116810190838211818310171561210857612108612069565b8160405282815288602084870101111561212157600080fd5b8260208601602083013760006020848301015280955050505050509250929050565b60005b8381101561215e578181015183820152602001612146565b50506000910152565b6000815180845261217f816020860160208601612143565b601f01601f19169290920160200192915050565b6001600160a01b03841681528260208201526060604082015260006114fb6060830184612167565b6000600182016121db57634e487b7160e01b600052601160045260246000fd5b5060010190565b600082516121f4818460208701612143565b919091019291505056fea164736f6c6343000813000a";

type SmartAccountConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: SmartAccountConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class SmartAccount__factory extends ContractFactory {
  constructor(...args: SmartAccountConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override deploy(
    _EntryPoint: string,
    overrides?: Overrides & { from?: string }
  ): Promise<SmartAccount> {
    return super.deploy(_EntryPoint, overrides || {}) as Promise<SmartAccount>;
  }
  override getDeployTransaction(
    _EntryPoint: string,
    overrides?: Overrides & { from?: string }
  ): TransactionRequest {
    return super.getDeployTransaction(_EntryPoint, overrides || {});
  }
  override attach(address: string): SmartAccount {
    return super.attach(address) as SmartAccount;
  }
  override connect(signer: Signer): SmartAccount__factory {
    return super.connect(signer) as SmartAccount__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): SmartAccountInterface {
    return new utils.Interface(_abi) as SmartAccountInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): SmartAccount {
    return new Contract(address, _abi, signerOrProvider) as SmartAccount;
  }
}
