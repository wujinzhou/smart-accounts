/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type {
  ECDSAValidator,
  ECDSAValidatorInterface,
} from "../../../contracts/validators/ECDSAValidator";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "account",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "oldOwner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "OwnerChanged",
    type: "event",
  },
  {
    inputs: [],
    name: "NAME",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "VERSION",
    outputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "enable",
    outputs: [],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    name: "owner",
    outputs: [
      {
        internalType: "address",
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
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "recover",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "payable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "bytes4",
        name: "interfaceId",
        type: "bytes4",
      },
    ],
    name: "supportsInterface",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "caller",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "",
        type: "bytes",
      },
    ],
    name: "validCaller",
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
        name: "account",
        type: "address",
      },
      {
        internalType: "bytes32",
        name: "userOpHash",
        type: "bytes32",
      },
      {
        internalType: "bytes",
        name: "signature",
        type: "bytes",
      },
    ],
    name: "validateSignature",
    outputs: [
      {
        internalType: "uint256",
        name: "validationData",
        type: "uint256",
      },
    ],
    stateMutability: "payable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x60808060405234610016576106fb908161001c8239f35b600080fdfe608060408181526004918236101561001657600080fd5b600092833560e01c91826301ffc9a71461032e575081630c9595561461028d578163666e1b3914610254578163971604c6146102055781639ea9bd591461019f578163a3f4df7e1461014c578163a4a1edb1146100d6575063ffa1ad741461007d57600080fd5b346100d257816003193601126100d2576100ce906100996103ad565b90600582527f302e302e31000000000000000000000000000000000000000000000000000000602083015251918291826103e3565b0390f35b5080fd5b90508260203660031901126101495781359067ffffffffffffffff8211610149575060649261010a60209236908501610364565b50505162461bcd60e51b815291820152600f60248201527f6e6f7420696d706c656d656e74656400000000000000000000000000000000006044820152fd5b80fd5b5050346100d257816003193601126100d2576100ce9061016a6103ad565b90600f82527f45434453412056616c696461746f720000000000000000000000000000000000602083015251918291826103e3565b919050346102015780600319360112610201576101ba610397565b9160243567ffffffffffffffff81116101fd57936101de8392602096369101610364565b50503381528085526001600160a01b0391829120541691519216148152f35b8480fd5b8280fd5b905060603660031901126102015761021b610397565b926044359067ffffffffffffffff821161014957509261024361024d92602095369101610364565b916024359061042c565b9051908152f35b5050346100d25760203660031901126100d257602091816001600160a01b03918261027d610397565b1681528085522054169051908152f35b905060203660031901126102015780359067ffffffffffffffff821161032a576102b991369101610364565b601411610201576001600160a01b03903560601c91338452836020528320805490837fffffffffffffffffffffffff0000000000000000000000000000000000000000831617905516337f381c0d11398486654573703c51ee8210ce9461764d133f9f0e53b6a5397053318480a480f35b8380fd5b849134610201576020366003190112610201573563ffffffff60e01b811680910361020157631431782f60e31b14815260209150f35b9181601f840112156103925782359167ffffffffffffffff8311610392576020838186019501011161039257565b600080fd5b600435906001600160a01b038216820361039257565b604051906040820182811067ffffffffffffffff8211176103cd57604052565b634e487b7160e01b600052604160045260246000fd5b6020808252825181830181905290939260005b82811061041857505060409293506000838284010152601f8019910116010190565b8181018601518482016040015285016103f6565b9290916001600160a01b0391826000951685528460205282604086205416937f19457468657265756d205369676e6564204d6573736167653a0a3332000000008652601c52603c85209067ffffffffffffffff928382116104ff5760405193601f8301601f19908116603f01168501908111858210176104eb5760405281845236828201116104e757918660208386946104d096836104d89901378401015261062d565b919091610513565b16036104e15790565b50600190565b8680fd5b634e487b7160e01b88526041600452602488fd5b634e487b7160e01b87526041600452602487fd5b600581101561061757806105245750565b600181036105715760405162461bcd60e51b815260206004820152601860248201527f45434453413a20696e76616c6964207369676e617475726500000000000000006044820152606490fd5b600281036105be5760405162461bcd60e51b815260206004820152601f60248201527f45434453413a20696e76616c6964207369676e6174757265206c656e677468006044820152606490fd5b6003146105c757565b60405162461bcd60e51b815260206004820152602260248201527f45434453413a20696e76616c6964207369676e6174757265202773272076616c604482015261756560f01b6064820152608490fd5b634e487b7160e01b600052602160045260246000fd5b90604181511460001461065b57610657916020820151906060604084015193015160001a90610665565b9091565b5050600090600290565b9291907f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a083116106e25791608094939160ff602094604051948552168484015260408301526060820152600093849182805260015afa156106d55781516001600160a01b038116156104e1579190565b50604051903d90823e3d90fd5b5050505060009060039056fea164736f6c6343000813000a";

type ECDSAValidatorConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: ECDSAValidatorConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class ECDSAValidator__factory extends ContractFactory {
  constructor(...args: ECDSAValidatorConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override deploy(
    overrides?: Overrides & { from?: string }
  ): Promise<ECDSAValidator> {
    return super.deploy(overrides || {}) as Promise<ECDSAValidator>;
  }
  override getDeployTransaction(
    overrides?: Overrides & { from?: string }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  override attach(address: string): ECDSAValidator {
    return super.attach(address) as ECDSAValidator;
  }
  override connect(signer: Signer): ECDSAValidator__factory {
    return super.connect(signer) as ECDSAValidator__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): ECDSAValidatorInterface {
    return new utils.Interface(_abi) as ECDSAValidatorInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): ECDSAValidator {
    return new Contract(address, _abi, signerOrProvider) as ECDSAValidator;
  }
}
