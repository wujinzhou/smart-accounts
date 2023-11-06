/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type {
  MockNFT,
  MockNFTInterface,
} from "../../../contracts/mock/MockNFT";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "approved",
        type: "address",
      },
      {
        indexed: true,
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "Approval",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "operator",
        type: "address",
      },
      {
        indexed: false,
        internalType: "bool",
        name: "approved",
        type: "bool",
      },
    ],
    name: "ApprovalForAll",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        indexed: true,
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "Transfer",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "approve",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "owner",
        type: "address",
      },
    ],
    name: "balanceOf",
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
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "getApproved",
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
        internalType: "address",
        name: "owner",
        type: "address",
      },
      {
        internalType: "address",
        name: "operator",
        type: "address",
      },
    ],
    name: "isApprovedForAll",
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
    inputs: [],
    name: "mint",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "name",
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
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "ownerOf",
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
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "safeTransferFrom",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "from",
        type: "address",
      },
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
    ],
    name: "safeTransferFrom",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "operator",
        type: "address",
      },
      {
        internalType: "bool",
        name: "approved",
        type: "bool",
      },
    ],
    name: "setApprovalForAll",
    outputs: [],
    stateMutability: "nonpayable",
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
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "symbol",
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
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "tokenURI",
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
    name: "totalSupply",
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
        name: "from",
        type: "address",
      },
      {
        internalType: "address",
        name: "to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "tokenId",
        type: "uint256",
      },
    ],
    name: "transferFrom",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
] as const;

const _bytecode =
  "0x6080346200030b576001600160401b039060409080820183811182821017620002f55782526007815260209266135bd8dad3919560ca1b84830152825183810181811083821117620002f557845260048152631353919560e21b85820152825190828211620002f55760008054926001958685811c95168015620002ea575b89861014620002d6578190601f9586811162000283575b5089908683116001146200021f57849262000213575b5050600019600383901b1c191690861b1781555b8151938411620001ff5784548581811c91168015620001f4575b88821014620001e05783811162000198575b5086928411600114620001325783949596509262000126575b5050600019600383901b1c191690821b1790555b5161101a9081620003118239f35b01519050388062000104565b9190601f1984169685845280842093905b88821062000180575050838596971062000166575b505050811b01905562000118565b015160001960f88460031b161c1916905538808062000158565b80878596829496860151815501950193019062000143565b8582528782208480870160051c8201928a8810620001d6575b0160051c019086905b828110620001ca575050620000eb565b838155018690620001ba565b92508192620001b1565b634e487b7160e01b82526022600452602482fd5b90607f1690620000d9565b634e487b7160e01b81526041600452602490fd5b015190503880620000ab565b8480528a85208994509190601f198416865b8d8282106200026c575050841162000252575b505050811b018155620000bf565b015160001960f88460031b161c1916905538808062000244565b8385015186558c9790950194938401930162000231565b9091508380528984208680850160051c8201928c8610620002cc575b918a91869594930160051c01915b828110620002bd57505062000095565b8681558594508a9101620002ad565b925081926200029f565b634e487b7160e01b83526022600452602483fd5b94607f16946200007e565b634e487b7160e01b600052604160045260246000fd5b600080fdfe608060408181526004918236101561001657600080fd5b600092833560e01c91826301ffc9a7146108ea5750816306fdde031461081f578163081812fc146107f7578163095ea7b31461067e5781631249c58b1461054d57816318160ddd1461052e57816323b872dd1461050457816342842e0e146104db5781636352211e146104ab57816370a082311461040157816395d89b41146102e8578163a22cb46514610218578163b88d4fde1461018a578163c87b56dd1461011a575063e985e9c5146100ca57600080fd5b3461011657806003193601126101165760ff816020936100e8610995565b6100f06109b0565b6001600160a01b0391821683526005875283832091168252855220549151911615158152f35b5080fd5b83833461011657602036600319011261011657610159610154610186943560005260026020526001600160a01b0360406000205416151590565b610a6b565b818151610165816109fb565b52805191610172836109fb565b825251918291602083526020830190610955565b0390f35b91905034610214576080366003190112610214576101a6610995565b6101ae6109b0565b846064359467ffffffffffffffff8611610116573660238701121561011657850135946101e66101dd87610a4f565b95519586610a2d565b8585523660248783010111610116578561021196602460209301838801378501015260443591610b8b565b80f35b8280fd5b91905034610214578060031936011261021457610233610995565b90602435918215158093036102e4576001600160a01b0316928333146102a25750338452600560205280842083855260205280842060ff1981541660ff8416179055519081527f17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c3160203392a380f35b6020606492519162461bcd60e51b8352820152601960248201527f4552433732313a20617070726f766520746f2063616c6c6572000000000000006044820152fd5b8480fd5b8284346103fe57806003193601126103fe578151918160019283549384811c918186169586156103f4575b60209687851081146103e1578899509688969785829a5291826000146103ba57505060011461035f575b5050506101869291610350910385610a2d565b51928284938452830190610955565b91908693508083527fb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf65b8284106103a2575050508201018161035061018661033d565b8054848a018601528895508794909301928101610389565b60ff19168782015293151560051b860190930193508492506103509150610186905061033d565b634e487b7160e01b835260228a52602483fd5b92607f1692610313565b80fd5b83915034610116576020366003190112610116576001600160a01b03610425610995565b169081156104425760208480858581526003845220549051908152f35b608490602085519162461bcd60e51b8352820152602960248201527f4552433732313a2061646472657373207a65726f206973206e6f74206120766160448201527f6c6964206f776e657200000000000000000000000000000000000000000000006064820152fd5b8284346103fe5760203660031901126103fe57506001600160a01b036104d360209335610ab7565b915191168152f35b50503461011657610211906104ef366109c6565b919251926104fc846109fb565b858452610b8b565b83346103fe57610211610516366109c6565b916105296105248433610c21565b610b19565b610d01565b5050346101165781600319360112610116576020906006549051908152f35b91905034610214578260031936011261021457600654600019811461066b576001019182600655331561062957506105a461059e8360005260026020526001600160a01b0360406000205416151590565b15610fc1565b6105c761059e8360005260026020526001600160a01b0360406000205416151590565b338352600360205280832060018154019055818352600260205282203373ffffffffffffffffffffffffffffffffffffffff1982541617905533827fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef8180a480f35b6020606492519162461bcd60e51b8352820152602060248201527f4552433732313a206d696e7420746f20746865207a65726f20616464726573736044820152fd5b634e487b7160e01b845260118352602484fd5b905034610214578160031936011261021457610698610995565b90602435926001600160a01b039182806106b187610ab7565b169416938085146107aa5780331490811561078b575b50156107235784865260205284208273ffffffffffffffffffffffffffffffffffffffff198254161790556106fb83610ab7565b167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9258480a480f35b6020608492519162461bcd60e51b8352820152603d60248201527f4552433732313a20617070726f76652063616c6c6572206973206e6f7420746f60448201527f6b656e206f776e6572206f7220617070726f76656420666f7220616c6c0000006064820152fd5b90508652600560205281862033875260205260ff8287205416386106c7565b506020608492519162461bcd60e51b8352820152602160248201527f4552433732313a20617070726f76616c20746f2063757272656e74206f776e656044820152603960f91b6064820152fd5b8284346103fe5760203660031901126103fe57506001600160a01b036104d360209335610adc565b8284346103fe57806003193601126103fe5781519181825492600184811c918186169586156108e0575b60209687851081146103e1578899509688969785829a5291826000146103ba575050600114610885575050506101869291610350910385610a2d565b91908693508280527f290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5635b8284106108c8575050508201018161035061018661033d565b8054848a0186015288955087949093019281016108af565b92607f1692610849565b849134610214576020366003190112610214573563ffffffff60e01b811680910361021457602092506380ac58cd60e01b8114908115610944575b8115610933575b5015158152f35b6301ffc9a760e01b1490508361092c565b635b5e139f60e01b81149150610925565b919082519283825260005b848110610981575050826000602080949584010152601f8019910116010190565b602081830181015184830182015201610960565b600435906001600160a01b03821682036109ab57565b600080fd5b602435906001600160a01b03821682036109ab57565b60609060031901126109ab576001600160a01b039060043582811681036109ab579160243590811681036109ab579060443590565b6020810190811067ffffffffffffffff821117610a1757604052565b634e487b7160e01b600052604160045260246000fd5b90601f8019910116810190811067ffffffffffffffff821117610a1757604052565b67ffffffffffffffff8111610a1757601f01601f191660200190565b15610a7257565b60405162461bcd60e51b815260206004820152601860248201527f4552433732313a20696e76616c696420746f6b656e20494400000000000000006044820152606490fd5b60005260026020526001600160a01b0360406000205416610ad9811515610a6b565b90565b610aff6101548260005260026020526001600160a01b0360406000205416151590565b60005260046020526001600160a01b036040600020541690565b15610b2057565b60405162461bcd60e51b815260206004820152602d60248201527f4552433732313a2063616c6c6572206973206e6f7420746f6b656e206f776e6560448201527f72206f7220617070726f766564000000000000000000000000000000000000006064820152608490fd5b90610baf939291610b9f6105248433610c21565b610baa838383610d01565b610e1d565b15610bb657565b60405162461bcd60e51b815260206004820152603260248201527f4552433732313a207472616e7366657220746f206e6f6e20455243373231526560448201527f63656976657220696d706c656d656e74657200000000000000000000000000006064820152608490fd5b906001600160a01b038080610c3584610ab7565b16931691838314938415610c68575b508315610c52575b50505090565b610c5e91929350610adc565b1614388080610c4c565b909350600052600560205260406000208260005260205260ff604060002054169238610c44565b15610c9657565b60405162461bcd60e51b815260206004820152602560248201527f4552433732313a207472616e736665722066726f6d20696e636f72726563742060448201527f6f776e65720000000000000000000000000000000000000000000000000000006064820152608490fd5b90610d2991610d0f84610ab7565b916001600160a01b03938493848094169485911614610c8f565b16918215610dcc5781610d4691610d3f86610ab7565b1614610c8f565b7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef600084815260046020526040812073ffffffffffffffffffffffffffffffffffffffff199081815416905583825260036020526040822060001981540190558482526040822060018154019055858252600260205284604083209182541617905580a4565b60405162461bcd60e51b8152602060048201526024808201527f4552433732313a207472616e7366657220746f20746865207a65726f206164646044820152637265737360e01b6064820152608490fd5b9293600093909291803b15610fb657948491610e789660405180948193630a85bd0160e11b978884523360048501526001600160a01b0380921660248501526044840152608060648401528260209b8c976084830190610955565b0393165af1849181610f5e575b50610f35575050503d600014610f2d573d610e9f81610a4f565b90610ead6040519283610a2d565b81528091833d92013e5b80519182610f2a5760405162461bcd60e51b815260206004820152603260248201527f4552433732313a207472616e7366657220746f206e6f6e20455243373231526560448201527f63656976657220696d706c656d656e74657200000000000000000000000000006064820152608490fd5b01fd5b506060610eb7565b7fffffffff00000000000000000000000000000000000000000000000000000000161492509050565b9091508581813d8311610faf575b610f768183610a2d565b810103126102e457517fffffffff00000000000000000000000000000000000000000000000000000000811681036102e4579038610e85565b503d610f6c565b505050915050600190565b15610fc857565b60405162461bcd60e51b815260206004820152601c60248201527f4552433732313a20746f6b656e20616c7265616479206d696e746564000000006044820152606490fdfea164736f6c6343000813000a";

type MockNFTConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: MockNFTConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class MockNFT__factory extends ContractFactory {
  constructor(...args: MockNFTConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override deploy(overrides?: Overrides & { from?: string }): Promise<MockNFT> {
    return super.deploy(overrides || {}) as Promise<MockNFT>;
  }
  override getDeployTransaction(
    overrides?: Overrides & { from?: string }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  override attach(address: string): MockNFT {
    return super.attach(address) as MockNFT;
  }
  override connect(signer: Signer): MockNFT__factory {
    return super.connect(signer) as MockNFT__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): MockNFTInterface {
    return new utils.Interface(_abi) as MockNFTInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): MockNFT {
    return new Contract(address, _abi, signerOrProvider) as MockNFT;
  }
}
