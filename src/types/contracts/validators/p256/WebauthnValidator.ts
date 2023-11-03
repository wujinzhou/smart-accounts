/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumber,
  BigNumberish,
  BytesLike,
  CallOverrides,
  ContractTransaction,
  Overrides,
  PayableOverrides,
  PopulatedTransaction,
  Signer,
  utils,
} from "ethers";
import type {
  FunctionFragment,
  Result,
  EventFragment,
} from "@ethersproject/abi";
import type { Listener, Provider } from "@ethersproject/providers";
import type {
  TypedEventFilter,
  TypedEvent,
  TypedListener,
  OnEvent,
} from "../../../common";

export interface WebauthnValidatorInterface extends utils.Interface {
  functions: {
    "NAME()": FunctionFragment;
    "VERSION()": FunctionFragment;
    "bindEmail(bytes)": FunctionFragment;
    "emails(address)": FunctionFragment;
    "enable(bytes)": FunctionFragment;
    "fromHex(string)": FunctionFragment;
    "fromHexChar(uint8)": FunctionFragment;
    "impl()": FunctionFragment;
    "publicKeys(address,string)": FunctionFragment;
    "recover(bytes)": FunctionFragment;
    "recoveryEmail(bytes,bytes)": FunctionFragment;
    "recoveryNonce(address)": FunctionFragment;
    "supportsInterface(bytes4)": FunctionFragment;
    "validCaller(address,bytes)": FunctionFragment;
    "validateParams(uint256,address,address,uint256,string)": FunctionFragment;
    "validateSignature(address,bytes32,bytes)": FunctionFragment;
    "verifier()": FunctionFragment;
  };

  getFunction(
    nameOrSignatureOrTopic:
      | "NAME"
      | "VERSION"
      | "bindEmail"
      | "emails"
      | "enable"
      | "fromHex"
      | "fromHexChar"
      | "impl"
      | "publicKeys"
      | "recover"
      | "recoveryEmail"
      | "recoveryNonce"
      | "supportsInterface"
      | "validCaller"
      | "validateParams"
      | "validateSignature"
      | "verifier"
  ): FunctionFragment;

  encodeFunctionData(functionFragment: "NAME", values?: undefined): string;
  encodeFunctionData(functionFragment: "VERSION", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "bindEmail",
    values: [BytesLike]
  ): string;
  encodeFunctionData(functionFragment: "emails", values: [string]): string;
  encodeFunctionData(functionFragment: "enable", values: [BytesLike]): string;
  encodeFunctionData(functionFragment: "fromHex", values: [string]): string;
  encodeFunctionData(
    functionFragment: "fromHexChar",
    values: [BigNumberish]
  ): string;
  encodeFunctionData(functionFragment: "impl", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "publicKeys",
    values: [string, string]
  ): string;
  encodeFunctionData(functionFragment: "recover", values: [BytesLike]): string;
  encodeFunctionData(
    functionFragment: "recoveryEmail",
    values: [BytesLike, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "recoveryNonce",
    values: [string]
  ): string;
  encodeFunctionData(
    functionFragment: "supportsInterface",
    values: [BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "validCaller",
    values: [string, BytesLike]
  ): string;
  encodeFunctionData(
    functionFragment: "validateParams",
    values: [BigNumberish, string, string, BigNumberish, string]
  ): string;
  encodeFunctionData(
    functionFragment: "validateSignature",
    values: [string, BytesLike, BytesLike]
  ): string;
  encodeFunctionData(functionFragment: "verifier", values?: undefined): string;

  decodeFunctionResult(functionFragment: "NAME", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "VERSION", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "bindEmail", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "emails", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "enable", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "fromHex", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "fromHexChar",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "impl", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "publicKeys", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "recover", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "recoveryEmail",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "recoveryNonce",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "supportsInterface",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "validCaller",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "validateParams",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "validateSignature",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "verifier", data: BytesLike): Result;

  events: {
    "EmailChanged(address,string,string)": EventFragment;
    "NonceIncrease(address,uint256)": EventFragment;
    "PkAdded(address,string)": EventFragment;
    "VerifySubject(string)": EventFragment;
  };

  getEvent(nameOrSignatureOrTopic: "EmailChanged"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "NonceIncrease"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "PkAdded"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "VerifySubject"): EventFragment;
}

export interface EmailChangedEventObject {
  account: string;
  oldEmail: string;
  newEmail: string;
}
export type EmailChangedEvent = TypedEvent<
  [string, string, string],
  EmailChangedEventObject
>;

export type EmailChangedEventFilter = TypedEventFilter<EmailChangedEvent>;

export interface NonceIncreaseEventObject {
  account: string;
  nonce: BigNumber;
}
export type NonceIncreaseEvent = TypedEvent<
  [string, BigNumber],
  NonceIncreaseEventObject
>;

export type NonceIncreaseEventFilter = TypedEventFilter<NonceIncreaseEvent>;

export interface PkAddedEventObject {
  account: string;
  keyId: string;
}
export type PkAddedEvent = TypedEvent<[string, string], PkAddedEventObject>;

export type PkAddedEventFilter = TypedEventFilter<PkAddedEvent>;

export interface VerifySubjectEventObject {
  subject: string;
}
export type VerifySubjectEvent = TypedEvent<[string], VerifySubjectEventObject>;

export type VerifySubjectEventFilter = TypedEventFilter<VerifySubjectEvent>;

export interface WebauthnValidator extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  interface: WebauthnValidatorInterface;

  queryFilter<TEvent extends TypedEvent>(
    event: TypedEventFilter<TEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TEvent>>;

  listeners<TEvent extends TypedEvent>(
    eventFilter?: TypedEventFilter<TEvent>
  ): Array<TypedListener<TEvent>>;
  listeners(eventName?: string): Array<Listener>;
  removeAllListeners<TEvent extends TypedEvent>(
    eventFilter: TypedEventFilter<TEvent>
  ): this;
  removeAllListeners(eventName?: string): this;
  off: OnEvent<this>;
  on: OnEvent<this>;
  once: OnEvent<this>;
  removeListener: OnEvent<this>;

  functions: {
    NAME(overrides?: CallOverrides): Promise<[string]>;

    VERSION(overrides?: CallOverrides): Promise<[string]>;

    bindEmail(
      data: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<ContractTransaction>;

    emails(arg0: string, overrides?: CallOverrides): Promise<[string]>;

    enable(
      data: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<ContractTransaction>;

    fromHex(s: string, overrides?: CallOverrides): Promise<[string]>;

    fromHexChar(c: BigNumberish, overrides?: CallOverrides): Promise<[number]>;

    impl(overrides?: CallOverrides): Promise<[string]>;

    publicKeys(
      arg0: string,
      arg1: string,
      overrides?: CallOverrides
    ): Promise<[string]>;

    recover(
      data: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<ContractTransaction>;

    recoveryEmail(
      signature: BytesLike,
      dkimHeaders: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<ContractTransaction>;

    recoveryNonce(
      arg0: string,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    supportsInterface(
      interfaceId: BytesLike,
      overrides?: CallOverrides
    ): Promise<[boolean]>;

    validCaller(
      arg0: string,
      arg1: BytesLike,
      overrides?: CallOverrides
    ): Promise<[boolean]>;

    validateParams(
      chainId: BigNumberish,
      validator: string,
      account: string,
      nonce: BigNumberish,
      from: string,
      overrides?: CallOverrides
    ): Promise<[boolean]>;

    validateSignature(
      account: string,
      userOpHash: BytesLike,
      signature: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<ContractTransaction>;

    verifier(overrides?: CallOverrides): Promise<[string]>;
  };

  NAME(overrides?: CallOverrides): Promise<string>;

  VERSION(overrides?: CallOverrides): Promise<string>;

  bindEmail(
    data: BytesLike,
    overrides?: PayableOverrides & { from?: string }
  ): Promise<ContractTransaction>;

  emails(arg0: string, overrides?: CallOverrides): Promise<string>;

  enable(
    data: BytesLike,
    overrides?: PayableOverrides & { from?: string }
  ): Promise<ContractTransaction>;

  fromHex(s: string, overrides?: CallOverrides): Promise<string>;

  fromHexChar(c: BigNumberish, overrides?: CallOverrides): Promise<number>;

  impl(overrides?: CallOverrides): Promise<string>;

  publicKeys(
    arg0: string,
    arg1: string,
    overrides?: CallOverrides
  ): Promise<string>;

  recover(
    data: BytesLike,
    overrides?: PayableOverrides & { from?: string }
  ): Promise<ContractTransaction>;

  recoveryEmail(
    signature: BytesLike,
    dkimHeaders: BytesLike,
    overrides?: Overrides & { from?: string }
  ): Promise<ContractTransaction>;

  recoveryNonce(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

  supportsInterface(
    interfaceId: BytesLike,
    overrides?: CallOverrides
  ): Promise<boolean>;

  validCaller(
    arg0: string,
    arg1: BytesLike,
    overrides?: CallOverrides
  ): Promise<boolean>;

  validateParams(
    chainId: BigNumberish,
    validator: string,
    account: string,
    nonce: BigNumberish,
    from: string,
    overrides?: CallOverrides
  ): Promise<boolean>;

  validateSignature(
    account: string,
    userOpHash: BytesLike,
    signature: BytesLike,
    overrides?: PayableOverrides & { from?: string }
  ): Promise<ContractTransaction>;

  verifier(overrides?: CallOverrides): Promise<string>;

  callStatic: {
    NAME(overrides?: CallOverrides): Promise<string>;

    VERSION(overrides?: CallOverrides): Promise<string>;

    bindEmail(data: BytesLike, overrides?: CallOverrides): Promise<void>;

    emails(arg0: string, overrides?: CallOverrides): Promise<string>;

    enable(data: BytesLike, overrides?: CallOverrides): Promise<void>;

    fromHex(s: string, overrides?: CallOverrides): Promise<string>;

    fromHexChar(c: BigNumberish, overrides?: CallOverrides): Promise<number>;

    impl(overrides?: CallOverrides): Promise<string>;

    publicKeys(
      arg0: string,
      arg1: string,
      overrides?: CallOverrides
    ): Promise<string>;

    recover(data: BytesLike, overrides?: CallOverrides): Promise<boolean>;

    recoveryEmail(
      signature: BytesLike,
      dkimHeaders: BytesLike,
      overrides?: CallOverrides
    ): Promise<boolean>;

    recoveryNonce(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

    supportsInterface(
      interfaceId: BytesLike,
      overrides?: CallOverrides
    ): Promise<boolean>;

    validCaller(
      arg0: string,
      arg1: BytesLike,
      overrides?: CallOverrides
    ): Promise<boolean>;

    validateParams(
      chainId: BigNumberish,
      validator: string,
      account: string,
      nonce: BigNumberish,
      from: string,
      overrides?: CallOverrides
    ): Promise<boolean>;

    validateSignature(
      account: string,
      userOpHash: BytesLike,
      signature: BytesLike,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    verifier(overrides?: CallOverrides): Promise<string>;
  };

  filters: {
    "EmailChanged(address,string,string)"(
      account?: string | null,
      oldEmail?: null,
      newEmail?: null
    ): EmailChangedEventFilter;
    EmailChanged(
      account?: string | null,
      oldEmail?: null,
      newEmail?: null
    ): EmailChangedEventFilter;

    "NonceIncrease(address,uint256)"(
      account?: string | null,
      nonce?: null
    ): NonceIncreaseEventFilter;
    NonceIncrease(
      account?: string | null,
      nonce?: null
    ): NonceIncreaseEventFilter;

    "PkAdded(address,string)"(
      account?: string | null,
      keyId?: null
    ): PkAddedEventFilter;
    PkAdded(account?: string | null, keyId?: null): PkAddedEventFilter;

    "VerifySubject(string)"(subject?: null): VerifySubjectEventFilter;
    VerifySubject(subject?: null): VerifySubjectEventFilter;
  };

  estimateGas: {
    NAME(overrides?: CallOverrides): Promise<BigNumber>;

    VERSION(overrides?: CallOverrides): Promise<BigNumber>;

    bindEmail(
      data: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<BigNumber>;

    emails(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

    enable(
      data: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<BigNumber>;

    fromHex(s: string, overrides?: CallOverrides): Promise<BigNumber>;

    fromHexChar(c: BigNumberish, overrides?: CallOverrides): Promise<BigNumber>;

    impl(overrides?: CallOverrides): Promise<BigNumber>;

    publicKeys(
      arg0: string,
      arg1: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    recover(
      data: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<BigNumber>;

    recoveryEmail(
      signature: BytesLike,
      dkimHeaders: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<BigNumber>;

    recoveryNonce(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

    supportsInterface(
      interfaceId: BytesLike,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    validCaller(
      arg0: string,
      arg1: BytesLike,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    validateParams(
      chainId: BigNumberish,
      validator: string,
      account: string,
      nonce: BigNumberish,
      from: string,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    validateSignature(
      account: string,
      userOpHash: BytesLike,
      signature: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<BigNumber>;

    verifier(overrides?: CallOverrides): Promise<BigNumber>;
  };

  populateTransaction: {
    NAME(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    VERSION(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    bindEmail(
      data: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    emails(
      arg0: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    enable(
      data: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    fromHex(
      s: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    fromHexChar(
      c: BigNumberish,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    impl(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    publicKeys(
      arg0: string,
      arg1: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    recover(
      data: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    recoveryEmail(
      signature: BytesLike,
      dkimHeaders: BytesLike,
      overrides?: Overrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    recoveryNonce(
      arg0: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    supportsInterface(
      interfaceId: BytesLike,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    validCaller(
      arg0: string,
      arg1: BytesLike,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    validateParams(
      chainId: BigNumberish,
      validator: string,
      account: string,
      nonce: BigNumberish,
      from: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    validateSignature(
      account: string,
      userOpHash: BytesLike,
      signature: BytesLike,
      overrides?: PayableOverrides & { from?: string }
    ): Promise<PopulatedTransaction>;

    verifier(overrides?: CallOverrides): Promise<PopulatedTransaction>;
  };
}
