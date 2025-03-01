import * as dotenv from 'dotenv'
import {
  getBytes,
  hashMessage,
  id,
  JsonRpcProvider,
  toBeArray,
  toUtf8Bytes,
  ZeroAddress
} from "ethers"; // v6

import {
  SafeAccountV0_3_0 as SafeAccount,
  MetaTransaction,
  CandidePaymaster,
  WebauthnPublicKey,
  WebauthnSignatureData,
  SignerSignaturePair,
  WebauthnDummySignerSignaturePair,
} from "abstractionkit";
import { UserVerificationRequirement, WebAuthnCredentials, extractClientDataFields, extractPublicKey, extractSignature } from './webauthn';
import { getMessageHashForSafe, isValidSignature } from "./safe-utils";

async function main(): Promise<void> {
  //get values from .env
  dotenv.config()
  const chainId = BigInt(process.env.CHAIN_ID as string)
  const bundlerUrl = process.env.BUNDLER_URL as string
  const jsonRpcNodeProvider = process.env.JSON_RPC_NODE_PROVIDER as string
  const paymasterRPC = process.env.PAYMASTER_RPC as string;

  const navigator = {
    credentials: new WebAuthnCredentials(),
  }

  const credential = navigator.credentials.create({
    publicKey: {
      rp: {
        name: 'Safe',
        id: 'safe.global',
      },
      user: {
        id: getBytes(id('chucknorris')),
        name: 'chucknorris',
        displayName: 'Chuck Norris',
      },
      challenge: toBeArray(Date.now()),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    },
  })


  const publicKey = extractPublicKey(credential.response)

  const webauthPublicKey: WebauthnPublicKey = {
    x: publicKey.x,
    y: publicKey.y,
  }

  //initializeNewAccount only needed when the smart account
  //have not been deployed yet for its first useroperation.
  //You can store the accountAddress to use it to initialize 
  //the SafeAccount object for the following useroperations
  let smartAccount = SafeAccount.initializeNewAccount(
    [webauthPublicKey]
  )

  //After the account contract is deployed, no need to call initializeNewAccount
  //let smartAccount = new SafeAccount(accountAddress)

  console.log("Account address(sender) : " + smartAccount.accountAddress)
  const metaTx: MetaTransaction = {
    to: ZeroAddress,
    value: 0n,
    data: "0x",
  }

  //createUserOperation will determine the nonce, fetch the gas prices,
  //estimate gas limits and return a useroperation to be signed.
  //you can override all these values using the overrides parameter.
  let userOperation = await smartAccount.createUserOperation(
    [metaTx],
    jsonRpcNodeProvider, //the node rpc is used to fetch the current nonce and fetch gas prices.
    bundlerUrl, //the bundler rpc is used to estimate the gas limits.
    {
      dummySignerSignaturePairs: [WebauthnDummySignerSignaturePair],
    }
  )

  let paymaster: CandidePaymaster = new CandidePaymaster(
    paymasterRPC,
  )
  console.log(userOperation)
  let [paymasterUserOperation, _sponsorMetadata] = await paymaster.createSponsorPaymasterUserOperation(
    userOperation,
    bundlerUrl,
  )
  userOperation = paymasterUserOperation;

  const safeInitOpHash = SafeAccount.getUserOperationEip712Hash(
    userOperation,
    chainId,
  )

  const assertion = navigator.credentials.get({
    publicKey: {
      challenge: getBytes(safeInitOpHash),
      rpId: 'safe.global',
      allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
      userVerification: UserVerificationRequirement.required,
    },
  })

  const webauthSignatureData: WebauthnSignatureData = {
    authenticatorData: assertion.response.authenticatorData,
    clientDataFields: extractClientDataFields(assertion.response),
    rs: extractSignature(assertion.response),
  }

  const webauthSignature: string = SafeAccount.createWebAuthnSignature(
    webauthSignatureData
  )

  const SignerSignaturePair: SignerSignaturePair = {
    signer: webauthPublicKey,
    signature: webauthSignature,
  }

  userOperation.signature = SafeAccount.formatSignaturesToUseroperationSignature(
    [SignerSignaturePair],
    { isInit: userOperation.nonce == 0n }
  )

  const sendUserOperationResponse = await smartAccount.sendUserOperation(
    userOperation,
    bundlerUrl
  )

  console.log("Useroperation sent. Waiting to be included ......")
  //included will return a UserOperationReceiptResult when 
  //useroperation is included onchain
  let userOperationReceiptResult = await sendUserOperationResponse.included()

  console.log("Useroperation receipt received.")
  console.log(userOperationReceiptResult)
  if (userOperationReceiptResult.success) {
    console.log("The account is now deployed. The transaction hash is : " + userOperationReceiptResult.receipt.transactionHash)
  } else {
    console.log("Useroperation execution failed")
  }

  // Get Message Hash For Safe
  const message = "Hello World";
  const messageHash = hashMessage(message);
  const safeMessageHash = getMessageHashForSafe(smartAccount.accountAddress, messageHash, chainId);

  // Sign the safe message hash with passkeys
  console.log("Signing the message: ", message);
  const assertion2 = navigator.credentials.get({
    publicKey: {
      challenge: getBytes(safeMessageHash),
      rpId: 'safe.global',
      allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
      userVerification: UserVerificationRequirement.required,
    },
  })

  // format the signature
  const webauthSignatureData2: WebauthnSignatureData = {
    authenticatorData: assertion2.response.authenticatorData,
    clientDataFields: extractClientDataFields(assertion2.response),
    rs: extractSignature(assertion2.response),
  }

  const webauthSignature2: string = SafeAccount.createWebAuthnSignature(
    webauthSignatureData2
  );

  const signerSignaturePair: SignerSignaturePair = {
    signer: webauthPublicKey,
    signature: webauthSignature2,
  }

  const signature = SafeAccount.buildSignaturesFromSingerSignaturePairs(
    [signerSignaturePair],
    { isInit: false }, // hardcoded because we know the safe account is already deployed. Else just check the nonce of the account
  )

  console.log("Message signed and formated: ", signature)

  // verify that the signature is valid
  const validSignature = await isValidSignature(
    smartAccount.accountAddress,
    toUtf8Bytes(message),
    getBytes(signature),
    new JsonRpcProvider(jsonRpcNodeProvider)
  );

  console.log("Is the signature valid? ", validSignature);
}

main()
