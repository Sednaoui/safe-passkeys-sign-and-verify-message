import * as ethers from 'ethers'; // v6

const MAGIC_VALUE = '0x1626ba7e'
const MAGIC_VALUE_BYTES = '0x20c13b0b'

export const isValidSignature = async (
    signerAddress: string,
    message: Uint8Array,
    signature: Uint8Array,
    provider: ethers.JsonRpcProvider
) => {

    if (!ethers.getAddress(signerAddress)) {
        throw new Error('Invalid signer address')
    }

    const msgBytes = message
    const bytecode = await provider.getCode(signerAddress)

    if (
        !bytecode ||
        bytecode === '0x' ||
        bytecode === '0x0' ||
        bytecode === '0x00'
    ) {
        const msgSigner = ethers.recoverAddress(msgBytes, ethers.toUtf8String(signature));
        return msgSigner.toLowerCase() === signerAddress.toLowerCase()
    } else {

        if (await check1271Signature(signerAddress, msgBytes, signature, provider))
            return true

        return await check1271SignatureBytes(
            signerAddress,
            msgBytes,
            signature,
            provider
        );

    }
}

const check1271Signature = async (
    signerAddress: string,
    msgBytes: Uint8Array,
    signature: Uint8Array,
    provider: ethers.JsonRpcProvider
) => {
    const fragment = ethers.FunctionFragment.from({
        constant: true,
        inputs: [
            {
                name: 'message',
                type: 'bytes32'
            },
            {
                name: 'signature',
                type: 'bytes'
            }
        ],
        name: 'isValidSignature',
        outputs: [
            {
                name: 'magicValue',
                type: 'bytes4'
            }
        ],
        payable: false,
        stateMutability: 'view',
        type: 'function'
    })
    const ifc = new ethers.Interface([])

    // Convert message to ETH signed message hash and call valid_signature
    try {
        const msgHash = ethers.hashMessage(msgBytes)
        const isValidSignatureData = ifc.encodeFunctionData(fragment, [msgHash, signature])
        const returnValue = (
            await provider.call({
                to: signerAddress,
                data: isValidSignatureData
            })
        ).slice(0, 10)
        if (returnValue.toLowerCase() === MAGIC_VALUE) return true
    } catch (err) { }

    // If the message is a 32 bytes, try without any conversion
    if (msgBytes.length === 32) {
        try {
            const isValidSignatureData = ifc.encodeFunctionData(fragment, [
                msgBytes,
                signature
            ])
            const returnValue = (
                await provider.call({
                    to: signerAddress,
                    data: isValidSignatureData
                })
            ).slice(0, 10)
            if (returnValue.toLowerCase() === MAGIC_VALUE) return true
            // eslint-disable-next-line no-empty
        } catch (err) { }
    }

    // Try taking a regular hash of the message
    try {
        const msgHash = ethers.keccak256(msgBytes)
        const isValidSignatureData = ifc.encodeFunctionData(fragment, [
            msgHash,
            signature
        ])
        const returnValue = (
            await provider.call({
                to: signerAddress,
                data: isValidSignatureData
            })
        ).slice(0, 10)
        if (returnValue.toLowerCase() === MAGIC_VALUE) return true
        // eslint-disable-next-line no-empty
    } catch (err) { }

    return false
}

const check1271SignatureBytes = async (
    signerAddress: string,
    msgBytes: Uint8Array,
    signature: Uint8Array,
    provider: ethers.JsonRpcProvider
) => {
    const fragment = ethers.FunctionFragment.from({
        constant: true,
        inputs: [
            {
                name: 'message',
                type: 'bytes'
            },
            {
                name: 'signature',
                type: 'bytes'
            }
        ],
        name: 'isValidSignature',
        outputs: [
            {
                name: 'magicValue',
                type: 'bytes4'
            }
        ],
        payable: false,
        stateMutability: 'view',
        type: 'function'
    })
    const ifc = new ethers.Interface([])

    try {
        const isValidSignatureData = ifc.encodeFunctionData(fragment, [
            msgBytes,
            signature
        ])
        const returnValue = (
            await provider.call({
                to: signerAddress,
                data: isValidSignatureData
            })
        ).slice(0, 10)
        if (returnValue.toLowerCase() === MAGIC_VALUE_BYTES) return true
        // eslint-disable-next-line no-empty
    } catch (err) { }

    return false
}


export async function getMessageHashForSafe(safeAccountAddress: string, message: string, chainId: BigInt) {
    const SAFE_MSG_TYPEHASH = "0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca";
    const DOMAIN_SEPARATOR_TYPEHASH = "0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218";
    const domainSeparator = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "uint256", "address"],
        [DOMAIN_SEPARATOR_TYPEHASH, chainId, safeAccountAddress]
    ));
    const encodedMessage = ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32"],
        [SAFE_MSG_TYPEHASH, ethers.keccak256(message)]
    );
    const messageHash = ethers.keccak256(ethers.solidityPacked(
        ["bytes1", "bytes1", "bytes32", "bytes32",],
        [Uint8Array.from([0x19]), Uint8Array.from([0x01]), domainSeparator, ethers.keccak256(encodedMessage)]
    ));
    return messageHash;
}
