
export const Erc20VerifierAbi = [
    {
      inputs: [],
      name: "InvalidInitialization",
      type: "error",
    },
    {
      inputs: [
        {
          internalType: "string",
          name: "message",
          type: "string",
        },
        {
          internalType: "uint64",
          name: "requestId",
          type: "uint64",
        },
        {
          internalType: "uint256",
          name: "linkID",
          type: "uint256",
        },
        {
          internalType: "uint64",
          name: "requestIdToCompare",
          type: "uint64",
        },
        {
          internalType: "uint256",
          name: "linkIdToCompare",
          type: "uint256",
        },
      ],
      name: "LinkedProofError",
      type: "error",
    },
    {
      inputs: [],
      name: "NotInitializing",
      type: "error",
    },
    {
      inputs: [
        {
          internalType: "address",
          name: "owner",
          type: "address",
        },
      ],
      name: "OwnableInvalidOwner",
      type: "error",
    },
    {
      inputs: [
        {
          internalType: "address",
          name: "account",
          type: "address",
        },
      ],
      name: "OwnableUnauthorizedAccount",
      type: "error",
    },
    {
      inputs: [
        {
          internalType: "contract ICircuitValidator",
          name: "validator",
          type: "address",
        },
      ],
      name: "addValidatorToWhitelist",
      outputs: [],
      stateMutability: "nonpayable",
      type: "function",
    },
    {
      inputs: [
        {
          internalType: "address",
          name: "sender",
          type: "address",
        },
        {
          internalType: "uint64",
          name: "requestId",
          type: "uint64",
        },
      ],
      name: "getProofStatus",
      outputs: [
        {
          components: [
            {
              internalType: "bool",
              name: "isVerified",
              type: "bool",
            },
            {
              internalType: "string",
              name: "validatorVersion",
              type: "string",
            },
            {
              internalType: "uint256",
              name: "blockNumber",
              type: "uint256",
            },
            {
              internalType: "uint256",
              name: "blockTimestamp",
              type: "uint256",
            },
          ],
          internalType: "struct IZKPVerifier.ProofStatus",
          name: "",
          type: "tuple",
        },
      ],
      stateMutability: "view",
      type: "function",
    },
    {
      inputs: [
        {
          internalType: "uint64",
          name: "requestId",
          type: "uint64",
        },
      ],
      name: "getRequestOwner",
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
          internalType: "uint64",
          name: "requestId",
          type: "uint64",
        },
      ],
      name: "getZKPRequest",
      outputs: [
        {
          components: [
            {
              internalType: "string",
              name: "metadata",
              type: "string",
            },
            {
              internalType: "contract ICircuitValidator",
              name: "validator",
              type: "address",
            },
            {
              internalType: "bytes",
              name: "data",
              type: "bytes",
            },
          ],
          internalType: "struct IZKPVerifier.ZKPRequest",
          name: "zkpRequest",
          type: "tuple",
        },
      ],
      stateMutability: "view",
      type: "function",
    },
    {
      inputs: [
        {
          internalType: "uint256",
          name: "startIndex",
          type: "uint256",
        },
        {
          internalType: "uint256",
          name: "length",
          type: "uint256",
        },
      ],
      name: "getZKPRequests",
      outputs: [
        {
          components: [
            {
              internalType: "string",
              name: "metadata",
              type: "string",
            },
            {
              internalType: "contract ICircuitValidator",
              name: "validator",
              type: "address",
            },
            {
              internalType: "bytes",
              name: "data",
              type: "bytes",
            },
          ],
          internalType: "struct IZKPVerifier.ZKPRequest[]",
          name: "",
          type: "tuple[]",
        },
      ],
      stateMutability: "view",
      type: "function",
    },
    {
      inputs: [],
      name: "getZKPRequestsCount",
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
          name: "sender",
          type: "address",
        },
        {
          internalType: "uint64",
          name: "requestId",
          type: "uint64",
        },
      ],
      name: "isProofVerified",
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
          internalType: "uint64",
          name: "requestId",
          type: "uint64",
        },
        {
          components: [
            {
              internalType: "string",
              name: "metadata",
              type: "string",
            },
            {
              internalType: "contract ICircuitValidator",
              name: "validator",
              type: "address",
            },
            {
              internalType: "bytes",
              name: "data",
              type: "bytes",
            },
          ],
          internalType: "struct IZKPVerifier.ZKPRequest",
          name: "request",
          type: "tuple",
        },
      ],
      name: "setZKPRequest",
      outputs: [],
      stateMutability: "nonpayable",
      type: "function",
    },
    {
      inputs: [
        {
          internalType: "uint64",
          name: "requestId",
          type: "uint64",
        },
        {
          internalType: "uint256[]",
          name: "inputs",
          type: "uint256[]",
        },
        {
          internalType: "uint256[2]",
          name: "a",
          type: "uint256[2]",
        },
        {
          internalType: "uint256[2][2]",
          name: "b",
          type: "uint256[2][2]",
        },
        {
          internalType: "uint256[2]",
          name: "c",
          type: "uint256[2]",
        },
      ],
      name: "submitZKPResponse",
      outputs: [],
      stateMutability: "nonpayable",
      type: "function",
    },
  ];
  