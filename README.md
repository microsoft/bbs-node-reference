# BBS Reference Implementation

TypeScript reference implementation for the [BBS signature scheme](https://github.com/decentralized-identity/bbs-signature). The goal is to help understand and verify the specification. This is NOT a production-ready implementation; testing is minimal and no effort is made to optimize and protect against specialized attacks (e.g., side-channel resistance). 

This project aims to keep up to date with the [latest specification](https://identity.foundation/bbs-signature/draft-looker-cfrg-bbs-signatures.html), but may be behind since the specification changes often; the current implementation matches the *10 July 2023* version of the specification, matching the [draft-irtf-cfrg-bbs-signatures-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/03/) version submitted to the CFRG.

Given the rapid evolution of the BBS scheme, there might be inconsistencies between the specification and the code; please open issues or file PRs if you find any!

## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both.

1. Get the source, for example using `git`
```
git clone -b main https://github.com/microsoft/bbs-node-reference.git
cd bbs-node-reference
```

2. Build the `npm` package
```
npm install
npm run build
```

3. Optionally, run the unit tests

```
npm test
```

4. Optionally, run the sample program

```
npm run bbs
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
