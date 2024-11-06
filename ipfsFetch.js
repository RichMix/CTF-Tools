const { ethers } = require("ethers");

async function getTokenURI() {
    // Connect to the Ethereum mainnet (replace with your Infura or Alchemy project ID)
    const provider = new ethers.providers.InfuraProvider("mainnet", "YOUR_INFURA_PROJECT_ID");
    const contractAddress = "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D";
    const tokenId = 3001;

    // ERC-721 ABI with just the tokenURI function
    const abi = [
        "function tokenURI(uint256 tokenId) public view returns (string memory)"
    ];

    // Connect to the NFT contract
    const nftContract = new ethers.Contract(contractAddress, abi, provider);
    const tokenURI = await nftContract.tokenURI(tokenId);
    console.log("Token URI:", tokenURI);
}

getTokenURI().catch(console.error);
