import { SecretNetworkClient, Wallet, coinsFromString } from "secretjs";


const wallet = new Wallet(process.env.MNEMONIC);

const secretjs = new SecretNetworkClient({
  chainId: "pulsar-3",
  url: "https://lcd.testnet.secretsaturn.net",
  wallet: wallet,
  walletAddress: wallet.address,
});

let contractCodeHash =
  "33ca320501c4cb7fb744fafc8ce8700d8fdbac260b46af68412da59df39b6866";
let contractAddress = "secret1zldfjv88d9sl4rlyfl0kuujyheawwfe6a65d7n";

let query_contract = async () => {
    let my_query = await secretjs.query.compute.queryContract({
      contract_address: contractAddress,
      code_hash: contractCodeHash,
      query: { get_count: {} },
    });
    console.log("count: ", my_query);
  };
  query_contract();