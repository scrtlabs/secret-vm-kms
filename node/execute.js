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

let try_execute = async () => {
  const tx = await secretjs.tx.compute.executeContract(
    {
      sender: wallet.address,
      contract_address: contractAddress,
      msg: {
        increment: {},
      },
      code_hash: contractCodeHash,
    },
    { gasLimit: 100_000 }
  );

  console.log(tx);
};
try_execute();