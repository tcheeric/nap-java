import { getPublicKey, nip19 } from 'nostr-tools';
import { buildAuthCompleteRequest, createPrivateKeySigner } from '@imani/nap-client-http';
import { hexToBytes } from '@imani/nap-core';

async function main() {
  const [baseUrl, privateKeyHex, stepUpArg] = process.argv.slice(2);
  const stepUp = stepUpArg === 'step-up';

  if (!baseUrl || !privateKeyHex) {
    throw new Error('Usage: tsClientInterop.ts <baseUrl> <privateKeyHex>');
  }

  const npub = nip19.npubEncode(getPublicKey(hexToBytes(privateKeyHex)));
  const initResponse = await fetch(`${baseUrl}/auth/init`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify({ npub }),
  });

  if (initResponse.status !== 200) {
    throw new Error(`Init failed with status ${initResponse.status}`);
  }

  const challenge = await initResponse.json();
  const completion = await buildAuthCompleteRequest({
    challenge,
    signer: createPrivateKeySigner(privateKeyHex),
    createdAt: 1_710_000_000,
    stepUp,
  });
  const completeResponse = await fetch(`${baseUrl}/auth/complete`, {
    method: 'POST',
    headers: {
      authorization: completion.authorization,
      'content-type': 'application/json',
    },
    body: new TextDecoder().decode(completion.rawBody),
  });
  const bodyText = await completeResponse.text();

  console.log(JSON.stringify({
    status: completeResponse.status,
    body: bodyText.length === 0 ? null : JSON.parse(bodyText),
  }));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
