import generateKeyPair from 'jose/util/generate_key_pair';
import fromKeyLike from 'jose/jwk/from_key_like';
import { forkJoin, from } from 'rxjs';
import { map, switchMap } from 'rxjs/operators';
import {writeFileSync} from 'fs';
import { join } from 'path';

const keypairAlgo = 'ES512';

from(generateKeyPair(keypairAlgo))
.pipe(
  switchMap(({privateKey, publicKey}) => {
    return forkJoin([
      fromKeyLike(privateKey),
      fromKeyLike(publicKey)
    ])
  }),
  map(([privateJWK, publicJWK]) => {
    const privateKey = {...privateJWK, alg: keypairAlgo};
    const publicKey = {...publicJWK, alg: keypairAlgo};
    const keypair = {privateKey, publicKey};
    return keypair;
  })
).subscribe(jwkPair => {
  const filename = `keypair_${new Date().valueOf()}.json`;
  const outputPath = join(process.cwd(), filename);
  try {
    writeFileSync(outputPath, JSON.stringify(jwkPair));
    console.log('Keypair generated and saved in', outputPath);
    process.exit(0);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}, err => {
  console.error(err);
  process.exit(1);
});
