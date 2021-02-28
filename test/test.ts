import { JWK } from 'jose/webcrypto/types';
import { switchMap } from 'rxjs/operators';
import { Nile } from '../src';


const keypair: {privateKey: JWK, publicKey: JWK} = require('./keys/keypair_test.json');

const TestId = 'TestKeyRegistration';
const nile = new Nile({
  id: TestId,
  privateKey: keypair.privateKey,
  publicKey: keypair.publicKey
});

// Send a message to ourselves
nile.prepareMessage({method: 'GET', path: '/hello'}, TestId)
.pipe(
  switchMap(encodedMessage => {
    console.log('Encoded Message', encodedMessage);
    // decode the message from yourself
    return nile.handleMessage(encodedMessage, TestId);
  })
)
.subscribe(decodedMessage => {
  console.log('Got message from self', decodedMessage);
  process.exit(0);
}, err => {
  console.error(err);
  process.exit(1);
})
