import CompactEncrypt from 'jose/jwe/compact/encrypt';
import CompactSign from 'jose/jws/compact/sign';
import parseJwk from 'jose/jwk/parse';
import { KeyLike } from 'jose/webcrypto/types';
import { from, Observable, of } from 'rxjs';
import { switchMap, tap } from 'rxjs/operators';

import { JWEContentEncAlgorithm } from '../models';
import { KeyInfo, KeyManagerService } from './keymanager';

export class EncoderService {

  private _encoder = new TextEncoder();

  constructor(
    private _keyMgmt: KeyManagerService,
    private _contentEncAlgo: JWEContentEncAlgorithm = 'A256CBC-HS512' // secure by default
  ) {
  }

  /**
   * Encode takes in an arbitrary string (though ideally a JSON string of a valid request) and protects it.
   * First the data is encrypted in a JWE using the specified content encryption algorithm and recipients public key,
   * then the JWE is signed by wrapping it in a JWS signed with your provided private key
   *
   * @param message JSON encoded object representing the entire message. headers, body, method, endpoint, etc
   * @param recipientPublicKey JWK fetched from the phonebook
   *
   * @returns a signed JWT, whose contents are a JWE. The JWS is signed using your own private key, for verification
   * by the recipient using your published public key. The JWE inside is encrypted using the public key of the recipient
   * so that only they may decrypt and read the contents.
   */
  encodeMessage(message: string, recipientPublicKey: JsonWebKey): Observable<string> {
    return this.encryptMessage(message, recipientPublicKey)
    .pipe(
      switchMap(encyptedMessage => this.signMessage(encyptedMessage))
    );
  }

  /**
   *
   * @param messageContents JSON string of the message you wish to protect
   * @param recipientPublicKey Public JWK of the recipient
   * @returns encrypted JWE. NOTE: this contains no proof of sender. to add that, please use `encodeMessage`
   */
  encryptMessage(messageContents: string, recipientPublicKey: JsonWebKey): Observable<string> {
    const encodedMessageContents = this._encoder.encode(messageContents);
    return from(parseJwk(recipientPublicKey))
    .pipe(
      switchMap(keylike => this._encrypt(
        encodedMessageContents,
        {alg: 'ECDH-ES+A256KW', enc: this._contentEncAlgo},
        keylike
      ))
    );
  }

  /**
   *
   * @param messageContents A string (ideally a JWE from the encyptMessage function) to sign with your private key
   * @returns a compact-format JWS signed by your provided private key
  */
  signMessage(messageContents: string): Observable<string> {
    const encodedMessage = this._encoder.encode(messageContents);
    return this._getOwnPrivateKey()
    .pipe(
      switchMap(privateKeyinfo => this._sign(encodedMessage, {alg: privateKeyinfo.key.alg}, privateKeyinfo.keyLike))
    );
  }

  /**
   * In order to register with the phonebook, you must establish key ownership
   * this is done by sending a JWS containing your public key signed with your private key
   * We also include a nonce, to prevent replay/duplication
   *
   * @returns - a compact JWS containing your public key and a nonce
   */
  generateSignedKeyMessage(): Observable<string> {
    // generate a JWS with the JWK and its thumbprint as the payload
    return this._keyMgmt.getPublicKeyInfo()
    .pipe(
      switchMap(keyInfo => {
        const payload = {
          key: keyInfo.key,
          thumbprint: keyInfo.thumbprint,
          exp: new Date().valueOf() + (2 * 60 * 1000) // 2m expiration
        };
        const JSONpayload = JSON.stringify(payload);
        return this.signMessage(JSONpayload);
      })
    );
  }

  private _encrypt(contents: Uint8Array, options: {alg: string, enc: string}, keylike: KeyLike): Observable<string> {
    return new Observable(obs => {
      new CompactEncrypt(contents)
      .setProtectedHeader(options)
      .encrypt(keylike)
      .then(jweString => {
        obs.next(jweString)
        obs.complete();
      }, err => {
        obs.error(err);
      })
    });
  }

  private _sign(message: Uint8Array, options: {alg: string}, privateKey: KeyLike): Observable<string> {
    return new Observable(obs => {
      new CompactSign(message)
      .setProtectedHeader(options)
      .sign(privateKey)
      .then(jwsString => {
        obs.next(jwsString)
        obs.complete();
      }, err => {
        obs.error(err);
      })
    });
  }

  private _getOwnPrivateKey(): Observable<KeyInfo> {
    return this._keyMgmt.getPrivateKeyInfo();
  }
}
