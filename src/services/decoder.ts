import compactDecrypt from 'jose/jwe/compact/decrypt';
import compactVerify from 'jose/jws/compact/verify';
import parseJwk from 'jose/jwk/parse';
import { JWK, KeyLike } from 'jose/webcrypto/types';
import { from, Observable, of, throwError } from 'rxjs';
import { map, switchMap } from 'rxjs/operators';
import { DecryptedMessage, VerifiedMessage } from '../models/message';
import { KeyInfo, KeyManagerService } from './keymanager';


export class DecoderService {

  private _decoder = new TextDecoder();

  constructor(
    private _keyMgmt: KeyManagerService
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
  decodeMessage(message: string, senderPublicKey: JsonWebKey): Observable<string> {
    return this.verifyMessage(message, senderPublicKey)
    .pipe(
      switchMap(encyptedMessage => this.decryptMessage(encyptedMessage.payload))
    );
  }

  /**
   *
   * @param jweString compact-format JWE of the request
   * @returns json string of the message contents
   */
  decryptMessage(jweString: string): Observable<string> {
    return this._getOwnPrivateKey()
    .pipe(
      switchMap(keyInfo => this._decrypt(
        jweString,
        keyInfo.keyLike
      )),
      map(decryptedMessage => decryptedMessage.payload)
    );
  }

  /**
   *
   * @param messagesJWS A compact-format JWS (also called a JWT)
   * @param senderPublicKey the Public Key of the supposed sender
   * @returns an object with the message and headers needed to decrypt it
  */
  verifyMessage(messageJWS: string, senderPublicKey: JsonWebKey): Observable<VerifiedMessage> {
    return from(parseJwk(senderPublicKey))
    .pipe(
      switchMap(publicKeyLike => this._verify(messageJWS, publicKeyLike))
    );
  }

  verifySignedKeyMessage(signedKeyMessage: string): Observable<{key: JWK, thumbprint: string}> {
    const signedKeyParts = signedKeyMessage.split(/\./g);
    if (!signedKeyParts || signedKeyParts.length !== 3) {
      return throwError({Status: 400, Message: 'Invalid signedKeyMessage format'});
    }
    const signedKeyBodyEncoded = signedKeyParts[1]; // payload of JWT in base64
    let untrustedBody: {key: JWK, exp: number, thumbprint: string};
    try {
      const bodyString = Buffer.from(signedKeyBodyEncoded, 'base64').toString('utf-8');
      untrustedBody = JSON.parse(bodyString);
    } catch (e)  {
      console.error(e);
      return throwError({Status: 400, Message: 'Invalid signedKeyMessage'});
    }
    if (!untrustedBody || !untrustedBody.key || !untrustedBody.exp) {
      return throwError({Status: 400, Message: 'Invalid signedKeyMessage'});
    }
    return this.verifyMessage(signedKeyMessage, untrustedBody.key)
    .pipe(
      switchMap(({payload, protectedHeader}) => {
        let keymessage;
        try {
          keymessage = JSON.parse(payload);
        } catch (e) {
          return throwError({Status: 400, Message: 'Invalid signedKeyMessage'});
        }
        if (keymessage.exp !== untrustedBody.exp || keymessage.exp < new Date().valueOf()) {
          return throwError({Status: 400, Message: 'Expired SignedKeyMessage'});
        }
        if (untrustedBody.thumbprint !== keymessage.thumbprint) {
          return throwError({Status: 400, Message: 'Thumbprint mismatch'});
        }
        return this._keyMgmt.calculateThumbprint(keymessage.key)
        .pipe(
          switchMap(calcPrint => {
            if (calcPrint !== keymessage.thumbprint) {
              return throwError({Status: 400, Message: 'Thumbprint mismatch'});
            }
            return of(keymessage);
          })
        );
      })
    );
  }

  private _decrypt(contents: string, privateKey: KeyLike): Observable<DecryptedMessage> {
    return new Observable(obs => {
      compactDecrypt(contents, privateKey)
      .then(({plaintext, protectedHeader}) => {
        const payloadString = this._decoder.decode(plaintext);
        obs.next({payload: payloadString, protectedHeader})
        obs.complete();
      }, err => {
        obs.error(err);
      })
    });
  }

  private _verify(jwsString: string, senderPublicKey: KeyLike): Observable<VerifiedMessage> {
    return new Observable(obs => {
      compactVerify(jwsString, senderPublicKey)
      .then(({payload, protectedHeader}) => {
        const payloadString = this._decoder.decode(payload);
        obs.next({payload: payloadString, protectedHeader})
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
