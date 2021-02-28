import parseJwk from 'jose/webcrypto/jwk/parse';
import calculateThumbprint from 'jose/webcrypto/jwk/thumbprint';
import { JWK, KeyLike } from 'jose/webcrypto/types';
import { forkJoin, from, Observable, of } from 'rxjs';
import { map, tap } from 'rxjs/operators';

export interface KeyInfo {
  key: JWK;
  keyLike: KeyLike;
  thumbprint: string;
}

export class KeyManagerService {

  private _publicThumbprint: string;
  private _privateThumbprint: string;

  private _publicKeyLike: KeyLike;
  private _privateKeyLike: KeyLike;

  constructor(
    private _publicKey: JWK,
    private _privateKey: JWK,
  ) {
  }

  getKeyPairInfo(): Observable<{public: KeyInfo, private: KeyInfo}> {
    return forkJoin([
      this.getPublicKeyInfo(),
      this.getPrivateKeyInfo()
    ]).pipe(
      map(([publicKeyInfo, privateKeyInfo]) => {
        return {
          public: publicKeyInfo,
          private: privateKeyInfo
        }
      })
    );
  }

  getPublicKeyInfo(): Observable<KeyInfo> {
    return forkJoin([
      this.getPublicThumbprint(),
      this.getPublicKeyLike()
    ]).pipe(
      map(([publicPrint, publicKeyLike]) => {
        return {
          key: this._publicKey,
          keyLike: publicKeyLike,
          thumbprint: publicPrint
        }
      })
    );
  }

  getPrivateKeyInfo(): Observable<KeyInfo> {
    return forkJoin([
      this.getPrivateThumbprint(),
      this.getPrivateKeyLike()
    ]).pipe(
      map(([privatePrint, privateKeyLike]) => {
        return {
          key: this._privateKey,
          keyLike: privateKeyLike,
          thumbprint: privatePrint
        }
      })
    );
  }

  getPublicThumbprint(): Observable<string> {
    if (this._publicThumbprint) {
      return of(this._publicThumbprint);
    }
    return this.calculateThumbprint(this._publicKey)
    .pipe(
      tap(thumbprint => {
        this._publicThumbprint = thumbprint;
      })
    );
  }

  getPrivateThumbprint(): Observable<string> {
    if (this._privateThumbprint) {
      return of(this._privateThumbprint);
    }
    return this.calculateThumbprint(this._privateKey)
    .pipe(
      tap(thumbprint => {
        this._privateThumbprint = thumbprint;
      })
    );
  }

  getPublicKeyLike(): Observable<KeyLike> {
    if (this._publicKeyLike) {
      return of(this._publicKeyLike);
    }
    return this.parseJWK(this._publicKey)
    .pipe(
      tap(keyLike => {
        this._publicKeyLike = keyLike;
      })
    );
  }

  getPrivateKeyLike(): Observable<KeyLike> {
    if (this._privateKeyLike) {
      return of(this._privateKeyLike);
    }
    return this.parseJWK(this._privateKey)
    .pipe(
      tap(keyLike => {
        this._privateKeyLike = keyLike;
      })
    );
  }

  calculateThumbprint(key: JWK): Observable<string> {
    return from(calculateThumbprint(key));
  }

  parseJWK(key: JWK): Observable<KeyLike> {
    return from(parseJwk(key));
  }
}
