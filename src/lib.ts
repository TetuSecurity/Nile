import { JWK } from 'jose/webcrypto/types';
import { Observable, of } from 'rxjs';
import { map, switchMap, tap } from 'rxjs/operators';
import { PhonebookService } from './models';
import { DecoderService } from './services/decoder';
import { EncoderService } from './services/encoder';
import { InMemoryPhonebookService } from './services/in-mem-phonebook';
import { KeyManagerService } from './services/keymanager';

export class Nile {

  private _id: string;
  private _privateKey: JWK;
  private _publicKey: JWK;
  private _phonebook: PhonebookService;

  private _encoder: EncoderService;
  private _decoder: DecoderService;
  private _keyMgmt: KeyManagerService;

  private _ready: boolean = false;


  constructor(options) {
    this._id = options.id || 'newRandomId';
    this._privateKey = options.privateKey;
    this._publicKey = options.publicKey;

    this._keyMgmt = new KeyManagerService(
      this._publicKey,
      this._privateKey
    );

    this._encoder = new EncoderService(
      this._keyMgmt,
      options.JWECEA || undefined
    );

    this._decoder = new DecoderService(
      this._keyMgmt
    );

    this._phonebook = options.phonebook || new InMemoryPhonebookService(this._decoder);
  }


  prepareMessage(message: any, recipientId: string): Observable<string> {
    const payloadString = JSON.stringify(message);
    return this._awaitReady()
    .pipe(
      switchMap(_ => this._phonebook.get(recipientId)),
      switchMap(recipientKeyEntry => this._encoder.encodeMessage(payloadString, recipientKeyEntry.key))
    );
  }

  handleMessage(encodedMessage: string, senderId: string): Observable<any> {
    return this._awaitReady()
    .pipe(
      switchMap(_ => this._phonebook.get(senderId)),
      switchMap(senderKeyEntry => this._decoder.decodeMessage(encodedMessage, senderKeyEntry.key)),
      map(decodedMessage => JSON.parse(decodedMessage))
    );
  }

  private _awaitReady(): Observable<boolean> {
    if (this._ready) {
      return of(true);
    } else {
      return this._encoder.generateSignedKeyMessage()
      .pipe(
        switchMap(signedKeyMessage => this._phonebook.register(this._id, signedKeyMessage)),
        tap(ready => this._ready = ready)
      );
    }
  }
}
