import { Observable, of, throwError } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

import { PhonebookEntry, PhonebookService } from '../models/phonebook';
import { DecoderService } from './decoder';

export class InMemoryPhonebookService implements PhonebookService {

  private _phonebook: {[id: string]: PhonebookEntry} = {};

  constructor(
    private _decoder: DecoderService
  ) {
  }

  register(id: string, signedKeyMessage: string): Observable<boolean> {
    // validate signedKeyMessage
    if (!signedKeyMessage || !id) {
      return throwError({Status: 400, Message: 'id and signedKeyMessage are required'});
    }
    return this._decoder.verifySignedKeyMessage(signedKeyMessage)
    .pipe(
      map(result => {
        this._phonebook[id] = {
          key: result.key,
          thumbprint: result.thumbprint,
          id: id
        };
        return true;
      }),
      catchError(err => {
        console.error(err);
        return of(false);
      })
    );
  }

  get(id: string): Observable<PhonebookEntry> {
    if (id in this._phonebook) {
      return of(this._phonebook[id]);
    } else {
      return of(null);
    }
  }

}
