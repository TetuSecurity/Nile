import { JWK } from 'jose/webcrypto/types';
import { Observable } from 'rxjs';

export interface PhonebookService {
  register(id: string, signedKeyMessage: string): Observable<boolean>;
  get(id: string): Observable<PhonebookEntry>
}


export interface PhonebookEntry {
  id: string;
  key: JWK;
  thumbprint: string;
}
