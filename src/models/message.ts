import { JWEHeaderParameters, JWSHeaderParameters } from 'jose/webcrypto/types';

export interface VerifiedMessage {
  payload: string; // JWE stored inside JWS
  protectedHeader?: JWSHeaderParameters;
}

export interface DecryptedMessage {
  payload: string; // request in json format
  protectedHeader?: JWEHeaderParameters;
}

export interface RequestMessage {
  method: string;
  path: string;
  headers?: {[key: string]: string | string[]};
  queryParams?: {[key: string]: string | string[]};
  body?: string;
  trailers?: {[key: string]: string | string[]};
}
