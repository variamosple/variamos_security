export interface SessionUser {
  id: string;
  name: string;
  user: string;
  email: string;
  roles?: string[];
  permissions?: string[];
}

export interface SessionInfo {
  sub: string;
  name: string;
  userName: string;
  email: string;
  roles?: string[];
  permissions?: string[];
  // The issuer, and the platform audience followed by the host the user
  // goes to (0.0.17); a token issued before holds the host alone
  iss?: string;
  aud?: string | string[];
  iat?: number;
  exp?: number;
}

export type Nullable<T> = T | null | undefined;

/** The fields of an answer, all optional: `new ResponseModel({ errorCode: 401 })`. */
export interface ResponseModelFields<Type> {
  transactionId?: string;
  errorCode?: number;
  message?: string;
  totalCount?: number;
  data?: Nullable<Type>;
}

export class ResponseModel<Type> {
  transactionId?: string;
  errorCode?: number;
  message?: string;
  totalCount?: number;
  data?: Nullable<Type>;

  constructor(fields: ResponseModelFields<Type> = {}) {
    this.transactionId = fields.transactionId;
    this.errorCode = fields.errorCode;
    this.message = fields.message;
    this.totalCount = fields.totalCount;
    this.data = fields.data;
  }

  withResponse(data: Nullable<Type>, totalCount?: number): this {
    this.data = data;
    this.totalCount = totalCount;

    return this;
  }

  withResponsePromise(
    data: Nullable<Type>,
    totalCount?: number,
  ): Promise<this> {
    this.data = data;
    this.totalCount = totalCount;

    return Promise.resolve(this);
  }

  withError(errorCode: number, errorMessage: string): this {
    this.errorCode = errorCode;
    this.message = errorMessage;

    return this;
  }

  withErrorPromise(errorCode: number, errorMessage: string): Promise<this> {
    this.errorCode = errorCode;
    this.message = errorMessage;

    return Promise.resolve(this);
  }
}

// req.user in the consumers' Express handlers (Express 4 and 5)
declare module "express-serve-static-core" {
  interface Request {
    user: Nullable<SessionUser>;
  }
}
