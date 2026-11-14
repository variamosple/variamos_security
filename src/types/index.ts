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

export class ResponseModel<Type> {
  constructor(
    public transactionId?: string,
    public errorCode?: number,
    public message?: string,
    public totalCount?: number,
    public data?: Nullable<Type>,
  ) {}

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
