// Preserve this import for future use
// @ts-ignore

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
  aud?: string;
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
    public data?: Nullable<Type>
  ) {}

  withResponse(data: Nullable<Type>, totalCount?: number): this {
    this.data = data;
    this.totalCount = totalCount;

    return this;
  }

  withResponsePromise(
    data: Nullable<Type>,
    totalCount?: number
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

declare global {
  namespace Express {
    interface Request {
      user: Nullable<SessionUser>;
    }
  }
}
